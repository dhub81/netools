#!/usr/bin/env python3

"""
SSH Tunnel Proxy Server - Sans-I/O Refactored v7

================================================

python3 d:\py\slv308.py ^
--ssh-host x.x.x.x ^
--ssh-port 22 ^
--pool-size 1 ^
--no-log-connections ^
--ssh-user user ^
--ssh-key "~\.ssh\id_rsa" ^
--local-port 3128 ^
--test-url http://www.google.com ^
--local-host 0.0.0.0

v7 目标：

- 严格收敛到更纯的 Sans-I/O 边界
- CONNECT_VIA_SSH 改为 OPEN_OUTBOUND_STREAM
- 移除 await_next，由 driver 根据 state 决定等待什么
- 将 pipe 背压/flush/pause/resume 从 core machine 移到 runtime adapter
- 将 idle timer effect 抽象成 SET_DEADLINE / CLEAR_DEADLINE
- 将 TERMINATE_SESSION 拆为 SESSION_DONE / SESSION_FAILED
- proxy_mode / endpoint / test stage 统一 Enum
- 保持单文件结构，尽量小步重构
"""

import sys
import asyncio
import os
import collections
import ipaddress
import argparse
import logging
import signal
import struct
import time
import traceback
import uuid

from dataclasses import dataclass, field, replace
from typing import Optional, Tuple, List, Any, Dict
from urllib.parse import urlparse
from enum import Enum, auto

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    os.system("")

try:
    import asyncssh
except ImportError:
    print(
        "\033[91mError: asyncssh required. Install: pip install asyncssh\033[0m",
        file=sys.stderr,
    )
    sys.exit(1)


# ============================================================================
# Logging
# ============================================================================


class ColorFormatter(logging.Formatter):
    GREY = "\033[90m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"

    def format(self, record):
        orig_msg, orig_levelname = record.msg, record.levelname

        if record.levelno == logging.DEBUG:
            lc, mc = self.GREY, self.GREY
        elif record.levelno == logging.INFO:
            lc, mc = self.CYAN, self.RESET
        elif record.levelno == logging.WARNING:
            lc, mc = self.YELLOW, self.YELLOW
        elif record.levelno >= logging.ERROR:
            lc, mc = self.RED, self.RED
        else:
            lc, mc = self.RESET, self.RESET

        record.levelname = f"{lc}{record.levelname}{self.RESET}"
        if isinstance(record.msg, str):
            msg = record.msg
            if record.levelno < logging.WARNING:
                msg = msg.replace("✓", f"{self.GREEN}✓{self.RESET}")
                msg = msg.replace("✗", f"{self.RED}✗{self.RESET}")
            record.msg = f"{mc}{msg}{self.RESET}"

        res = super().format(record)
        record.msg, record.levelname = orig_msg, orig_levelname
        return res


# ============================================================================
# Config
# ============================================================================


class ProxyMode(Enum):
    SOCKS5 = auto()
    HTTP = auto()
    BOTH = auto()


@dataclass(frozen=True)
class Config:
    ssh_host: str = ""
    ssh_port: int = 22
    ssh_username: str = ""
    ssh_password: str = ""
    ssh_key_path: str = ""
    ssh_key_passphrase: str = ""
    known_hosts: Optional[str] = None

    local_host: str = "127.0.0.1"
    local_port: int = 1080
    proxy_mode: ProxyMode = ProxyMode.BOTH

    local_only: bool = False

    pool_size: int = 3
    max_retries: int = 3
    retry_delay: float = 2.0
    keepalive_interval: float = 30.0
    connection_timeout: float = 10.0

    buffer_size: int = 65536
    drain_threshold: int = 262144

    log_connections: bool = True
    log_level: str = "INFO"

    test_url: str = "http://httpbin.org/ip"
    auto_test: bool = True
    shutdown_timeout: float = 10.0

    handshake_timeout: float = 10.0
    max_handshake_buffer: int = 8192
    pool_acquire_timeout: float = 5.0

    pipe_idle_timeout: float = 300.0
    pipe_buffer_high_water: int = 1048576
    pipe_buffer_low_water: int = 262144


def validate_config(cfg: Config) -> List[str]:
    errors = []
    if not cfg.ssh_host:
        errors.append("SSH host required")
    if not cfg.ssh_username:
        errors.append("SSH username required")
    if not cfg.ssh_password and not cfg.ssh_key_path:
        errors.append("SSH password/key required")
    if cfg.ssh_key_path and not os.path.exists(cfg.ssh_key_path):
        errors.append(f"Key not found: {cfg.ssh_key_path}")
    if not (1 <= cfg.pool_size <= 20):
        errors.append("Pool size must be in range 1..20")
    if cfg.max_handshake_buffer < 1024:
        errors.append("max_handshake_buffer too small")
    return errors


# ============================================================================
# Enums / Transition Model
# ============================================================================


class Phase(Enum):
    INIT = auto()
    SOCKS5_AUTH = auto()
    SOCKS5_REQ = auto()
    HTTP_REQ = auto()
    CONNECTING = auto()
    PIPING = auto()
    CLOSED = auto()


class SessionMode(Enum):
    UNKNOWN = auto()
    SOCKS5 = auto()
    HTTP_CONNECT = auto()
    HTTP_PROXY = auto()


class PipeStage(Enum):
    FLOWING = auto()
    HALF_CLOSED_CLIENT = auto()
    HALF_CLOSED_REMOTE = auto()
    CLOSED = auto()


class Endpoint(Enum):
    CLIENT = auto()
    REMOTE = auto()


@dataclass(frozen=True)
class Transition:
    state: "ProxyProtocolState"
    effects: Tuple["Effect", ...] = ()


# ============================================================================
# Sans-I/O Events
# ============================================================================


class Event:
    pass


@dataclass(frozen=True)
class SessionStarted(Event):
    pass


@dataclass(frozen=True)
class ClientDataReceived(Event):
    data: bytes


@dataclass(frozen=True)
class ClientConnectionClosed(Event):
    pass


@dataclass(frozen=True)
class HandshakeTimeout(Event):
    elapsed: float


@dataclass(frozen=True)
class SendFailed(Event):
    where: str = ""


@dataclass(frozen=True)
class OutboundStreamOpened(Event):
    pass


class ConnectFailReason(Enum):
    REFUSED = auto()
    UNREACHABLE = auto()
    TIMEOUT = auto()
    DNS_ERROR = auto()
    POOL_UNAVAILABLE = auto()
    OTHER = auto()


@dataclass(frozen=True)
class OutboundStreamOpenFailed(Event):
    reason: ConnectFailReason
    detail: str = ""


@dataclass(frozen=True)
class PipeDataFromClient(Event):
    data: bytes
    length: int


@dataclass(frozen=True)
class PipeDataFromRemote(Event):
    data: bytes
    length: int


@dataclass(frozen=True)
class PipeEOF(Event):
    source: Endpoint


@dataclass(frozen=True)
class PipeError(Event):
    source: Endpoint
    error_msg: str = ""


@dataclass(frozen=True)
class PipeIdleTimeout(Event):
    elapsed: float = 0.0


# ============================================================================
# Sans-I/O Effects
# ============================================================================


class EffectType(Enum):
    WRITE_CLIENT = auto()
    WRITE_REMOTE = auto()
    OPEN_OUTBOUND_STREAM = auto()

    START_PIPE_RUNTIME = auto()
    PIPE_WRITE_EOF = auto()
    PIPE_CLOSE_BOTH = auto()

    SET_DEADLINE = auto()
    CLEAR_DEADLINE = auto()

    SESSION_DONE = auto()
    SESSION_FAILED = auto()

    TEST_LOG = auto()


@dataclass(frozen=True)
class Effect:
    type: EffectType
    data: Any = None


def write_client(data: bytes) -> Effect:
    return Effect(EffectType.WRITE_CLIENT, data)


def write_remote(data: bytes) -> Effect:
    return Effect(EffectType.WRITE_REMOTE, data)


def open_outbound_stream(host: str, port: int) -> Effect:
    return Effect(EffectType.OPEN_OUTBOUND_STREAM, (host, port))


def start_pipe_runtime() -> Effect:
    return Effect(EffectType.START_PIPE_RUNTIME)


def pipe_write_eof(destination: Endpoint) -> Effect:
    return Effect(EffectType.PIPE_WRITE_EOF, destination)


def pipe_close_both() -> Effect:
    return Effect(EffectType.PIPE_CLOSE_BOTH)


def set_deadline(kind: str, timeout: float) -> Effect:
    return Effect(EffectType.SET_DEADLINE, {"kind": kind, "timeout": timeout})


def clear_deadline(kind: str) -> Effect:
    return Effect(EffectType.CLEAR_DEADLINE, {"kind": kind})


def session_done(reason: str = "") -> Effect:
    return Effect(EffectType.SESSION_DONE, reason)


def session_failed(reason: str = "") -> Effect:
    return Effect(EffectType.SESSION_FAILED, reason)


def test_log(success: bool, msg: str) -> Effect:
    return Effect(EffectType.TEST_LOG, (success, msg))


# ============================================================================
# Protocol helpers
# ============================================================================

HTTP_METHODS = (
    b"GET",
    b"POST",
    b"PUT",
    b"DELETE",
    b"HEAD",
    b"OPTIONS",
    b"PATCH",
    b"CONNECT",
    b"TRACE",
)


def looks_like_http_request(buf: bytes) -> bool:
    if not buf:
        return False
    line_end = buf.find(b"\r\n")
    first_line = buf if line_end == -1 else buf[:line_end]
    for m in HTTP_METHODS:
        if first_line.startswith(m + b" "):
            return True
    return False


def socks5_reply(rep: int) -> bytes:
    return struct.pack("!BBBB4sH", 0x05, rep, 0x00, 0x01, b"\x00\x00\x00\x00", 0)


def parse_http_connect_target(raw: bytes) -> Tuple[str, int]:
    if raw.startswith(b"["):
        end = raw.find(b"]")
        if end <= 0:
            raise ValueError("invalid ipv6 connect target")
        host = raw[1:end].decode("ascii")
        if len(raw) <= end + 2 or raw[end + 1 : end + 2] != b":":
            port = 443
        else:
            port = int(raw[end + 2 :].decode("ascii"))
        return host, port

    target = raw.decode("ascii")
    if ":" in target:
        host, port_str = target.rsplit(":", 1)
        return host, int(port_str)
    return target, 443


def normalize_host_port_from_host_header(
    host_value: str, default_port: int
) -> Tuple[str, int]:
    host_value = host_value.strip()
    if host_value.startswith("["):
        end = host_value.find("]")
        if end <= 0:
            raise ValueError("invalid host header ipv6")
        host = host_value[1:end]
        if len(host_value) > end + 1 and host_value[end + 1] == ":":
            return host, int(host_value[end + 2 :])
        return host, default_port
    if host_value.count(":") == 1:
        host, port_str = host_value.rsplit(":", 1)
        if port_str.isdigit():
            return host, int(port_str)
    return host_value, default_port


def format_host_header(host: str, port: int, scheme: str) -> str:
    try:
        ip = ipaddress.ip_address(host)
        is_v6 = ip.version == 6
    except ValueError:
        is_v6 = False
    default_port = 443 if scheme == "https" else 80
    host_text = f"[{host}]" if is_v6 else host
    if port == default_port:
        return host_text
    return f"{host_text}:{port}"


def map_connect_fail_to_socks_rep(reason: ConnectFailReason) -> int:
    if reason == ConnectFailReason.REFUSED:
        return 0x05
    if reason in (
        ConnectFailReason.UNREACHABLE,
        ConnectFailReason.DNS_ERROR,
    ):
        return 0x04
    if reason == ConnectFailReason.TIMEOUT:
        return 0x04
    if reason == ConnectFailReason.POOL_UNAVAILABLE:
        return 0x01
    return 0x01


# ============================================================================
# Unified Proxy State
# ============================================================================


@dataclass(frozen=True)
class ProxyProtocolState:
    phase: Phase = Phase.INIT
    proxy_mode: ProxyMode = ProxyMode.BOTH

    buffer: bytes = b""
    session_mode: SessionMode = SessionMode.UNKNOWN

    target_host: str = ""
    target_port: int = 0

    http_rewritten_headers: bytes = b""

    pipe_stage: PipeStage = PipeStage.FLOWING
    bytes_sent: int = 0
    bytes_received: int = 0

    error: str = ""


# ============================================================================
# Pipe reducer
# ============================================================================


def _pipe_reducer(
    state: ProxyProtocolState,
    event: Event,
    pipe_idle_timeout: float = 300.0,
) -> Transition:
    ps = state.pipe_stage

    if ps == PipeStage.CLOSED:
        return Transition(state=state, effects=())

    if isinstance(event, PipeIdleTimeout):
        new_state = replace(
            state,
            phase=Phase.CLOSED,
            pipe_stage=PipeStage.CLOSED,
            error=f"idle timeout ({event.elapsed:.0f}s)",
        )
        return Transition(
            state=new_state,
            effects=(clear_deadline("idle"), session_failed("idle timeout")),
        )

    if isinstance(event, PipeError):
        new_state = replace(
            state,
            phase=Phase.CLOSED,
            pipe_stage=PipeStage.CLOSED,
            error=f"{event.source.name.lower()}: {event.error_msg}",
        )
        return Transition(
            state=new_state,
            effects=(
                clear_deadline("idle"),
                session_failed(f"pipe error: {event.source.name.lower()}"),
            ),
        )

    if isinstance(event, SendFailed):
        new_state = replace(
            state,
            phase=Phase.CLOSED,
            pipe_stage=PipeStage.CLOSED,
            error=f"send failed: {event.where}",
        )
        return Transition(
            state=new_state,
            effects=(clear_deadline("idle"), session_failed(f"send failed: {event.where}")),
        )

    if isinstance(event, PipeDataFromClient):
        if ps in (PipeStage.HALF_CLOSED_CLIENT, PipeStage.CLOSED):
            return Transition(state=state, effects=())
        return Transition(
            state=replace(state, bytes_sent=state.bytes_sent + event.length),
            effects=(
                write_remote(event.data),
                set_deadline("idle", pipe_idle_timeout),
            ),
        )

    if isinstance(event, PipeDataFromRemote):
        if ps in (PipeStage.HALF_CLOSED_REMOTE, PipeStage.CLOSED):
            return Transition(state=state, effects=())
        return Transition(
            state=replace(state, bytes_received=state.bytes_received + event.length),
            effects=(
                write_client(event.data),
                set_deadline("idle", pipe_idle_timeout),
            ),
        )

    if isinstance(event, PipeEOF):
        if event.source == Endpoint.CLIENT:
            if ps == PipeStage.FLOWING:
                return Transition(
                    state=replace(state, pipe_stage=PipeStage.HALF_CLOSED_CLIENT),
                    effects=(pipe_write_eof(Endpoint.REMOTE),),
                )
            elif ps == PipeStage.HALF_CLOSED_REMOTE:
                return Transition(
                    state=replace(state, phase=Phase.CLOSED, pipe_stage=PipeStage.CLOSED),
                    effects=(clear_deadline("idle"), session_done("both eof")),
                )

        elif event.source == Endpoint.REMOTE:
            if ps == PipeStage.FLOWING:
                return Transition(
                    state=replace(state, pipe_stage=PipeStage.HALF_CLOSED_REMOTE),
                    effects=(pipe_write_eof(Endpoint.CLIENT),),
                )
            elif ps == PipeStage.HALF_CLOSED_CLIENT:
                return Transition(
                    state=replace(state, phase=Phase.CLOSED, pipe_stage=PipeStage.CLOSED),
                    effects=(clear_deadline("idle"), session_done("both eof")),
                )

        return Transition(state=state, effects=())

    return Transition(state=state, effects=())


# ============================================================================
# Handshake / lifecycle reducer
# ============================================================================


def proxy_protocol_reducer(
    state: ProxyProtocolState,
    event: Event,
    max_buffer: int = 8192,
    pipe_idle_timeout: float = 300.0,
) -> Transition:
    if state.phase == Phase.PIPING:
        return _pipe_reducer(state, event, pipe_idle_timeout=pipe_idle_timeout)

    if isinstance(event, SessionStarted):
        return Transition(state=state, effects=())

    if isinstance(event, HandshakeTimeout):
        new_state = replace(
            state,
            phase=Phase.CLOSED,
            buffer=b"",
            error=f"handshake timeout ({event.elapsed:.0f}s)",
        )
        return Transition(
            state=new_state,
            effects=(session_failed("handshake timeout"),),
        )

    if isinstance(event, (ClientConnectionClosed, SendFailed)):
        new_state = replace(state, phase=Phase.CLOSED, buffer=b"")
        return Transition(
            state=new_state,
            effects=(session_done("client/session closed"),),
        )

    if isinstance(event, OutboundStreamOpened):
        return _handle_target_connected(state, pipe_idle_timeout=pipe_idle_timeout)

    if isinstance(event, OutboundStreamOpenFailed):
        return _handle_target_connect_failed(state, event)

    if not isinstance(event, ClientDataReceived):
        return Transition(state=state, effects=())

    buf = state.buffer + event.data

    if len(buf) > max_buffer and state.phase not in (Phase.CONNECTING, Phase.PIPING):
        return Transition(
            state=replace(state, phase=Phase.CLOSED, buffer=b""),
            effects=(session_failed("handshake buffer overflow"),),
        )

    state = replace(state, buffer=buf)
    effects: List[Effect] = []

    while True:
        buf = state.buffer

        if state.phase == Phase.INIT:
            if len(buf) < 1:
                break

            if buf[0] == 0x05 and state.proxy_mode in (ProxyMode.SOCKS5, ProxyMode.BOTH):
                state = replace(state, phase=Phase.SOCKS5_AUTH)
                continue

            if state.proxy_mode in (ProxyMode.HTTP, ProxyMode.BOTH) and looks_like_http_request(buf):
                state = replace(state, phase=Phase.HTTP_REQ)
                continue

            if len(buf) < 8:
                break

            return Transition(
                state=replace(state, phase=Phase.CLOSED, buffer=b""),
                effects=(session_failed("unknown protocol"),),
            )

        elif state.phase == Phase.SOCKS5_AUTH:
            result = _handle_socks5_auth(state, effects)
            if result is None:
                break
            return result

        elif state.phase == Phase.SOCKS5_REQ:
            result = _handle_socks5_req(state, effects)
            if result is None:
                break
            return result

        elif state.phase == Phase.HTTP_REQ:
            result = _handle_http_req(state, effects)
            if result is None:
                break
            return result

        else:
            break

    return Transition(state=state, effects=tuple(effects))


def _handle_target_connected(
    state: ProxyProtocolState,
    pipe_idle_timeout: float = 300.0,
) -> Transition:
    effects: List[Effect] = []

    if state.session_mode == SessionMode.SOCKS5:
        effects.append(write_client(socks5_reply(0x00)))
        if state.buffer:
            effects.append(write_remote(state.buffer))

    elif state.session_mode == SessionMode.HTTP_CONNECT:
        effects.append(write_client(b"HTTP/1.1 200 Connection Established\r\n\r\n"))
        if state.buffer:
            effects.append(write_remote(state.buffer))

    elif state.session_mode == SessionMode.HTTP_PROXY:
        target_data = state.http_rewritten_headers + state.buffer
        effects.append(write_remote(target_data))

    early_bytes = len(state.buffer)
    new_state = replace(
        state,
        phase=Phase.PIPING,
        buffer=b"",
        pipe_stage=PipeStage.FLOWING,
        bytes_sent=state.bytes_sent + early_bytes,
    )
    effects.extend([start_pipe_runtime(), set_deadline("idle", pipe_idle_timeout)])

    return Transition(
        state=new_state,
        effects=tuple(effects),
    )


def _handle_target_connect_failed(
    state: ProxyProtocolState, event: OutboundStreamOpenFailed
) -> Transition:
    if state.session_mode == SessionMode.SOCKS5:
        rep = socks5_reply(map_connect_fail_to_socks_rep(event.reason))
    elif state.session_mode in (SessionMode.HTTP_CONNECT, SessionMode.HTTP_PROXY):
        rep = b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"
    else:
        rep = b""

    effs: List[Effect] = []
    if rep:
        effs.append(write_client(rep))
    effs.append(session_failed(f"connect failed: {event.reason.name.lower()}"))

    return Transition(
        state=replace(
            state,
            phase=Phase.CLOSED,
            buffer=b"",
            error=f"connect failed: {event.reason.name.lower()} {event.detail}".strip(),
        ),
        effects=tuple(effs),
    )


def _handle_socks5_auth(
    state: ProxyProtocolState, prior_effects: List[Effect]
) -> Optional[Transition]:
    buf = state.buffer
    if len(buf) < 2:
        return None

    ver = buf[0]
    nmethods = buf[1]

    if ver != 0x05:
        return Transition(
            state=replace(state, phase=Phase.CLOSED, buffer=b""),
            effects=(session_failed("invalid socks5 version"),),
        )

    if len(buf) < 2 + nmethods:
        return None

    methods = buf[2 : 2 + nmethods]
    if 0x00 not in methods:
        return Transition(
            state=replace(state, phase=Phase.CLOSED, buffer=b""),
            effects=(write_client(b"\x05\xFF"), session_failed("no acceptable auth method")),
        )

    prior_effects.append(write_client(b"\x05\x00"))
    new_state = replace(state, phase=Phase.SOCKS5_REQ, buffer=buf[2 + nmethods :])

    result = _handle_socks5_req(new_state, prior_effects)
    if result is None:
        return Transition(
            state=new_state,
            effects=tuple(prior_effects),
        )
    return result


def _handle_socks5_req(
    state: ProxyProtocolState, prior_effects: List[Effect]
) -> Optional[Transition]:
    buf = state.buffer
    if len(buf) < 4:
        return None

    ver, cmd, rsv, atyp = buf[0], buf[1], buf[2], buf[3]

    if ver != 0x05 or rsv != 0x00:
        return Transition(
            state=replace(state, phase=Phase.CLOSED, buffer=b""),
            effects=(session_failed("invalid socks5 request"),),
        )

    if cmd != 0x01:
        return Transition(
            state=replace(state, phase=Phase.CLOSED, buffer=b""),
            effects=(write_client(socks5_reply(0x07)), session_failed("unsupported socks5 cmd")),
        )

    try:
        if atyp == 0x01:
            if len(buf) < 10:
                return None
            host = ".".join(str(b) for b in buf[4:8])
            port = struct.unpack("!H", buf[8:10])[0]
            header_len = 10

        elif atyp == 0x03:
            if len(buf) < 5:
                return None
            dlen = buf[4]
            if len(buf) < 5 + dlen + 2:
                return None
            host = buf[5 : 5 + dlen].decode("ascii")
            port = struct.unpack("!H", buf[5 + dlen : 5 + dlen + 2])[0]
            header_len = 5 + dlen + 2

        elif atyp == 0x04:
            if len(buf) < 22:
                return None
            host = str(ipaddress.IPv6Address(buf[4:20]))
            port = struct.unpack("!H", buf[20:22])[0]
            header_len = 22

        else:
            return Transition(
                state=replace(state, phase=Phase.CLOSED, buffer=b""),
                effects=(write_client(socks5_reply(0x08)), session_failed("unsupported atyp")),
            )

    except Exception:
        return Transition(
            state=replace(state, phase=Phase.CLOSED, buffer=b""),
            effects=(write_client(socks5_reply(0x01)), session_failed("socks5 parse error")),
        )

    prior_effects.append(open_outbound_stream(host, port))
    return Transition(
        state=replace(
            state,
            phase=Phase.CONNECTING,
            session_mode=SessionMode.SOCKS5,
            target_host=host,
            target_port=port,
            buffer=buf[header_len:],
        ),
        effects=tuple(prior_effects),
    )


def _handle_http_req(
    state: ProxyProtocolState, prior_effects: List[Effect]
) -> Optional[Transition]:
    buf = state.buffer
    if b"\r\n\r\n" not in buf:
        return None

    head, body = buf.split(b"\r\n\r\n", 1)
    lines = head.split(b"\r\n")
    if not lines:
        return Transition(
            state=replace(state, phase=Phase.CLOSED, buffer=b""),
            effects=(session_failed("invalid http request"),),
        )

    try:
        first_line = lines[0].decode("ascii")
    except UnicodeDecodeError:
        return Transition(
            state=replace(state, phase=Phase.CLOSED, buffer=b""),
            effects=(session_failed("invalid http request line encoding"),),
        )

    parts = first_line.split()
    if len(parts) != 3:
        return Transition(
            state=replace(state, phase=Phase.CLOSED, buffer=b""),
            effects=(session_failed("invalid http request line"),),
        )

    method, target, version = parts
    method_b = method.encode("ascii")

    if method_b not in HTTP_METHODS:
        return Transition(
            state=replace(state, phase=Phase.CLOSED, buffer=b""),
            effects=(session_failed("unsupported http method"),),
        )

    try:
        if method == "CONNECT":
            host, port = parse_http_connect_target(target.encode("ascii"))
            prior_effects.append(open_outbound_stream(host, port))
            return Transition(
                state=replace(
                    state,
                    phase=Phase.CONNECTING,
                    session_mode=SessionMode.HTTP_CONNECT,
                    target_host=host,
                    target_port=port,
                    buffer=body,
                ),
                effects=tuple(prior_effects),
            )

        parsed = urlparse(target)
        hostname = parsed.hostname
        scheme = parsed.scheme or "http"
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        host_header_value = None
        other_headers: List[bytes] = []

        for line in lines[1:]:
            low = line.lower()
            if low.startswith(b"proxy-"):
                continue
            if low.startswith(b"host:"):
                try:
                    host_header_value = line[5:].strip().decode("ascii")
                except UnicodeDecodeError:
                    return Transition(
                        state=replace(state, phase=Phase.CLOSED, buffer=b""),
                        effects=(session_failed("invalid host header encoding"),),
                    )
                continue
            other_headers.append(line)

        if not hostname:
            if not host_header_value:
                return Transition(
                    state=replace(state, phase=Phase.CLOSED, buffer=b""),
                    effects=(session_failed("missing host in http request"),),
                )
            hostname, port = normalize_host_port_from_host_header(
                host_header_value, default_port=80
            )
            path = target if target.startswith("/") else "/" + target

        rebuilt_host = format_host_header(hostname, port, scheme)

        rewritten = f"{method} {path} {version}\r\n".encode("ascii")
        rewritten += f"Host: {rebuilt_host}\r\n".encode("ascii")
        for line in other_headers:
            rewritten += line + b"\r\n"
        rewritten += b"\r\n"

        prior_effects.append(open_outbound_stream(hostname, port))
        return Transition(
            state=replace(
                state,
                phase=Phase.CONNECTING,
                session_mode=SessionMode.HTTP_PROXY,
                target_host=hostname,
                target_port=port,
                http_rewritten_headers=rewritten,
                buffer=body,
            ),
            effects=tuple(prior_effects),
        )

    except Exception:
        return Transition(
            state=replace(state, phase=Phase.CLOSED, buffer=b""),
            effects=(session_failed("http parse error"),),
        )


# ============================================================================
# Sans-I/O unit tests
# ============================================================================


def _run_protocol_tests():
    print("Running Sans-I/O protocol tests...")
    passed = 0
    failed = 0

    def check(name, condition):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"  ✓ {name}")
        else:
            failed += 1
            print(f"  ✗ {name}")

    # ---------------------------------------------------------------------
    # Handshake / protocol detection
    # ---------------------------------------------------------------------

    s = ProxyProtocolState(proxy_mode=ProxyMode.SOCKS5)
    tr = proxy_protocol_reducer(s, SessionStarted())
    s = tr.state
    check("SessionStarted: phase unchanged", s.phase == Phase.INIT)

    s = ProxyProtocolState(proxy_mode=ProxyMode.SOCKS5)
    tr = proxy_protocol_reducer(s, ClientDataReceived(b"\x05\x01\x00"))
    s, effs = tr.state, list(tr.effects)
    check(
        "SOCKS5 auth: reply no-auth",
        any(e.type == EffectType.WRITE_CLIENT and e.data == b"\x05\x00" for e in effs),
    )
    check("SOCKS5 auth: phase -> SOCKS5_REQ", s.phase == Phase.SOCKS5_REQ)

    req = b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50"
    tr = proxy_protocol_reducer(s, ClientDataReceived(req))
    s, effs = tr.state, list(tr.effects)
    check("SOCKS5 req: phase -> CONNECTING", s.phase == Phase.CONNECTING)
    check(
        "SOCKS5 req: OPEN_OUTBOUND effect",
        any(
            e.type == EffectType.OPEN_OUTBOUND_STREAM and e.data == ("127.0.0.1", 80)
            for e in effs
        ),
    )
    check(
        "SOCKS5 req: target parsed",
        s.target_host == "127.0.0.1" and s.target_port == 80,
    )

    tr = proxy_protocol_reducer(s, OutboundStreamOpened(), pipe_idle_timeout=123.0)
    s, effs = tr.state, list(tr.effects)
    check("SOCKS5 connected: phase -> PIPING", s.phase == Phase.PIPING)
    check(
        "SOCKS5 connected: pipe_stage FLOWING",
        s.pipe_stage == PipeStage.FLOWING,
    )
    check(
        "SOCKS5 connected: success reply",
        any(
            e.type == EffectType.WRITE_CLIENT and e.data == socks5_reply(0x00)
            for e in effs
        ),
    )
    check(
        "SOCKS5 connected: start pipe runtime",
        any(e.type == EffectType.START_PIPE_RUNTIME for e in effs),
    )
    check(
        "SOCKS5 connected: set idle deadline from arg",
        any(
            e.type == EffectType.SET_DEADLINE
            and (e.data or {}).get("kind") == "idle"
            and (e.data or {}).get("timeout") == 123.0
            for e in effs
        ),
    )

    s2 = ProxyProtocolState(proxy_mode=ProxyMode.SOCKS5)
    s2 = proxy_protocol_reducer(s2, ClientDataReceived(b"\x05\x01\x00")).state
    s2 = proxy_protocol_reducer(s2, ClientDataReceived(req)).state
    tr2 = proxy_protocol_reducer(
        s2, OutboundStreamOpenFailed(ConnectFailReason.REFUSED, "refused")
    )
    s2, effs2 = tr2.state, list(tr2.effects)
    check("SOCKS5 fail: phase -> CLOSED", s2.phase == Phase.CLOSED)
    check(
        "SOCKS5 fail: error reply + failed",
        any(e.type == EffectType.WRITE_CLIENT for e in effs2)
        and any(e.type == EffectType.SESSION_FAILED for e in effs2),
    )

    s3 = ProxyProtocolState(proxy_mode=ProxyMode.SOCKS5)
    tr3 = proxy_protocol_reducer(s3, ClientDataReceived(b"\x05"))
    s3, effs3 = tr3.state, list(tr3.effects)
    check("SOCKS5 partial: wait for more", s3.phase == Phase.SOCKS5_AUTH)
    check("SOCKS5 partial: no effects yet", effs3 == [])

    tr3 = proxy_protocol_reducer(s3, ClientDataReceived(b"\x01\x00"))
    s3, effs3 = tr3.state, list(tr3.effects)
    check(
        "SOCKS5 partial: complete auth",
        s3.phase == Phase.SOCKS5_REQ
        and any(e.type == EffectType.WRITE_CLIENT and e.data == b"\x05\x00" for e in effs3),
    )

    s4 = ProxyProtocolState(proxy_mode=ProxyMode.SOCKS5)
    combined = b"\x05\x01\x00" + b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50"
    tr4 = proxy_protocol_reducer(s4, ClientDataReceived(combined))
    s4, effs4 = tr4.state, list(tr4.effects)
    check("SOCKS5 combined: phase -> CONNECTING", s4.phase == Phase.CONNECTING)
    check(
        "SOCKS5 combined: auth reply + connect",
        any(e.type == EffectType.WRITE_CLIENT and e.data == b"\x05\x00" for e in effs4)
        and any(e.type == EffectType.OPEN_OUTBOUND_STREAM for e in effs4),
    )

    s5 = ProxyProtocolState(proxy_mode=ProxyMode.HTTP)
    http_req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"
    tr5 = proxy_protocol_reducer(s5, ClientDataReceived(http_req))
    s5, effs5 = tr5.state, list(tr5.effects)
    check("HTTP CONNECT: phase -> CONNECTING", s5.phase == Phase.CONNECTING)
    check(
        "HTTP CONNECT: target",
        s5.target_host == "example.com" and s5.target_port == 443,
    )
    check(
        "HTTP CONNECT: effect",
        any(
            e.type == EffectType.OPEN_OUTBOUND_STREAM and e.data == ("example.com", 443)
            for e in effs5
        ),
    )

    tr5 = proxy_protocol_reducer(s5, OutboundStreamOpened())
    s5, effs5 = tr5.state, list(tr5.effects)
    check("HTTP CONNECT ok: phase -> PIPING", s5.phase == Phase.PIPING)
    check(
        "HTTP CONNECT ok: 200 reply",
        any(b"200" in e.data for e in effs5 if e.type == EffectType.WRITE_CLIENT),
    )

    s6 = ProxyProtocolState(proxy_mode=ProxyMode.HTTP)
    get_req = (
        b"GET http://example.com/path?q=1 HTTP/1.1\r\n"
        b"Host: example.com\r\nProxy-Connection: keep-alive\r\n\r\n"
    )
    tr6 = proxy_protocol_reducer(s6, ClientDataReceived(get_req))
    s6, effs6 = tr6.state, list(tr6.effects)
    check("HTTP Proxy GET: phase -> CONNECTING", s6.phase == Phase.CONNECTING)
    check(
        "HTTP Proxy GET: target",
        s6.target_host == "example.com" and s6.target_port == 80,
    )
    check(
        "HTTP Proxy GET: rewritten has path not URL",
        b"GET /path?q=1 HTTP/1.1" in s6.http_rewritten_headers,
    )
    check(
        "HTTP Proxy GET: no Proxy-Connection header",
        b"Proxy-Connection" not in s6.http_rewritten_headers,
    )

    s6b = ProxyProtocolState(proxy_mode=ProxyMode.HTTP)
    get_req2 = (
        b"GET /abc HTTP/1.1\r\n"
        b"Host: example.org:8080\r\n"
        b"Connection: keep-alive\r\n\r\n"
    )
    tr6b = proxy_protocol_reducer(s6b, ClientDataReceived(get_req2))
    s6b, effs6b = tr6b.state, list(tr6b.effects)
    check("HTTP origin-form + Host: phase -> CONNECTING", s6b.phase == Phase.CONNECTING)
    check(
        "HTTP origin-form + Host: target from Host header",
        s6b.target_host == "example.org" and s6b.target_port == 8080,
    )
    check(
        "HTTP origin-form + Host: rewritten request line kept path",
        b"GET /abc HTTP/1.1" in s6b.http_rewritten_headers,
    )

    s6c = ProxyProtocolState(proxy_mode=ProxyMode.HTTP)
    bad_http = b"GET /x HTTP/1.1\r\n\r\n"
    tr6c = proxy_protocol_reducer(s6c, ClientDataReceived(bad_http))
    s6c, effs6c = tr6c.state, list(tr6c.effects)
    check(
        "HTTP missing Host for origin-form -> CLOSED",
        s6c.phase == Phase.CLOSED and any(e.type == EffectType.SESSION_FAILED for e in effs6c),
    )

    s6d = ProxyProtocolState(proxy_mode=ProxyMode.HTTP)
    tr6d = proxy_protocol_reducer(s6d, ClientDataReceived(b"BOGUS / HTTP/1.1\r\n\r\n"))
    s6d, effs6d = tr6d.state, list(tr6d.effects)
    check(
        "HTTP unsupported method/unknown protocol path closes eventually",
        s6d.phase in (Phase.INIT, Phase.CLOSED),
    )

    s7 = ProxyProtocolState(proxy_mode=ProxyMode.BOTH)
    big_data = b"X" * 9000
    tr7 = proxy_protocol_reducer(s7, ClientDataReceived(big_data), max_buffer=8192)
    s7, effs7 = tr7.state, list(tr7.effects)
    check(
        "Buffer overflow: closed",
        s7.phase == Phase.CLOSED
        and any(e.type == EffectType.SESSION_FAILED for e in effs7),
    )

    s8 = ProxyProtocolState(proxy_mode=ProxyMode.SOCKS5)
    tr8 = proxy_protocol_reducer(s8, ClientConnectionClosed())
    s8 = tr8.state
    check("ConnectionClosed: phase -> CLOSED", s8.phase == Phase.CLOSED)

    s9 = ProxyProtocolState(proxy_mode=ProxyMode.SOCKS5)
    s9 = proxy_protocol_reducer(s9, ClientDataReceived(b"\x05\x01\x00")).state
    ipv6_req = b"\x05\x01\x00\x04" + b"\x00" * 15 + b"\x01" + struct.pack("!H", 8080)
    tr9 = proxy_protocol_reducer(s9, ClientDataReceived(ipv6_req))
    s9, effs9 = tr9.state, list(tr9.effects)
    check("SOCKS5 IPv6: phase -> CONNECTING", s9.phase == Phase.CONNECTING)
    check(
        "SOCKS5 IPv6: target is ipv6",
        s9.target_host == "::1" and s9.target_port == 8080,
    )

    s10 = ProxyProtocolState(proxy_mode=ProxyMode.SOCKS5)
    tr10 = proxy_protocol_reducer(
        s10, ClientDataReceived(b"\x04\x01\x00\x50\x7f\x00\x00\x01userid\x00")
    )
    s10, effs10 = tr10.state, list(tr10.effects)
    check(
        "Unknown proto: closed",
        s10.phase == Phase.CLOSED
        and any(e.type == EffectType.SESSION_FAILED for e in effs10),
    )

    s11 = ProxyProtocolState(proxy_mode=ProxyMode.SOCKS5)
    s11 = proxy_protocol_reducer(s11, ClientDataReceived(b"\x05\x01\x00")).state
    trailing = b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50" + b"early-data"
    s11 = proxy_protocol_reducer(s11, ClientDataReceived(trailing)).state
    check("SOCKS5 trailing: buffered", s11.buffer == b"early-data")
    tr11 = proxy_protocol_reducer(s11, OutboundStreamOpened())
    effs11 = list(tr11.effects)
    check(
        "SOCKS5 trailing: written on connect",
        any(
            e.type == EffectType.WRITE_REMOTE and e.data == b"early-data"
            for e in effs11
        ),
    )

    tr_to = proxy_protocol_reducer(
        ProxyProtocolState(proxy_mode=ProxyMode.SOCKS5), HandshakeTimeout(10.0)
    )
    check("Handshake timeout -> CLOSED", tr_to.state.phase == Phase.CLOSED)

    s12 = ProxyProtocolState(proxy_mode=ProxyMode.SOCKS5)
    tr12 = proxy_protocol_reducer(s12, ClientDataReceived(b"\x05\x01\x02"))
    s12, effs12 = tr12.state, list(tr12.effects)
    check(
        "SOCKS5 no acceptable method",
        s12.phase == Phase.CLOSED
        and any(e.type == EffectType.WRITE_CLIENT and e.data == b"\x05\xFF" for e in effs12),
    )

    s13 = ProxyProtocolState(proxy_mode=ProxyMode.SOCKS5)
    s13 = proxy_protocol_reducer(s13, ClientDataReceived(b"\x05\x01\x00")).state
    bad_cmd = b"\x05\x02\x00\x01\x7f\x00\x00\x01\x00\x50"
    tr13 = proxy_protocol_reducer(s13, ClientDataReceived(bad_cmd))
    s13, effs13 = tr13.state, list(tr13.effects)
    check(
        "SOCKS5 unsupported cmd",
        s13.phase == Phase.CLOSED
        and any(
            e.type == EffectType.WRITE_CLIENT and e.data == socks5_reply(0x07)
            for e in effs13
        ),
    )

    s14 = ProxyProtocolState(proxy_mode=ProxyMode.SOCKS5)
    s14 = proxy_protocol_reducer(s14, ClientDataReceived(b"\x05\x01\x00")).state
    bad_atyp = b"\x05\x01\x00\x09xxxx"
    tr14 = proxy_protocol_reducer(s14, ClientDataReceived(bad_atyp))
    s14, effs14 = tr14.state, list(tr14.effects)
    check(
        "SOCKS5 unsupported atyp",
        s14.phase == Phase.CLOSED
        and any(
            e.type == EffectType.WRITE_CLIENT and e.data == socks5_reply(0x08)
            for e in effs14
        ),
    )

    s15 = ProxyProtocolState(proxy_mode=ProxyMode.HTTP)
    http_ipv6 = b"CONNECT [::1]:8443 HTTP/1.1\r\nHost: [::1]:8443\r\n\r\n"
    tr15 = proxy_protocol_reducer(s15, ClientDataReceived(http_ipv6))
    s15 = tr15.state
    check(
        "HTTP CONNECT IPv6 target parsed",
        s15.phase == Phase.CONNECTING and s15.target_host == "::1" and s15.target_port == 8443,
    )

    # ---------------------------------------------------------------------
    # Piping stage tests
    # ---------------------------------------------------------------------

    print("\n  --- Piping stage tests ---")

    def make_piping_state(**kwargs) -> ProxyProtocolState:
        defaults = dict(
            phase=Phase.PIPING,
            pipe_stage=PipeStage.FLOWING,
            target_host="example.com",
            target_port=80,
        )
        defaults.update(kwargs)
        return ProxyProtocolState(**defaults)

    ps1 = make_piping_state()
    trp1 = proxy_protocol_reducer(ps1, PipeDataFromClient(b"hello", 5), pipe_idle_timeout=77.0)
    ps1, effs_p1 = trp1.state, list(trp1.effects)
    check(
        "Pipe: forward client->remote",
        any(
            e.type == EffectType.WRITE_REMOTE and e.data == b"hello"
            for e in effs_p1
        ),
    )
    check("Pipe: bytes_sent updated", ps1.bytes_sent == 5)
    check(
        "Pipe: reset idle deadline on client data with configured timeout",
        any(
            e.type == EffectType.SET_DEADLINE
            and (e.data or {}).get("kind") == "idle"
            and (e.data or {}).get("timeout") == 77.0
            for e in effs_p1
        ),
    )

    ps2 = make_piping_state()
    trp2 = proxy_protocol_reducer(ps2, PipeDataFromRemote(b"world", 5), pipe_idle_timeout=88.0)
    ps2, effs_p2 = trp2.state, list(trp2.effects)
    check(
        "Pipe: forward remote->client",
        any(
            e.type == EffectType.WRITE_CLIENT and e.data == b"world"
            for e in effs_p2
        ),
    )
    check("Pipe: bytes_received updated", ps2.bytes_received == 5)
    check(
        "Pipe: reset idle deadline on remote data with configured timeout",
        any(
            e.type == EffectType.SET_DEADLINE
            and (e.data or {}).get("kind") == "idle"
            and (e.data or {}).get("timeout") == 88.0
            for e in effs_p2
        ),
    )

    ps3 = make_piping_state()
    trp3 = proxy_protocol_reducer(ps3, PipeEOF(Endpoint.CLIENT))
    ps3, effs_p3 = trp3.state, list(trp3.effects)
    check(
        "Pipe: client EOF -> HALF_CLOSED_CLIENT",
        ps3.pipe_stage == PipeStage.HALF_CLOSED_CLIENT,
    )
    check(
        "Pipe: write EOF to remote",
        any(
            e.type == EffectType.PIPE_WRITE_EOF and e.data == Endpoint.REMOTE
            for e in effs_p3
        ),
    )

    trp3b = proxy_protocol_reducer(ps3, PipeEOF(Endpoint.REMOTE))
    ps3, effs_p3b = trp3b.state, list(trp3b.effects)
    check(
        "Pipe: both EOF -> CLOSED",
        ps3.pipe_stage == PipeStage.CLOSED and ps3.phase == Phase.CLOSED,
    )
    check(
        "Pipe: session done on both EOF",
        any(e.type == EffectType.SESSION_DONE for e in effs_p3b),
    )

    ps4 = make_piping_state()
    trp4 = proxy_protocol_reducer(ps4, PipeEOF(Endpoint.REMOTE))
    ps4, effs_p4 = trp4.state, list(trp4.effects)
    check(
        "Pipe: remote EOF -> HALF_CLOSED_REMOTE",
        ps4.pipe_stage == PipeStage.HALF_CLOSED_REMOTE,
    )

    trp4b = proxy_protocol_reducer(ps4, PipeDataFromRemote(b"late", 4))
    ps4b, effs_p4b = trp4b.state, list(trp4b.effects)
    check(
        "Pipe: data from closed remote ignored",
        not any(e.type == EffectType.WRITE_CLIENT for e in effs_p4b),
    )

    trp4c = proxy_protocol_reducer(ps4, PipeDataFromClient(b"still-ok", 8))
    ps4c, effs_p4c = trp4c.state, list(trp4c.effects)
    check(
        "Pipe: client data during half-close OK",
        any(e.type == EffectType.WRITE_REMOTE for e in effs_p4c),
    )

    ps5 = make_piping_state()
    trp5 = proxy_protocol_reducer(ps5, PipeError(Endpoint.REMOTE, "connection reset"))
    ps5, effs_p5 = trp5.state, list(trp5.effects)
    check(
        "Pipe: error -> CLOSED",
        ps5.pipe_stage == PipeStage.CLOSED and ps5.phase == Phase.CLOSED,
    )
    check(
        "Pipe: error -> failed",
        any(e.type == EffectType.SESSION_FAILED for e in effs_p5),
    )
    check("Pipe: error recorded", "reset" in ps5.error)

    ps5b = make_piping_state()
    trp5b = proxy_protocol_reducer(ps5b, SendFailed("remote_write"))
    ps5b, effs_p5b = trp5b.state, list(trp5b.effects)
    check(
        "Pipe: SendFailed -> CLOSED",
        ps5b.pipe_stage == PipeStage.CLOSED and ps5b.phase == Phase.CLOSED,
    )
    check(
        "Pipe: SendFailed -> failed",
        any(e.type == EffectType.SESSION_FAILED for e in effs_p5b),
    )
    check("Pipe: SendFailed error recorded", "send failed" in ps5b.error)

    ps6 = make_piping_state()
    trp6 = proxy_protocol_reducer(ps6, PipeIdleTimeout(300.0))
    ps6, effs_p6 = trp6.state, list(trp6.effects)
    check(
        "Pipe: idle timeout -> CLOSED",
        ps6.pipe_stage == PipeStage.CLOSED and ps6.phase == Phase.CLOSED,
    )
    check(
        "Pipe: idle timeout clears deadline",
        any(e.type == EffectType.CLEAR_DEADLINE for e in effs_p6),
    )

    ps7 = make_piping_state(pipe_stage=PipeStage.CLOSED, phase=Phase.CLOSED)
    trp7 = proxy_protocol_reducer(ps7, PipeDataFromClient(b"ignored", 7))
    ps7, effs_p7 = trp7.state, list(trp7.effects)
    check("Pipe: data after CLOSED ignored", effs_p7 == [] and ps7.bytes_sent == 0)

    ps8 = make_piping_state()
    ps8 = proxy_protocol_reducer(ps8, PipeDataFromClient(b"aaa", 3)).state
    ps8 = proxy_protocol_reducer(ps8, PipeDataFromRemote(b"bb", 2)).state
    ps8 = proxy_protocol_reducer(ps8, PipeDataFromClient(b"cccc", 4)).state
    check("Pipe: stats accumulate (sent)", ps8.bytes_sent == 7)
    check("Pipe: stats accumulate (recv)", ps8.bytes_received == 2)

    ps9 = make_piping_state(pipe_stage=PipeStage.HALF_CLOSED_CLIENT)
    trp9 = proxy_protocol_reducer(ps9, PipeError(Endpoint.REMOTE, "reset"))
    ps9, effs_p9 = trp9.state, list(trp9.effects)
    check(
        "Pipe: error during half-close -> CLOSED",
        ps9.pipe_stage == PipeStage.CLOSED and ps9.phase == Phase.CLOSED,
    )

    ps10 = make_piping_state(pipe_stage=PipeStage.HALF_CLOSED_CLIENT)
    trp10 = proxy_protocol_reducer(ps10, PipeDataFromClient(b"nope", 4))
    ps10, effs_p10 = trp10.state, list(trp10.effects)
    check(
        "Pipe: client data after client EOF ignored",
        effs_p10 == [] and ps10.bytes_sent == 0,
    )

    print(f"\nProtocol test results: {passed} passed, {failed} failed")
    return failed == 0


# ============================================================================
# Test Client State Machine
# ============================================================================


@dataclass(frozen=True)
class TestStart(Event):
    pass


class TestStage(Enum):
    INIT = auto()
    SOCKS_WAIT_AUTH_REP = auto()
    SOCKS_WAIT_CONN_REP = auto()
    HTTP_WAIT_CONNECT_REP = auto()
    HTTP_WAIT_DATA = auto()
    WAIT_HTTP_DATA = auto()
    SUCCESS = auto()
    FAILED = auto()


@dataclass(frozen=True)
class TestClientState:
    stage: TestStage = TestStage.INIT
    proxy_mode: ProxyMode = ProxyMode.SOCKS5

    test_host: str = ""
    test_port: int = 80
    test_path: str = "/"
    test_url_raw: str = ""
    is_https: bool = False

    buffer: bytes = b""


def parse_http_status_line(buf: bytes) -> Optional[Tuple[int, str]]:
    if b"\r\n" not in buf:
        return None
    first = buf.split(b"\r\n", 1)[0]
    try:
        text = first.decode("ascii", errors="strict")
    except UnicodeDecodeError:
        return None
    parts = text.split(" ", 2)
    if len(parts) < 2 or not parts[1].isdigit():
        return None
    return int(parts[1]), text


def test_client_reducer(
    state: TestClientState, event: Event
) -> Tuple[TestClientState, List[Effect]]:
    if isinstance(event, ClientConnectionClosed):
        if state.stage == TestStage.SUCCESS:
            return state, []
        return replace(state, stage=TestStage.FAILED), [
            test_log(False, "Connection closed unexpectedly"),
            session_failed("test connection closed"),
        ]

    if isinstance(event, TestStart):
        if state.proxy_mode in (ProxyMode.SOCKS5, ProxyMode.BOTH):
            return replace(state, stage=TestStage.SOCKS_WAIT_AUTH_REP), [write_client(b"\x05\x01\x00")]
        if state.is_https:
            req = (
                f"CONNECT {state.test_host}:{state.test_port} HTTP/1.1\r\n"
                f"Host: {state.test_host}:{state.test_port}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            return replace(state, stage=TestStage.HTTP_WAIT_CONNECT_REP), [write_client(req)]

        req = (
            f"GET {state.test_url_raw} HTTP/1.1\r\n"
            f"Host: {state.test_host}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")
        return replace(state, stage=TestStage.HTTP_WAIT_DATA), [write_client(req)]

    if not isinstance(event, ClientDataReceived):
        return state, []

    buf = state.buffer + event.data

    if state.stage == TestStage.SOCKS_WAIT_AUTH_REP:
        if len(buf) < 2:
            return replace(state, buffer=buf), []
        if buf[:2] != b"\x05\x00":
            return replace(state, stage=TestStage.FAILED), [
                test_log(False, "SOCKS5 handshake failed"),
                session_failed("test socks handshake failed"),
            ]
        addr = state.test_host.encode("ascii")
        req = (
            struct.pack("!BBBBB", 0x05, 0x01, 0x00, 0x03, len(addr))
            + addr
            + struct.pack("!H", state.test_port)
        )
        return replace(state, stage=TestStage.SOCKS_WAIT_CONN_REP, buffer=buf[2:]), [write_client(req)]

    if state.stage == TestStage.SOCKS_WAIT_CONN_REP:
        if len(buf) < 4:
            return replace(state, buffer=buf), []

        if buf[1] != 0x00:
            return replace(state, stage=TestStage.FAILED), [
                test_log(False, f"SOCKS5 connect failed (rep={buf[1]})"),
                session_failed("test socks connect failed"),
            ]

        atyp = buf[3]
        if atyp == 0x01:
            header_len = 10
        elif atyp == 0x03:
            if len(buf) >= 5:
                header_len = 5 + buf[4] + 2
            else:
                return replace(state, buffer=buf), []
        elif atyp == 0x04:
            header_len = 22
        else:
            return replace(state, stage=TestStage.FAILED), [
                test_log(False, f"Unknown atyp {atyp}"),
                session_failed("test unknown atyp"),
            ]

        if len(buf) < header_len:
            return replace(state, buffer=buf), []

        req = (
            f"GET {state.test_path} HTTP/1.1\r\n"
            f"Host: {state.test_host}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")
        return replace(state, stage=TestStage.WAIT_HTTP_DATA, buffer=buf[header_len:]), [write_client(req)]

    if state.stage == TestStage.HTTP_WAIT_CONNECT_REP:
        if b"\r\n\r\n" not in buf:
            return replace(state, buffer=buf), []

        status = parse_http_status_line(buf)

        if not status or status[0] != 200:
            line = status[1] if status else "Invalid response"
            return replace(state, stage=TestStage.FAILED), [
                test_log(False, f"HTTP CONNECT failed: {line}"),
                session_failed("test http connect failed"),
            ]

        req = (
            f"GET {state.test_path} HTTP/1.1\r\n"
            f"Host: {state.test_host}\r\n"
            f"Connection: close\r\n\r\n"
        ).encode("ascii")
        head_len = buf.find(b"\r\n\r\n") + 4
        return replace(state, stage=TestStage.WAIT_HTTP_DATA, buffer=buf[head_len:]), [write_client(req)]

    if state.stage in (TestStage.WAIT_HTTP_DATA, TestStage.HTTP_WAIT_DATA):
        status = parse_http_status_line(buf)
        if status:
            code, line = status
            if b"\r\n\r\n" in buf or len(buf) > 512:
                ok = 200 <= code < 400
                return replace(state, stage=TestStage.SUCCESS if ok else TestStage.FAILED), [
                    test_log(ok, line),
                    session_done("test completed"),
                ]
        return replace(state, buffer=buf), []

    return state, []


# ============================================================================
# Runtime State / Utilities
# ============================================================================


@dataclass
class Stats:
    bytes_sent: int = 0
    bytes_received: int = 0
    active: int = 0
    total: int = 0
    peak: int = 0
    errors: int = 0
    start_time: float = field(default_factory=time.monotonic)


@dataclass
class PoolSlot:
    conn: Optional[asyncssh.SSHClientConnection] = None
    slot_id: str = field(default_factory=lambda: uuid.uuid4().hex[-6:])
    usage: int = 0
    last_used: float = field(default_factory=time.monotonic)


@dataclass
class PoolState:
    slots: List[Optional[PoolSlot]] = field(default_factory=list)
    watchers: List[Optional[asyncio.Task]] = field(default_factory=list)
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    closed: bool = False


@dataclass
class ServerState:
    stats: Stats = field(default_factory=Stats)
    pool: PoolState = field(default_factory=PoolState)
    server: Optional[asyncio.AbstractServer] = None
    shutdown_event: asyncio.Event = field(default_factory=asyncio.Event)
    active_tasks: set = field(default_factory=set)


def format_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}PB"


def stats_summary(s: Stats) -> str:
    return (
        f"Uptime: {(time.monotonic() - s.start_time) / 60:.1f}min | "
        f"Connections: {s.active} active, {s.total} total, {s.peak} peak | "
        f"Traffic: ↑{format_bytes(s.bytes_sent)} "
        f"↓{format_bytes(s.bytes_received)} | "
        f"Errors: {s.errors}"
    )


def pool_status_str(pool: PoolState) -> str:
    alive = sum(1 for s in pool.slots if s and s.conn and not s.conn.is_closed())
    return f"{alive}/{len(pool.slots)} connections alive"


async def safe_close(writer):
    if not writer:
        return
    try:
        if hasattr(writer, "is_closing") and writer.is_closing():
            return
        writer.close()
        if hasattr(writer, "wait_closed"):
            await asyncio.wait_for(writer.wait_closed(), timeout=3.0)
    except Exception:
        pass


# ============================================================================
# I/O Guard Helpers
# ============================================================================


def _is_writer_usable(writer) -> bool:
    if writer is None:
        return False
    try:
        if hasattr(writer, "is_closing") and writer.is_closing():
            return False
        if hasattr(writer, "_session") and writer._session is None:
            return False
        transport = getattr(writer, "_transport", None)
        if transport is not None:
            if hasattr(transport, "is_closing") and transport.is_closing():
                return False
    except Exception:
        return False
    return True


def _pause_reader_if_possible(reader):
    if reader is None:
        return
    transport = getattr(reader, "_transport", None)
    if transport is not None and hasattr(transport, "pause_reading"):
        try:
            transport.pause_reading()
        except Exception:
            pass


def _resume_reader_if_possible(reader):
    if reader is None:
        return
    transport = getattr(reader, "_transport", None)
    if transport is not None and hasattr(transport, "resume_reading"):
        try:
            transport.resume_reading()
        except Exception:
            pass


# ============================================================================
# SSH Pool
# ============================================================================


def init_pool_state(size: int) -> PoolState:
    return PoolState(slots=[None] * size, watchers=[None] * size)


def build_ssh_kwargs(c: Config) -> Dict[str, Any]:
    kw: Dict[str, Any] = {
        "host": c.ssh_host,
        "port": c.ssh_port,
        "username": c.ssh_username,
        "keepalive_interval": c.keepalive_interval,
        "known_hosts": c.known_hosts,
        "agent_path": None,
    }
    if c.ssh_key_path:
        kw["client_keys"] = [c.ssh_key_path]
        if c.ssh_key_passphrase:
            kw["passphrase"] = c.ssh_key_passphrase
    else:
        kw["password"] = c.ssh_password
    return kw


async def create_ssh_connection(cfg: Config):
    return await asyncio.wait_for(
        asyncssh.connect(**build_ssh_kwargs(cfg)),
        timeout=cfg.connection_timeout,
    )


async def watch_connection(cfg: Config, pool: PoolState, idx: int, log: logging.Logger):
    while not pool.closed:
        async with pool.lock:
            slot = pool.slots[idx]

        if slot and slot.conn:
            try:
                await slot.conn.wait_closed()
            except asyncio.CancelledError:
                break
            except Exception:
                pass
        else:
            try:
                await asyncio.sleep(cfg.retry_delay)
            except asyncio.CancelledError:
                break

        if pool.closed:
            break

        if slot and slot.conn:
            log.warning(f"Connection #{idx} (...{slot.slot_id}) lost. Reconnecting...")

        async with pool.lock:
            pool.slots[idx] = None

        rc = 0
        while not pool.closed:
            rc += 1
            try:
                new_conn = await create_ssh_connection(cfg)
                new_slot = PoolSlot(conn=new_conn)
                async with pool.lock:
                    pool.slots[idx] = new_slot
                log.info(f"  ✓ Connection #{idx} re-established (...{new_slot.slot_id})")
                break
            except asyncio.CancelledError:
                return
            except Exception as e:
                delay = min(cfg.retry_delay * (2 ** (rc - 1)), 30.0)
                if rc <= 3:
                    log.warning(
                        f"  ✗ Reconnect #{idx} attempt {rc} failed: {e}. Retry in {delay}s..."
                    )
                try:
                    await asyncio.sleep(delay)
                except asyncio.CancelledError:
                    return


async def create_initial_connection(
    cfg: Config, pool: PoolState, idx: int, log: logging.Logger
) -> bool:
    for att in range(1, cfg.max_retries + 1):
        if pool.closed:
            return False
        try:
            conn = await create_ssh_connection(cfg)
            slot = PoolSlot(conn=conn)
            async with pool.lock:
                pool.slots[idx] = slot
            pool.watchers[idx] = asyncio.create_task(watch_connection(cfg, pool, idx, log))
            log.info(f"  ✓ Connection #{idx} established (...{slot.slot_id})")
            return True
        except asyncio.CancelledError:
            return False
        except Exception as e:
            log.warning(
                f"  ✗ Connection #{idx} attempt {att}/{cfg.max_retries} failed: {e}"
            )
            if att < cfg.max_retries:
                await asyncio.sleep(cfg.retry_delay)

    log.error(
        f"  ✗ Connection #{idx} failed initial attempts. Switching to background retry."
    )
    pool.watchers[idx] = asyncio.create_task(watch_connection(cfg, pool, idx, log))
    return False


async def init_pool(cfg: Config, pool: PoolState, log: logging.Logger) -> bool:
    log.info(f"Initializing connection pool (size={cfg.pool_size})...")
    results = await asyncio.gather(
        *[create_initial_connection(cfg, pool, i, log) for i in range(cfg.pool_size)],
        return_exceptions=True,
    )
    ok = sum(1 for r in results if r is True)

    if ok == 0:
        log.warning(
            "⚠️ Failed to establish any initial SSH connections. Will retry in background."
        )
    elif ok < cfg.pool_size:
        log.warning(
            f"Pool partially initialized: {ok}/{cfg.pool_size}. Background tasks will continue."
        )
    else:
        log.info(f"✓ Connection pool fully initialized ({ok} connections)")
    return True


async def acquire_connection(pool: PoolState):
    async with pool.lock:
        best_indices = []
        best_usage = float("inf")

        for i, slot in enumerate(pool.slots):
            if slot and slot.conn and not slot.conn.is_closed():
                if slot.usage < best_usage:
                    best_usage = slot.usage
                    best_indices = [i]
                elif slot.usage == best_usage:
                    best_indices.append(i)

        if not best_indices:
            return None

        best_idx = min(best_indices, key=lambda i: pool.slots[i].last_used)
        slot = pool.slots[best_idx]
        slot.usage += 1
        slot.last_used = time.monotonic()
        return best_idx, slot.conn, slot.slot_id


async def acquire_connection_with_retry(pool: PoolState, timeout: float = 5.0):
    deadline = time.monotonic() + timeout
    while True:
        res = await acquire_connection(pool)
        if res is not None:
            return res
        if time.monotonic() >= deadline:
            break
        await asyncio.sleep(0.2)
    return None


async def release_connection(pool: PoolState, idx: int, slot_id: str):
    async with pool.lock:
        slot = pool.slots[idx]
        if slot and slot.slot_id == slot_id:
            slot.usage = max(0, slot.usage - 1)


async def close_pool(pool: PoolState):
    pool.closed = True

    for w in pool.watchers:
        if w and not w.done():
            w.cancel()

    async with pool.lock:
        for i, slot in enumerate(pool.slots):
            if slot and slot.conn and not slot.conn.is_closed():
                try:
                    slot.conn.close()
                    await asyncio.wait_for(slot.conn.wait_closed(), timeout=3.0)
                except Exception:
                    pass
            pool.slots[i] = None


# ============================================================================
# Shell I/O Context
# ============================================================================


@dataclass
class RelayFlowState:
    pending_to_remote: int = 0
    pending_to_client: int = 0
    client_reading_paused: bool = False
    remote_reading_paused: bool = False


@dataclass
class IOContext:
    client_writer: Any = None
    client_reader: Any = None
    remote_reader: Any = None
    remote_writer: Any = None
    pool_idx: Optional[int] = None
    pool_slot_id: Optional[str] = None

    pipe_event_queue: Optional[asyncio.Queue] = None
    pipe_reader_tasks: List[asyncio.Task] = field(default_factory=list)
    idle_timer_handle: Optional[asyncio.TimerHandle] = None

    relay_flow: RelayFlowState = field(default_factory=RelayFlowState)

    closed: bool = False


# ============================================================================
# Shell helpers
# ============================================================================


async def _start_pipe_runtime_if_needed(ctx: IOContext, cfg: Config):
    if ctx.pipe_event_queue is not None:
        return
    if not ctx.remote_reader:
        return

    ctx.pipe_event_queue = asyncio.Queue()
    ctx.pipe_reader_tasks = [
        asyncio.create_task(
            pipe_reader_task(ctx.client_reader, Endpoint.CLIENT, ctx.pipe_event_queue, cfg.buffer_size)
        ),
        asyncio.create_task(
            pipe_reader_task(ctx.remote_reader, Endpoint.REMOTE, ctx.pipe_event_queue, cfg.buffer_size)
        ),
    ]


def _cancel_idle_timer(ctx: IOContext):
    if ctx.idle_timer_handle is not None:
        ctx.idle_timer_handle.cancel()
        ctx.idle_timer_handle = None


def _reset_idle_timer(ctx: IOContext, timeout: float):
    _cancel_idle_timer(ctx)
    if ctx.pipe_event_queue is None or timeout <= 0:
        return
    loop = asyncio.get_event_loop()
    ctx.idle_timer_handle = loop.call_later(
        timeout,
        lambda: ctx.pipe_event_queue.put_nowait(PipeIdleTimeout(timeout)),
    )


async def _close_connection_now(ctx: IOContext):
    if ctx.closed:
        return
    ctx.closed = True
    _cancel_idle_timer(ctx)

    for t in ctx.pipe_reader_tasks:
        if not t.done():
            t.cancel()
    if ctx.pipe_reader_tasks:
        await asyncio.gather(*ctx.pipe_reader_tasks, return_exceptions=True)

    await safe_close(ctx.remote_writer)
    await safe_close(ctx.client_writer)


def _maybe_apply_backpressure_after_remote_write(ctx: IOContext, cfg: Config, n: int):
    rf = ctx.relay_flow
    rf.pending_to_remote += n
    if rf.pending_to_remote >= cfg.pipe_buffer_high_water and not rf.client_reading_paused:
        rf.client_reading_paused = True
        _pause_reader_if_possible(ctx.client_reader)


def _maybe_apply_backpressure_after_client_write(ctx: IOContext, cfg: Config, n: int):
    rf = ctx.relay_flow
    rf.pending_to_client += n
    if rf.pending_to_client >= cfg.pipe_buffer_high_water and not rf.remote_reading_paused:
        rf.remote_reading_paused = True
        _pause_reader_if_possible(ctx.remote_reader)


async def _flush_remote_and_maybe_resume(ctx: IOContext, cfg: Config):
    if not _is_writer_usable(ctx.remote_writer):
        raise RuntimeError("remote writer closed")
    await ctx.remote_writer.drain()
    rf = ctx.relay_flow
    rf.pending_to_remote = 0
    if rf.client_reading_paused and rf.pending_to_remote <= cfg.pipe_buffer_low_water:
        rf.client_reading_paused = False
        _resume_reader_if_possible(ctx.client_reader)


async def _flush_client_and_maybe_resume(ctx: IOContext, cfg: Config):
    if not _is_writer_usable(ctx.client_writer):
        raise RuntimeError("client writer closed")
    await ctx.client_writer.drain()
    rf = ctx.relay_flow
    rf.pending_to_client = 0
    if rf.remote_reading_paused and rf.pending_to_client <= cfg.pipe_buffer_low_water:
        rf.remote_reading_paused = False
        _resume_reader_if_possible(ctx.remote_reader)


# ============================================================================
# Effect Executor
# ============================================================================


async def execute_one_effect(
    eff: Effect,
    ctx: IOContext,
    cfg: Config,
    server_state: ServerState,
    log: logging.Logger,
    peer: tuple,
) -> List[Event]:
    if eff.type == EffectType.WRITE_CLIENT:
        if not _is_writer_usable(ctx.client_writer):
            return [SendFailed("client_write: writer closed")]
        try:
            payload = eff.data
            ctx.client_writer.write(payload)
            _maybe_apply_backpressure_after_client_write(ctx, cfg, len(payload))
            if ctx.relay_flow.pending_to_client >= cfg.drain_threshold:
                await _flush_client_and_maybe_resume(ctx, cfg)
            else:
                await ctx.client_writer.drain()
        except Exception as e:
            return [SendFailed(f"client_write: {e}")]
        return []

    elif eff.type == EffectType.WRITE_REMOTE:
        if not _is_writer_usable(ctx.remote_writer):
            return [SendFailed("remote_write: writer closed")]
        try:
            payload = eff.data
            ctx.remote_writer.write(payload)
            _maybe_apply_backpressure_after_remote_write(ctx, cfg, len(payload))
            if ctx.relay_flow.pending_to_remote >= cfg.drain_threshold:
                await _flush_remote_and_maybe_resume(ctx, cfg)
        except Exception as e:
            return [SendFailed(f"remote_write: {e}")]
        return []

    elif eff.type == EffectType.OPEN_OUTBOUND_STREAM:
        host, port = eff.data

        if cfg.log_connections:
            mode = "DIRECT" if cfg.local_only else "SSH"
            log.info(f"[{peer[0]}:{peer[1]}] -> {host}:{port} ({mode})")

        if cfg.local_only:
            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=cfg.connection_timeout
                )
                ctx.remote_reader, ctx.remote_writer = remote_reader, remote_writer
                return [OutboundStreamOpened()]
            except Exception as e:
                return [OutboundStreamOpenFailed(ConnectFailReason.OTHER, str(e))]
        else:
            acquired = await acquire_connection_with_retry(server_state.pool, timeout=cfg.pool_acquire_timeout)
            if acquired is None:
                server_state.stats.errors += 1
                return [OutboundStreamOpenFailed(ConnectFailReason.POOL_UNAVAILABLE, "no ssh connection available")]

            pool_idx, ssh_conn, pool_slot_id = acquired
            ctx.pool_idx, ctx.pool_slot_id = pool_idx, pool_slot_id
            try:
                remote_reader, remote_writer = await asyncio.wait_for(ssh_conn.open_connection(host, port), timeout=cfg.connection_timeout)
                ctx.remote_reader, ctx.remote_writer = remote_reader, remote_writer
                return [OutboundStreamOpened()]
            except Exception as e:
                server_state.stats.errors += 1
                return [OutboundStreamOpenFailed(ConnectFailReason.OTHER, str(e))]

    elif eff.type == EffectType.PIPE_WRITE_EOF:
        destination = eff.data
        try:
            if destination == Endpoint.REMOTE and _is_writer_usable(ctx.remote_writer):
                if hasattr(ctx.remote_writer, "can_write_eof"):
                    if ctx.remote_writer.can_write_eof():
                        ctx.remote_writer.write_eof()
                else:
                    ctx.remote_writer.write_eof()
            elif destination == Endpoint.CLIENT and _is_writer_usable(ctx.client_writer):
                if hasattr(ctx.client_writer, "can_write_eof"):
                    if ctx.client_writer.can_write_eof():
                        ctx.client_writer.write_eof()
                else:
                    ctx.client_writer.write_eof()
        except Exception:
            pass
        return []

    elif eff.type == EffectType.PIPE_CLOSE_BOTH:
        await _close_connection_now(ctx)
        return []

    elif eff.type == EffectType.START_PIPE_RUNTIME:
        await _start_pipe_runtime_if_needed(ctx, cfg)
        return []

    elif eff.type == EffectType.SET_DEADLINE:
        data = eff.data or {}
        if data.get("kind") == "idle":
            _reset_idle_timer(ctx, float(data.get("timeout", cfg.pipe_idle_timeout)))
        return []

    elif eff.type == EffectType.CLEAR_DEADLINE:
        data = eff.data or {}
        if data.get("kind") == "idle":
            _cancel_idle_timer(ctx)
        return []

    elif eff.type == EffectType.SESSION_DONE:
        await _close_connection_now(ctx)
        return []

    elif eff.type == EffectType.SESSION_FAILED:
        await _close_connection_now(ctx)
        return []

    elif eff.type == EffectType.TEST_LOG:
        success, msg = eff.data
        if success:
            log.info(f"✓ Test: {msg}")
        else:
            log.warning(f"✗ Test: {msg}")
        return []

    return []


# ============================================================================
# Pipe Reader Tasks
# ============================================================================


async def pipe_reader_task(reader, source: Endpoint, event_queue: asyncio.Queue, buf_size: int):
    try:
        while True:
            data = await reader.read(buf_size)
            if not data:
                await event_queue.put(PipeEOF(source))
                return
            await event_queue.put(
                PipeDataFromClient(data, len(data))
                if source == Endpoint.CLIENT
                else PipeDataFromRemote(data, len(data))
            )
    except asyncio.CancelledError:
        return
    except Exception as e:
        await event_queue.put(PipeError(source, str(e)))


# ============================================================================
# Unified Event-Driven Loop Helper
# ============================================================================


async def _drain_pending(
    pending_events: collections.deque,
    protocol_state: ProxyProtocolState,
    ctx: IOContext,
    cfg: Config,
    server_state: ServerState,
    log: logging.Logger,
    peer: tuple,
) -> ProxyProtocolState:
    while pending_events:
        event = pending_events.popleft()

        tr = proxy_protocol_reducer(
            protocol_state,
            event,
            cfg.max_handshake_buffer,
            cfg.pipe_idle_timeout,
        )
        protocol_state = tr.state

        for eff in tr.effects:
            new_events = await execute_one_effect(
                eff, ctx, cfg, server_state, log, peer
            )
            pending_events.extend(new_events)

    return protocol_state


async def client_read(reader):
    return await reader.read(4096)


async def _wait_for_next_event(
    protocol_state: ProxyProtocolState,
    ctx: IOContext,
    cfg: Config,
    log: logging.Logger,
    peer: tuple,
) -> Event:
    if protocol_state.phase in (
        Phase.INIT,
        Phase.SOCKS5_AUTH,
        Phase.SOCKS5_REQ,
        Phase.HTTP_REQ,
    ):
        try:
            data = await asyncio.wait_for(
                client_read(ctx.client_reader),
                timeout=cfg.handshake_timeout,
            )
            return ClientDataReceived(data) if data else ClientConnectionClosed()
        except asyncio.TimeoutError:
            if cfg.log_connections:
                log.debug(f"[{peer[0]}:{peer[1]}] Handshake timeout")
            return HandshakeTimeout(cfg.handshake_timeout)
        except Exception:
            return ClientConnectionClosed()

    if protocol_state.phase == Phase.CONNECTING:
        await asyncio.sleep(0)
        return ClientConnectionClosed()

    if protocol_state.phase == Phase.PIPING:
        if ctx.pipe_event_queue is None:
            return ClientConnectionClosed()
        try:
            return await ctx.pipe_event_queue.get()
        except asyncio.CancelledError:
            return ClientConnectionClosed()

    return ClientConnectionClosed()


# ============================================================================
# Client Handler
# ============================================================================


async def handle_client(
    cfg: Config,
    server_state: ServerState,
    log: logging.Logger,
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
):
    stats = server_state.stats
    peer = client_writer.get_extra_info("peername", ("?", 0))

    protocol_state = ProxyProtocolState(proxy_mode=cfg.proxy_mode)
    ctx = IOContext(
        client_writer=client_writer,
        client_reader=client_reader,
    )
    pending_events: collections.deque = collections.deque()
    last_ps_sent = 0
    last_ps_recv = 0

    def sync_stats_from_protocol_state(ps: ProxyProtocolState):
        nonlocal last_ps_sent, last_ps_recv
        delta_sent = max(0, ps.bytes_sent - last_ps_sent)
        delta_recv = max(0, ps.bytes_received - last_ps_recv)
        if delta_sent:
            stats.bytes_sent += delta_sent
            last_ps_sent = ps.bytes_sent
        if delta_recv:
            stats.bytes_received += delta_recv
            last_ps_recv = ps.bytes_received

    try:
        stats.active += 1
        stats.total += 1
        if stats.active > stats.peak:
            stats.peak = stats.active

        pending_events.append(SessionStarted())
        protocol_state = await _drain_pending(
            pending_events, protocol_state, ctx, cfg, server_state, log, peer
        )
        sync_stats_from_protocol_state(protocol_state)

        while not ctx.closed and protocol_state.phase != Phase.CLOSED:
            if pending_events:
                protocol_state = await _drain_pending(
                    pending_events, protocol_state, ctx, cfg, server_state, log, peer
                )
                sync_stats_from_protocol_state(protocol_state)
                continue

            event = await _wait_for_next_event(protocol_state, ctx, cfg, log, peer)
            pending_events.append(event)

            protocol_state = await _drain_pending(
                pending_events, protocol_state, ctx, cfg, server_state, log, peer
            )
            sync_stats_from_protocol_state(protocol_state)

    except asyncio.CancelledError:
        pass
    except Exception as e:
        if cfg.log_connections:
            log.debug(f"Client error: {e}")
        stats.errors += 1
    finally:
        _cancel_idle_timer(ctx)

        for t in ctx.pipe_reader_tasks:
            if not t.done():
                t.cancel()
        if ctx.pipe_reader_tasks:
            await asyncio.gather(*ctx.pipe_reader_tasks, return_exceptions=True)

        await safe_close(ctx.remote_writer)
        await safe_close(client_writer)
        if ctx.pool_idx is not None and ctx.pool_slot_id is not None:
            await release_connection(server_state.pool, ctx.pool_idx, ctx.pool_slot_id)
        stats.active = max(0, stats.active - 1)


async def client_wrapper(
    cfg: Config,
    state: ServerState,
    log: logging.Logger,
    r: asyncio.StreamReader,
    w: asyncio.StreamWriter,
):
    task = asyncio.current_task()
    state.active_tasks.add(task)
    try:
        await handle_client(cfg, state, log, r, w)
    finally:
        state.active_tasks.discard(task)


# ============================================================================
# Runtime unit tests
# ============================================================================


class _FakeTransport:
    def __init__(self):
        self.paused = False
        self.pause_calls = 0
        self.resume_calls = 0
        self.closing = False

    def pause_reading(self):
        self.paused = True
        self.pause_calls += 1

    def resume_reading(self):
        self.paused = False
        self.resume_calls += 1

    def is_closing(self):
        return self.closing


class _FakeReader:
    def __init__(self):
        self._transport = _FakeTransport()


class _FakeWriter:
    def __init__(self, usable=True, can_eof=True):
        self.buffer = []
        self.drain_calls = 0
        self.closed = False
        self.wait_closed_calls = 0
        self.write_eof_calls = 0
        self._transport = _FakeTransport()
        self._session = object() if usable else None
        self._can_eof = can_eof

    def is_closing(self):
        return self.closed

    def write(self, data):
        if self.closed:
            raise RuntimeError("writer closed")
        self.buffer.append(data)

    async def drain(self):
        if self.closed:
            raise RuntimeError("writer closed on drain")
        self.drain_calls += 1

    def close(self):
        self.closed = True

    async def wait_closed(self):
        self.wait_closed_calls += 1

    def can_write_eof(self):
        return self._can_eof

    def write_eof(self):
        self.write_eof_calls += 1


async def _run_runtime_tests_async():
    print("\nRunning runtime adapter tests...")
    passed = 0
    failed = 0

    def check(name, condition):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"  ✓ {name}")
        else:
            failed += 1
            print(f"  ✗ {name}")

    cfg = Config(
        proxy_mode=ProxyMode.BOTH,
        pipe_buffer_high_water=100,
        pipe_buffer_low_water=50,
        drain_threshold=120,
        pipe_idle_timeout=33.0,
    )

    # ------------------------------------------------------------------
    # backpressure helper tests
    # ------------------------------------------------------------------

    ctx1 = IOContext(client_reader=_FakeReader(), remote_reader=_FakeReader())
    _maybe_apply_backpressure_after_remote_write(ctx1, cfg, 30)
    check("Runtime BP remote write: below high water no pause", ctx1.relay_flow.client_reading_paused is False)
    _maybe_apply_backpressure_after_remote_write(ctx1, cfg, 80)
    check("Runtime BP remote write: pause client at high water", ctx1.relay_flow.client_reading_paused is True)
    check("Runtime BP remote write: client transport paused", ctx1.client_reader._transport.pause_calls == 1)

    ctx2 = IOContext(client_reader=_FakeReader(), remote_reader=_FakeReader())
    _maybe_apply_backpressure_after_client_write(ctx2, cfg, 120)
    check("Runtime BP client write: pause remote at high water", ctx2.relay_flow.remote_reading_paused is True)
    check("Runtime BP client write: remote transport paused", ctx2.remote_reader._transport.pause_calls == 1)

    ctx3 = IOContext(
        client_reader=_FakeReader(),
        remote_reader=_FakeReader(),
        remote_writer=_FakeWriter(),
        relay_flow=RelayFlowState(
            pending_to_remote=150,
            client_reading_paused=True,
        ),
    )
    await _flush_remote_and_maybe_resume(ctx3, cfg)
    check("Flush remote resets pending_to_remote", ctx3.relay_flow.pending_to_remote == 0)
    check("Flush remote resumes client reading", ctx3.relay_flow.client_reading_paused is False)
    check("Flush remote transport resumed", ctx3.client_reader._transport.resume_calls == 1)

    ctx4 = IOContext(
        client_reader=_FakeReader(),
        remote_reader=_FakeReader(),
        client_writer=_FakeWriter(),
        relay_flow=RelayFlowState(
            pending_to_client=160,
            remote_reading_paused=True,
        ),
    )
    await _flush_client_and_maybe_resume(ctx4, cfg)
    check("Flush client resets pending_to_client", ctx4.relay_flow.pending_to_client == 0)
    check("Flush client resumes remote reading", ctx4.relay_flow.remote_reading_paused is False)
    check("Flush client transport resumed", ctx4.remote_reader._transport.resume_calls == 1)

    # ------------------------------------------------------------------
    # execute_one_effect tests
    # ------------------------------------------------------------------

    log = logging.getLogger("SSHProxy.test.runtime")
    server_state = ServerState(pool=init_pool_state(0))
    peer = ("127.0.0.1", 12345)

    ctx5 = IOContext(
        client_writer=_FakeWriter(),
        client_reader=_FakeReader(),
        remote_reader=_FakeReader(),
    )
    eff5 = write_client(b"x" * 110)
    evs5 = await execute_one_effect(eff5, ctx5, cfg, server_state, log, peer)
    check("execute WRITE_CLIENT emits no events on success", evs5 == [])
    check("execute WRITE_CLIENT writes payload", ctx5.client_writer.buffer == [b"x" * 110])
    check("execute WRITE_CLIENT applies remote-side backpressure pause", ctx5.relay_flow.remote_reading_paused is True)

    ctx6 = IOContext(
        remote_writer=_FakeWriter(),
        client_reader=_FakeReader(),
        remote_reader=_FakeReader(),
    )
    eff6 = write_remote(b"y" * 110)
    evs6 = await execute_one_effect(eff6, ctx6, cfg, server_state, log, peer)
    check("execute WRITE_REMOTE emits no events on success", evs6 == [])
    check("execute WRITE_REMOTE writes payload", ctx6.remote_writer.buffer == [b"y" * 110])
    check("execute WRITE_REMOTE applies client-side backpressure pause", ctx6.relay_flow.client_reading_paused is True)

    ctx7 = IOContext(
        remote_writer=_FakeWriter(),
        client_reader=_FakeReader(),
        remote_reader=_FakeReader(),
    )
    eff7 = write_remote(b"z" * 130)
    evs7 = await execute_one_effect(eff7, ctx7, cfg, server_state, log, peer)
    check("execute WRITE_REMOTE over drain_threshold flushes", evs7 == [])
    check("execute WRITE_REMOTE flush drain called", ctx7.remote_writer.drain_calls == 1)
    check("execute WRITE_REMOTE flush resumes client reading", ctx7.relay_flow.client_reading_paused is False)

    ctx8 = IOContext(
        client_writer=_FakeWriter(),
        client_reader=_FakeReader(),
        remote_reader=_FakeReader(),
    )
    eff8 = write_client(b"k" * 130)
    evs8 = await execute_one_effect(eff8, ctx8, cfg, server_state, log, peer)
    check("execute WRITE_CLIENT over drain_threshold flushes", evs8 == [])
    check("execute WRITE_CLIENT flush drain called", ctx8.client_writer.drain_calls == 1)
    check("execute WRITE_CLIENT flush resumes remote reading", ctx8.relay_flow.remote_reading_paused is False)

    ctx9 = IOContext(client_writer=None)
    evs9 = await execute_one_effect(write_client(b"a"), ctx9, cfg, server_state, log, peer)
    check(
        "execute WRITE_CLIENT closed writer -> SendFailed",
        len(evs9) == 1 and isinstance(evs9[0], SendFailed),
    )

    ctx10 = IOContext(remote_writer=None)
    evs10 = await execute_one_effect(write_remote(b"a"), ctx10, cfg, server_state, log, peer)
    check(
        "execute WRITE_REMOTE closed writer -> SendFailed",
        len(evs10) == 1 and isinstance(evs10[0], SendFailed),
    )

    ctx11 = IOContext(pipe_event_queue=asyncio.Queue())
    evs11 = await execute_one_effect(set_deadline("idle", 9.5), ctx11, cfg, server_state, log, peer)
    check("execute SET_DEADLINE no events", evs11 == [])
    check("execute SET_DEADLINE installs timer", ctx11.idle_timer_handle is not None)
    await execute_one_effect(clear_deadline("idle"), ctx11, cfg, server_state, log, peer)
    check("execute CLEAR_DEADLINE clears timer", ctx11.idle_timer_handle is None)

    ctx12 = IOContext(
        client_writer=_FakeWriter(),
        remote_writer=_FakeWriter(),
    )
    await execute_one_effect(pipe_write_eof(Endpoint.CLIENT), ctx12, cfg, server_state, log, peer)
    await execute_one_effect(pipe_write_eof(Endpoint.REMOTE), ctx12, cfg, server_state, log, peer)
    check("execute PIPE_WRITE_EOF client", ctx12.client_writer.write_eof_calls == 1)
    check("execute PIPE_WRITE_EOF remote", ctx12.remote_writer.write_eof_calls == 1)

    ctx13 = IOContext(
        client_writer=_FakeWriter(),
        remote_writer=_FakeWriter(),
    )
    await execute_one_effect(session_done("ok"), ctx13, cfg, server_state, log, peer)
    check("execute SESSION_DONE closes ctx", ctx13.closed is True)

    # ------------------------------------------------------------------
    # runtime backpressure behavior tests
    # ------------------------------------------------------------------

    ctx14 = IOContext(
        remote_writer=_FakeWriter(),
        client_reader=_FakeReader(),
        remote_reader=_FakeReader(),
    )
    await execute_one_effect(write_remote(b"a" * 60), ctx14, cfg, server_state, log, peer)
    await execute_one_effect(write_remote(b"b" * 60), ctx14, cfg, server_state, log, peer)
    check(
        "Runtime BP sequence: client paused after cumulative remote writes",
        ctx14.client_reader._transport.pause_calls == 1,
    )

    ctx15 = IOContext(
        remote_writer=_FakeWriter(),
        client_reader=_FakeReader(),
        remote_reader=_FakeReader(),
        relay_flow=RelayFlowState(
            pending_to_remote=0,
            client_reading_paused=False,
        ),
    )
    await execute_one_effect(write_remote(b"x" * 30), ctx15, cfg, server_state, log, peer)
    await execute_one_effect(write_remote(b"x" * 30), ctx15, cfg, server_state, log, peer)
    await execute_one_effect(write_remote(b"x" * 30), ctx15, cfg, server_state, log, peer)
    await execute_one_effect(write_remote(b"x" * 30), ctx15, cfg, server_state, log, peer)
    check(
        "Runtime BP threshold crossing pauses exactly once",
        ctx15.client_reader._transport.pause_calls == 1,
    )

    ctx16 = IOContext(
        remote_writer=_FakeWriter(),
        client_reader=_FakeReader(),
        remote_reader=_FakeReader(),
    )
    await execute_one_effect(write_remote(b"x" * 130), ctx16, cfg, server_state, log, peer)
    check(
        "Runtime BP flush path resumes after pause",
        ctx16.client_reader._transport.resume_calls == 1,
    )

    ctx17 = IOContext(
        client_writer=_FakeWriter(),
        client_reader=_FakeReader(),
        remote_reader=_FakeReader(),
    )
    await execute_one_effect(write_client(b"x" * 130), ctx17, cfg, server_state, log, peer)
    check(
        "Runtime BP client flush path resumes remote reader",
        ctx17.remote_reader._transport.resume_calls == 1,
    )

    print(f"\nRuntime test results: {passed} passed, {failed} failed")
    return failed == 0


def _run_runtime_tests():
    return asyncio.run(_run_runtime_tests_async())


# ============================================================================
# Benchmarks
# ============================================================================


def _bench_print_rate(name: str, count: int, dt: float, unit: str = "ev/s"):
    rate = (count / dt) if dt > 0 else 0.0
    print(f"  {name}: {count} in {dt:.4f}s = {rate:.1f} {unit}")


def _run_core_benchmarks():
    print("\nRunning core benchmarks...")

    iterations = 100000
    payload = b"x" * 4096

    s = ProxyProtocolState(
        phase=Phase.PIPING,
        pipe_stage=PipeStage.FLOWING,
        target_host="example.com",
        target_port=80,
    )

    t0 = time.perf_counter()
    total_effects = 0
    for _ in range(iterations):
        tr = proxy_protocol_reducer(
            s,
            PipeDataFromClient(payload, len(payload)),
            pipe_idle_timeout=300.0,
        )
        s = tr.state
        total_effects += len(tr.effects)
    dt = time.perf_counter() - t0
    _bench_print_rate("pipe c->r", iterations, dt)
    print(f"    bytes_sent={s.bytes_sent} effects={total_effects}")

    iterations2 = 100000
    payload_a = b"a" * 1024
    payload_b = b"b" * 1024

    s2 = ProxyProtocolState(
        phase=Phase.PIPING,
        pipe_stage=PipeStage.FLOWING,
        target_host="example.com",
        target_port=80,
    )

    t0 = time.perf_counter()
    total_effects2 = 0
    for i in range(iterations2):
        ev = (
            PipeDataFromClient(payload_a, len(payload_a))
            if (i % 2 == 0)
            else PipeDataFromRemote(payload_b, len(payload_b))
        )
        tr = proxy_protocol_reducer(
            s2,
            ev,
            pipe_idle_timeout=300.0,
        )
        s2 = tr.state
        total_effects2 += len(tr.effects)
    dt = time.perf_counter() - t0
    _bench_print_rate("pipe alternating", iterations2, dt)
    print(
        f"    bytes_sent={s2.bytes_sent} "
        f"bytes_received={s2.bytes_received} "
        f"effects={total_effects2}"
    )

    sessions = 10000
    auth = b"\x05\x01\x00"
    req = b"\x05\x01\x00\x03\x0bexample.com\x00\x50"
    pipe_data = b"hello-through-proxy"

    t0 = time.perf_counter()
    total_effects3 = 0
    for _ in range(sessions):
        s3 = ProxyProtocolState(proxy_mode=ProxyMode.SOCKS5)

        tr = proxy_protocol_reducer(s3, SessionStarted())
        s3 = tr.state
        total_effects3 += len(tr.effects)

        tr = proxy_protocol_reducer(s3, ClientDataReceived(auth))
        s3 = tr.state
        total_effects3 += len(tr.effects)

        tr = proxy_protocol_reducer(s3, ClientDataReceived(req))
        s3 = tr.state
        total_effects3 += len(tr.effects)

        tr = proxy_protocol_reducer(s3, OutboundStreamOpened())
        s3 = tr.state
        total_effects3 += len(tr.effects)

        tr = proxy_protocol_reducer(
            s3,
            PipeDataFromClient(pipe_data, len(pipe_data)),
        )
        s3 = tr.state
        total_effects3 += len(tr.effects)

        tr = proxy_protocol_reducer(s3, PipeEOF(Endpoint.CLIENT))
        s3 = tr.state
        total_effects3 += len(tr.effects)

        tr = proxy_protocol_reducer(s3, PipeEOF(Endpoint.REMOTE))
        s3 = tr.state
        total_effects3 += len(tr.effects)

    dt = time.perf_counter() - t0
    _bench_print_rate("socks5 lifecycle", sessions, dt, "sess/s")
    print(f"    total_effects={total_effects3}")

    http_n = 20000
    req_http = (
        b"GET http://example.com/path/to/resource?q=1&x=2 HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"Proxy-Connection: keep-alive\r\n"
        b"Connection: keep-alive\r\n"
        b"User-Agent: bench\r\n"
        b"\r\n"
    )

    t0 = time.perf_counter()
    total_effects4 = 0
    last_state = None
    for _ in range(http_n):
        s4 = ProxyProtocolState(proxy_mode=ProxyMode.HTTP)
        tr = proxy_protocol_reducer(s4, ClientDataReceived(req_http))
        last_state = tr.state
        total_effects4 += len(tr.effects)
    dt = time.perf_counter() - t0
    _bench_print_rate("http rewrite", http_n, dt, "req/s")
    if last_state is not None:
        print(
            f"    last_target={last_state.target_host}:{last_state.target_port} "
            f"rewritten={len(last_state.http_rewritten_headers)}B "
            f"effects={total_effects4}"
        )


async def _run_runtime_benchmarks_async():
    print("\nRunning runtime benchmarks...")

    log = logging.getLogger("SSHProxy.bench.runtime")
    server_state = ServerState(pool=init_pool_state(0))
    peer = ("127.0.0.1", 9999)

    cfg_no_flush = Config(
        proxy_mode=ProxyMode.BOTH,
        pipe_buffer_high_water=1 << 30,
        pipe_buffer_low_water=1 << 29,
        drain_threshold=1 << 30,
        pipe_idle_timeout=300.0,
    )

    cfg_flush = Config(
        proxy_mode=ProxyMode.BOTH,
        pipe_buffer_high_water=64 * 1024,
        pipe_buffer_low_water=16 * 1024,
        drain_threshold=32 * 1024,
        pipe_idle_timeout=300.0,
    )

    n1 = 50000
    payload1 = b"x" * 4096
    ctx1 = IOContext(
        remote_writer=_FakeWriter(),
        client_reader=_FakeReader(),
        remote_reader=_FakeReader(),
    )

    t0 = time.perf_counter()
    generated_events = 0
    for _ in range(n1):
        evs = await execute_one_effect(
            write_remote(payload1), ctx1, cfg_no_flush, server_state, log, peer
        )
        generated_events += len(evs)
    dt = time.perf_counter() - t0
    _bench_print_rate("WRITE_REMOTE no-flush", n1, dt)
    print(
        f"    writes={len(ctx1.remote_writer.buffer)} "
        f"drain_calls={ctx1.remote_writer.drain_calls} "
        f"pause_calls={ctx1.client_reader._transport.pause_calls} "
        f"events={generated_events}"
    )

    n2 = 20000
    payload2 = b"y" * 4096
    ctx2 = IOContext(
        remote_writer=_FakeWriter(),
        client_reader=_FakeReader(),
        remote_reader=_FakeReader(),
    )

    t0 = time.perf_counter()
    generated_events2 = 0
    for _ in range(n2):
        evs = await execute_one_effect(
            write_remote(payload2), ctx2, cfg_flush, server_state, log, peer
        )
        generated_events2 += len(evs)
    dt = time.perf_counter() - t0
    _bench_print_rate("WRITE_REMOTE flush-heavy", n2, dt)
    print(
        f"    writes={len(ctx2.remote_writer.buffer)} "
        f"drain_calls={ctx2.remote_writer.drain_calls} "
        f"pause_calls={ctx2.client_reader._transport.pause_calls} "
        f"resume_calls={ctx2.client_reader._transport.resume_calls} "
        f"events={generated_events2}"
    )

    n3 = 20000
    payload3 = b"z" * 4096
    ctx3 = IOContext(
        client_writer=_FakeWriter(),
        client_reader=_FakeReader(),
        remote_reader=_FakeReader(),
    )

    t0 = time.perf_counter()
    generated_events3 = 0
    for _ in range(n3):
        evs = await execute_one_effect(
            write_client(payload3), ctx3, cfg_flush, server_state, log, peer
        )
        generated_events3 += len(evs)
    dt = time.perf_counter() - t0
    _bench_print_rate("WRITE_CLIENT flush-heavy", n3, dt)
    print(
        f"    writes={len(ctx3.client_writer.buffer)} "
        f"drain_calls={ctx3.client_writer.drain_calls} "
        f"pause_calls={ctx3.remote_reader._transport.pause_calls} "
        f"resume_calls={ctx3.remote_reader._transport.resume_calls} "
        f"events={generated_events3}"
    )

    n4 = 50000
    ctx4 = IOContext(pipe_event_queue=asyncio.Queue())

    t0 = time.perf_counter()
    for _ in range(n4):
        await execute_one_effect(
            set_deadline("idle", 30.0), ctx4, cfg_no_flush, server_state, log, peer
        )
    dt = time.perf_counter() - t0
    _bench_print_rate("SET_DEADLINE reset", n4, dt)
    print(f"    timer_installed={ctx4.idle_timer_handle is not None}")

    await execute_one_effect(
        clear_deadline("idle"), ctx4, cfg_no_flush, server_state, log, peer
    )

    n5 = 20000
    cfg_osc = Config(
        proxy_mode=ProxyMode.BOTH,
        pipe_buffer_high_water=100,
        pipe_buffer_low_water=50,
        drain_threshold=10_000_000,
        pipe_idle_timeout=300.0,
    )
    ctx5 = IOContext(
        remote_writer=_FakeWriter(),
        client_reader=_FakeReader(),
        remote_reader=_FakeReader(),
    )

    pattern = (55, 10, 55, 10, 55, 10)

    t0 = time.perf_counter()
    for i in range(n5):
        size = pattern[i % len(pattern)]
        await execute_one_effect(
            write_remote(b"a" * size), ctx5, cfg_osc, server_state, log, peer
        )
        if ctx5.relay_flow.pending_to_remote > 80:
            await _flush_remote_and_maybe_resume(ctx5, cfg_osc)
    dt = time.perf_counter() - t0
    _bench_print_rate("backpressure oscillation", n5, dt)
    print(
        f"    pause_calls={ctx5.client_reader._transport.pause_calls} "
        f"resume_calls={ctx5.client_reader._transport.resume_calls} "
        f"pending_to_remote={ctx5.relay_flow.pending_to_remote}"
    )


def _run_runtime_benchmarks():
    return asyncio.run(_run_runtime_benchmarks_async())


# ============================================================================
# Test / periodic / shutdown
# ============================================================================


async def run_proxy_test(cfg: Config, log: logging.Logger):
    await asyncio.sleep(1.5)
    log.info(f"  Testing proxy with: {cfg.test_url}")

    writer = None
    try:
        connect_host = "127.0.0.1" if cfg.local_host == "0.0.0.0" else cfg.local_host
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(connect_host, cfg.local_port),
            timeout=5.0,
        )

        p = urlparse(cfg.test_url)
        t_state = TestClientState(
            proxy_mode=cfg.proxy_mode,
            test_host=p.hostname or "",
            test_port=p.port or (443 if p.scheme == "https" else 80),
            test_path=p.path or "/",
            test_url_raw=cfg.test_url,
            is_https=(p.scheme == "https"),
        )

        async def exec_test_cmds(cmds: List[Effect]) -> bool:
            for cmd in cmds:
                if cmd.type == EffectType.WRITE_CLIENT:
                    writer.write(cmd.data)
                    await writer.drain()
                elif cmd.type in (EffectType.SESSION_DONE, EffectType.SESSION_FAILED):
                    return True
                elif cmd.type == EffectType.TEST_LOG:
                    success, msg = cmd.data
                    if success:
                        log.info(f"✓ Test: {msg}")
                    else:
                        log.warning(f"✗ Test: {msg}")
            return False

        t_state, cmds = test_client_reducer(t_state, TestStart())
        if await exec_test_cmds(cmds):
            return

        while t_state.stage not in (TestStage.SUCCESS, TestStage.FAILED):
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=10.0)
            except Exception:
                data = b""

            ev = ClientDataReceived(data) if data else ClientConnectionClosed()
            t_state, cmds = test_client_reducer(t_state, ev)
            if await exec_test_cmds(cmds):
                break

    except Exception as e:
        log.warning(f"✗ Test failed: {e}")
    finally:
        await safe_close(writer)


async def periodic_stats(state: ServerState, log: logging.Logger):
    last_sent = state.stats.bytes_sent
    last_recv = state.stats.bytes_received
    last_time = time.monotonic()

    try:
        while True:
            await asyncio.sleep(10)
            now = time.monotonic()
            curr_sent = state.stats.bytes_sent
            curr_recv = state.stats.bytes_received
            dt = max(0.001, now - last_time)

            up_speed = max(0.0, (curr_sent - last_sent) / dt)
            down_speed = max(0.0, (curr_recv - last_recv) / dt)

            last_sent, last_recv, last_time = curr_sent, curr_recv, now

            speed_str = (
                f"Speed: ↑{format_bytes(int(up_speed))}/s "
                f"↓{format_bytes(int(down_speed))}/s"
            )
            log.info(
                f"[\033[35mStats\033[0m] {stats_summary(state.stats)} | "
                f"\033[33m{speed_str}\033[0m | "
                f"\033[35mPool\033[0m: {pool_status_str(state.pool)}"
            )
    except asyncio.CancelledError:
        pass


async def graceful_shutdown(cfg: Config, state: ServerState, log: logging.Logger):
    if state.server:
        state.server.close()
        try:
            await asyncio.wait_for(state.server.wait_closed(), timeout=2.0)
        except asyncio.TimeoutError:
            pass

    if state.active_tasks:
        log.info(f"Waiting for {len(state.active_tasks)} active connections...")
        done, pending = await asyncio.wait(state.active_tasks, timeout=cfg.shutdown_timeout)
        if pending:
            log.warning(f"Force-cancelling {len(pending)} connections")
            for t in pending:
                t.cancel()
            await asyncio.wait(pending, timeout=3.0)

    await close_pool(state.pool)
    log.info(f"Final: {stats_summary(state.stats)}\n✓ Proxy server shut down")


# ============================================================================
# Main server
# ============================================================================


async def run_server(cfg: Config):
    log = logging.getLogger("SSHProxy")
    log.setLevel(getattr(logging, cfg.log_level.upper(), logging.INFO))

    if not log.handlers:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(
            ColorFormatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%H:%M:%S",
            )
        )
        log.addHandler(h)

    log.info(
        f"\033[96m{'=' * 60}\033[0m\n"
        f"\033[92mSSH Proxy Server (Sans-I/O v7 — stricter core/runtime split)\033[0m\n"
        f"\033[96m{'=' * 60}\033[0m"
    )

    errors = validate_config(cfg)
    if errors:
        for e in errors:
            log.error(f"Config error: {e}")
        return

    state = ServerState(pool=init_pool_state(cfg.pool_size))
    if not cfg.local_only:
        await init_pool(cfg, state.pool, log)
    else:
        log.info("Running in DIRECT mode (no SSH tunnel)")


    try:
        state.server = await asyncio.start_server(
            lambda r, w: client_wrapper(cfg, state, log, r, w),
            host=cfg.local_host,
            port=cfg.local_port,
        )
    except OSError as e:
        log.error(f"Cannot bind {cfg.local_host}:{cfg.local_port}: {e}")
        await close_pool(state.pool)
        return

    log.info(
        f"✓ Listening on \033[96m{cfg.local_host}:{cfg.local_port}\033[0m "
        f"[\033[33m{cfg.proxy_mode.name}\033[0m]"
    )

    if sys.platform != "win32":
        loop = asyncio.get_event_loop()
        for sig_name in ("SIGINT", "SIGTERM"):
            sig = getattr(signal, sig_name, None)
            if sig:
                try:
                    loop.add_signal_handler(sig, lambda: state.shutdown_event.set())
                except NotImplementedError:
                    pass

    tasks = [asyncio.create_task(periodic_stats(state, log))]
    if cfg.auto_test:
        tasks.append(asyncio.create_task(run_proxy_test(cfg, log)))

    try:
        if sys.platform == "win32":
            while not state.shutdown_event.is_set():
                await asyncio.sleep(0.5)
        else:
            await state.shutdown_event.wait()
    except (asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        for t in tasks:
            t.cancel()
        log.info("Graceful shutdown initiated...")
        await graceful_shutdown(cfg, state, log)


def parse_args() -> Config:
    p = argparse.ArgumentParser(description="SSH Tunnel Proxy (Sans-I/O v7)")

    g = p.add_argument_group("SSH")
    g.add_argument("-H", "--ssh-host", required=True)
    g.add_argument("-P", "--ssh-port", type=int, default=22)
    g.add_argument("-u", "--username", "--ssh-user", dest="username", required=True)
    g.add_argument("-p", "--password", default="")
    g.add_argument("-k", "--key-path", "--ssh-key", dest="key_path", default="")
    g.add_argument("--key-passphrase", default="")
    g.add_argument("--known-hosts", default=None)

    g = p.add_argument_group("Proxy")
    g.add_argument("--host", "--local-host", dest="host", default="127.0.0.1")
    g.add_argument("--port", "--local-port", dest="port", type=int, default=1080)
    p.add_argument("--local", action="store_true", help="Direct connection mode (no SSH)")
    g.add_argument("--mode", choices=["socks5", "http", "both"], default="both")

    g = p.add_argument_group("Pool")
    g.add_argument("--pool-size", type=int, default=3)
    g.add_argument("--max-retries", type=int, default=3)
    g.add_argument("--retry-delay", type=float, default=2.0)
    g.add_argument("--keepalive", type=float, default=30.0)
    g.add_argument("--timeout", type=float, default=10.0)
    g.add_argument("--pool-acquire-timeout", type=float, default=5.0)

    g = p.add_argument_group("Performance")
    g.add_argument("--buffer-size", type=int, default=65536)
    g.add_argument("--drain-threshold", type=int, default=262144)
    g.add_argument("--max-handshake-buffer", type=int, default=8192)
    g.add_argument("--handshake-timeout", type=float, default=10.0)
    g.add_argument("--pipe-idle-timeout", type=float, default=300.0)
    g.add_argument("--pipe-buffer-high-water", type=int, default=1048576)
    g.add_argument("--pipe-buffer-low-water", type=int, default=262144)

    g = p.add_argument_group("Misc")
    g.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    g.add_argument("--no-log-connections", action="store_true")
    g.add_argument("--test-url", default="http://httpbin.org/ip")
    g.add_argument("--no-test", action="store_true")
    g.add_argument("--shutdown-timeout", type=float, default=10.0)

    a = p.parse_args()

    mode_map = {
        "socks5": ProxyMode.SOCKS5,
        "http": ProxyMode.HTTP,
        "both": ProxyMode.BOTH,
    }

    return Config(
        ssh_host=a.ssh_host,
        local_only=a.local,
        ssh_port=a.ssh_port,
        ssh_username=a.username,
        ssh_password=a.password,
        ssh_key_path=(os.path.normpath(os.path.expanduser(a.key_path)) if a.key_path else ""),
        ssh_key_passphrase=a.key_passphrase,
        known_hosts=a.known_hosts,
        local_host=a.host,
        local_port=a.port,
        proxy_mode=mode_map[a.mode],
        pool_size=a.pool_size,
        max_retries=a.max_retries,
        retry_delay=a.retry_delay,
        keepalive_interval=a.keepalive,
        connection_timeout=a.timeout,
        pool_acquire_timeout=a.pool_acquire_timeout,
        buffer_size=a.buffer_size,
        drain_threshold=a.drain_threshold,
        max_handshake_buffer=a.max_handshake_buffer,
        handshake_timeout=a.handshake_timeout,
        pipe_idle_timeout=a.pipe_idle_timeout,
        pipe_buffer_high_water=a.pipe_buffer_high_water,
        pipe_buffer_low_water=a.pipe_buffer_low_water,
        log_connections=not a.no_log_connections,
        log_level=a.log_level,
        test_url=a.test_url,
        auto_test=not a.no_test,
        shutdown_timeout=a.shutdown_timeout,
    )


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        ok1 = _run_protocol_tests()
        ok2 = _run_runtime_tests()

        try:
            _run_core_benchmarks()
            _run_runtime_benchmarks()
        except Exception:
            traceback.print_exc(file=sys.stderr)
            sys.exit(1)

        sys.exit(0 if (ok1 and ok2) else 1)

    try:
        asyncio.run(run_server(parse_args()))
    except KeyboardInterrupt:
        print(
            "\n\033[92m✓\033[0m \033[36mShutting down gracefully...\033[0m",
            file=sys.stderr,
        )
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
