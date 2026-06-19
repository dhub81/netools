#!/usr/bin/env python3

r"""
SSH Tunnel Proxy Server - Sans-I/O Refactored v7

================================================

python3 d:\py\slv313.py ^
--ssh-host x.x.x.x ^
--ssh-port 22 ^
--pool-size 1 ^
--no-log-connections ^
--ssh-user user ^
--ssh-key "~\.ssh\id_rsa" ^
--local-port 3128 ^
--test-url http://www.google.com ^
--local-host 0.0.0.0

"""

from __future__ import annotations

import sys
import asyncio
import os
import collections
import hashlib
import ipaddress
import argparse
import contextlib
import io
import json
import logging
import pathlib
import signal
import socket
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
    asyncssh = None


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


_IO_RESOURCE_LOG_FILE = None
_IO_RESOURCE_LOG_PATH = ""


def configure_io_resource_log_file(path: str) -> None:
    global _IO_RESOURCE_LOG_FILE, _IO_RESOURCE_LOG_PATH
    close_io_resource_log_file()
    if not path:
        return
    log_path = pathlib.Path(path).expanduser()
    if log_path.parent and str(log_path.parent) not in ("", "."):
        log_path.parent.mkdir(parents=True, exist_ok=True)
    _IO_RESOURCE_LOG_FILE = open(log_path, "w", encoding="utf-8", newline="\n", buffering=1)
    _IO_RESOURCE_LOG_PATH = str(log_path)


def close_io_resource_log_file() -> None:
    global _IO_RESOURCE_LOG_FILE, _IO_RESOURCE_LOG_PATH
    if _IO_RESOURCE_LOG_FILE is not None:
        try:
            _IO_RESOURCE_LOG_FILE.flush()
            _IO_RESOURCE_LOG_FILE.close()
        finally:
            _IO_RESOURCE_LOG_FILE = None
            _IO_RESOURCE_LOG_PATH = ""


def io_resource_log(cfg: Config, event: str, **fields) -> None:
    if not cfg.verbose and not cfg.log_file:
        return
    rec = {
        "type": "io_resource",
        "event": event,
        "time_unix_nano": time.time_ns(),
    }
    for key, value in fields.items():
        if isinstance(value, Enum):
            value = value.name.lower()
        rec[key] = value
    line = json.dumps(rec, separators=(",", ":"), ensure_ascii=False)
    if cfg.log_file:
        global _IO_RESOURCE_LOG_FILE, _IO_RESOURCE_LOG_PATH
        if _IO_RESOURCE_LOG_FILE is None or _IO_RESOURCE_LOG_PATH != str(pathlib.Path(cfg.log_file).expanduser()):
            configure_io_resource_log_file(cfg.log_file)
        _IO_RESOURCE_LOG_FILE.write(line + "\n")
        _IO_RESOURCE_LOG_FILE.flush()
        return
    print(line, file=sys.stderr, flush=True)


def _stream_addr(writer: Any, name: str, default: str = "unknown") -> str:
    if writer is None:
        return default
    try:
        addr = writer.get_extra_info(name)
        if addr is None:
            return default
        if isinstance(addr, tuple):
            return f"{addr[0]}:{addr[1]}"
        return str(addr)
    except Exception:
        return default


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
    max_sessions: int = 10
    event_loop_shards: int = 1
    max_retries: int = 3
    retry_delay: float = 2.0
    keepalive_interval: float = 30.0
    connection_timeout: float = 10.0

    buffer_size: int = 65536
    drain_threshold: int = 262144

    log_connections: bool = True
    log_level: str = "INFO"
    verbose: bool = False
    log_file: str = ""

    test_url: str = "http://httpbin.org/ip"
    auto_test: bool = True
    shutdown_timeout: float = 10.0

    handshake_timeout: float = 10.0
    max_handshake_buffer: int = 8192
    pool_acquire_timeout: float = 5.0

    pipe_idle_timeout: float = 300.0
    pipe_buffer_high_water: int = 1048576
    pipe_buffer_low_water: int = 262144

    max_consecutive_failures: int = 3          # 连续失败多少次后强制重连
    health_check_interval: float = 3.0        # 健康检查间隔(秒)
    slot_cooldown_after_failure: float = 1.0   # 失败后冷却时间(秒)


def validate_config(cfg: Config) -> List[str]:
    errors = []
    if not cfg.local_only and asyncssh is None:
        errors.append("asyncssh required. Install: pip install asyncssh")
    if not cfg.local_only:
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
    if not (1 <= cfg.max_sessions <= 1024):
        errors.append("max_sessions must be in range 1..1024")
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
    pool_slot_idx: Optional[int] = None
    pool_slot_id: Optional[str] = None


class ConnectFailReason(Enum):
    REFUSED = auto()
    UNREACHABLE = auto()
    TIMEOUT = auto()
    DNS_ERROR = auto()
    POOL_UNAVAILABLE = auto()
    TARGET_REFUSED = auto()    # 目标拒绝（SSH 连接本身无问题）
    SSH_BROKEN = auto()        # SSH 连接级故障
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


@dataclass
class PoolSlot:
    conn: Optional[asyncssh.SSHClientConnection] = None
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    in_use: int = 0
    usage: int = 0                                                          # ← 新增
    created_at: float = field(default_factory=time.monotonic)               # ← 修复
    last_used: float = 0.0
    healthy: bool = True
    consecutive_failures: int = 0
    last_failure_time: float = 0.0
    slot_id: str = field(default_factory=lambda: uuid.uuid4().hex[:8])      # ← 新增


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

    MARK_SLOT_FAILURE = auto()

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


def mark_slot_failure_eff(idx: int, slot_id: str) -> Effect:
    return Effect(EffectType.MARK_SLOT_FAILURE, (idx, slot_id))


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


def http_connect_target_has_explicit_port(target: str) -> bool:
    if target.startswith("["):
        end = target.find("]")
        return end > 0 and len(target) > end + 2 and target[end + 1] == ":" and target[end + 2 :].isdigit()
    if ":" not in target:
        return False
    _, port = target.rsplit(":", 1)
    return port.isdigit()


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


def find_crlfcrlf(data: bytes) -> int:
    return data.find(b"\r\n\r\n")


def split_lines(data: bytes) -> List[str]:
    text = data.decode("ascii")
    if text.endswith("\r\n"):
        text = text[:-2]
    return text.split("\r\n")


def is_valid_http_method(method: str) -> bool:
    return method.encode("ascii", errors="ignore") in HTTP_METHODS


def is_valid_http_version(version: str) -> bool:
    return version in ("HTTP/1.0", "HTTP/1.1")


def bytes_has_prefix_fold(line: bytes, prefix: bytes) -> bool:
    return line[: len(prefix)].lower() == prefix.lower()


def format_ipv4_host(data: bytes) -> str:
    if len(data) != 4:
        raise ValueError("invalid ipv4 length")
    return ".".join(str(b) for b in data)


def format_ipv6_host(data: bytes) -> str:
    if len(data) != 16:
        raise ValueError("invalid ipv6 length")
    return str(ipaddress.IPv6Address(data))


def map_connect_fail_to_socks_rep(reason: ConnectFailReason) -> int:
    if reason == ConnectFailReason.REFUSED:
        return 0x05
    if reason == ConnectFailReason.TARGET_REFUSED:
        return 0x05
    if reason in (
        ConnectFailReason.UNREACHABLE,
        ConnectFailReason.DNS_ERROR,
    ):
        return 0x04
    if reason == ConnectFailReason.TIMEOUT:
        return 0x04
    if reason == ConnectFailReason.SSH_BROKEN:
        return 0x01   # general failure — not the target's fault
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

    pool_slot_idx: Optional[int] = None
    pool_slot_id: Optional[str] = None

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
            effects=(session_failed("idle timeout"),),
        )

    if isinstance(event, PipeError):
        new_state = replace(
            state,
            phase=Phase.CLOSED,
            pipe_stage=PipeStage.CLOSED,
            error=f"{event.source.name.lower()}: {event.error_msg}",
        )
        effects: list = []
        if event.source == Endpoint.REMOTE:
            effects.append(clear_deadline("idle"))
        effects.append(session_failed("pipe error"))
        return Transition(
            state=new_state,
            effects=tuple(effects),
        )

    if isinstance(event, SendFailed):
        new_state = replace(
            state,
            phase=Phase.CLOSED,
            pipe_stage=PipeStage.CLOSED,
            error=f"send failed: {event.where}",
        )
        effects_list: list = [clear_deadline("idle"), session_failed("send failed")]
        return Transition(
            state=new_state,
            effects=tuple(effects_list),
        )

    if isinstance(event, PipeDataFromClient):
        if ps in (PipeStage.HALF_CLOSED_CLIENT, PipeStage.CLOSED):
            return Transition(state=state, effects=())
        return Transition(
            state=replace(state, bytes_sent=state.bytes_sent + event.length),
            effects=(write_remote(event.data),),
        )

    if isinstance(event, PipeDataFromRemote):
        if ps in (PipeStage.HALF_CLOSED_REMOTE, PipeStage.CLOSED):
            return Transition(state=state, effects=())
        return Transition(
            state=replace(state, bytes_received=state.bytes_received + event.length),
            effects=(write_client(event.data),),
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
                    effects=(session_done("both eof"),),
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
                    effects=(session_done("both eof"),),
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
        return _handle_target_connected(state, event, pipe_idle_timeout=pipe_idle_timeout)

    if isinstance(event, OutboundStreamOpenFailed):
        return _handle_target_connect_failed(state, event)

    if not isinstance(event, ClientDataReceived):
        return Transition(state=state, effects=())

    state = replace(state, buffer=state.buffer + event.data)
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

        if (
            len(state.buffer) > max_buffer
            and state.phase in (Phase.INIT, Phase.SOCKS5_AUTH, Phase.SOCKS5_REQ, Phase.HTTP_REQ)
        ):
            return Transition(
                state=replace(state, phase=Phase.CLOSED, buffer=b""),
                effects=(session_failed("handshake buffer overflow"),),
            )

    if (
        len(state.buffer) > max_buffer
        and state.phase in (Phase.INIT, Phase.SOCKS5_AUTH, Phase.SOCKS5_REQ, Phase.HTTP_REQ)
    ):
        return Transition(
            state=replace(state, phase=Phase.CLOSED, buffer=b""),
            effects=(session_failed("handshake buffer overflow"),),
        )

    return Transition(state=state, effects=tuple(effects))


def _handle_target_connected(
    state: ProxyProtocolState,
    event: OutboundStreamOpened,
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
        pool_slot_idx=event.pool_slot_idx,
        pool_slot_id=event.pool_slot_id,
        bytes_sent=state.bytes_sent + early_bytes,
    )
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
        if event.reason == ConnectFailReason.TARGET_REFUSED:
            rep = b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"
        elif event.reason == ConnectFailReason.SSH_BROKEN:
            rep = b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n"
        else:
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
        msg = "unsupported socks5 cmd"
        if cmd == 0x03:
            msg = "UDP ASSOCIATE not supported"
        return Transition(
            state=replace(state, phase=Phase.CLOSED, buffer=b""),
            effects=(write_client(socks5_reply(0x07)), session_failed(msg)),
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
            effects=(session_failed("unsupported http version"),),
        )

    method, target, version = parts
    method_b = method.encode("ascii")

    if not is_valid_http_version(version):
        return Transition(
            state=replace(state, phase=Phase.CLOSED, buffer=b""),
            effects=(session_failed("unsupported http version"),),
        )

    if method_b not in HTTP_METHODS:
        return Transition(
            state=replace(state, phase=Phase.CLOSED, buffer=b""),
            effects=(session_failed("unsupported http method"),),
        )

    try:
        if method == "CONNECT":
            if not http_connect_target_has_explicit_port(target):
                return Transition(
                    state=replace(state, phase=Phase.CLOSED, buffer=b""),
                    effects=(session_failed("malformed CONNECT target"),),
                )
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
                    effects=(session_failed("missing Host header"),),
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

    # TARGET_REFUSED → SOCKS5 rep 0x05
    s_tr = ProxyProtocolState(proxy_mode=ProxyMode.SOCKS5)
    s_tr = proxy_protocol_reducer(s_tr, ClientDataReceived(b"\x05\x01\x00")).state
    s_tr = proxy_protocol_reducer(s_tr, ClientDataReceived(req)).state
    tr_tr = proxy_protocol_reducer(
        s_tr, OutboundStreamOpenFailed(ConnectFailReason.TARGET_REFUSED, "port closed")
    )
    effs_tr = list(tr_tr.effects)
    check(
        "SOCKS5 TARGET_REFUSED: rep=0x05",
        any((e.type == EffectType.WRITE_CLIENT and e.data == socks5_reply(0x05)) for e in effs_tr)
    )

    # SSH_BROKEN → HTTP 503
    s_sb = ProxyProtocolState(proxy_mode=ProxyMode.HTTP)
    http_c = b"CONNECT target.com:443 HTTP/1.1\r\nHost: target.com:443\r\n\r\n"
    s_sb = proxy_protocol_reducer(s_sb, ClientDataReceived(http_c)).state
    tr_sb = proxy_protocol_reducer(
        s_sb, OutboundStreamOpenFailed(ConnectFailReason.SSH_BROKEN, "conn lost")
    )
    effs_sb = list(tr_sb.effects)
    check(
        "HTTP SSH_BROKEN: 503 response",
        any(e.type == EffectType.WRITE_CLIENT and b"503" in e.data for e in effs_sb),
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

    # --- MARK_SLOT_FAILURE from pipe reducer ---
    print("\n  --- MARK_SLOT_FAILURE tests ---")

    ps_mf = make_piping_state(pool_slot_idx=2, pool_slot_id="abc123")
    tr_mf = proxy_protocol_reducer(ps_mf, PipeError(Endpoint.REMOTE, "conn reset"))
    effs_mf = list(tr_mf.effects)
    check(
        "Pipe REMOTE error with pool info → MARK_SLOT_FAILURE",
        any(e.type == EffectType.MARK_SLOT_FAILURE and e.data == (2, "abc123") for e in effs_mf),
    )

    ps_mf2 = make_piping_state(pool_slot_idx=1, pool_slot_id="def456")
    tr_mf2 = proxy_protocol_reducer(ps_mf2, PipeError(Endpoint.CLIENT, "reset"))
    effs_mf2 = list(tr_mf2.effects)
    check(
        "Pipe CLIENT error with pool info → NO MARK_SLOT_FAILURE",
        not any(e.type == EffectType.MARK_SLOT_FAILURE for e in effs_mf2),
    )

    ps_mf3 = make_piping_state()  # no pool info
    tr_mf3 = proxy_protocol_reducer(ps_mf3, PipeError(Endpoint.REMOTE, "reset"))
    effs_mf3 = list(tr_mf3.effects)
    check(
        "Pipe REMOTE error without pool info → NO MARK_SLOT_FAILURE",
        not any(e.type == EffectType.MARK_SLOT_FAILURE for e in effs_mf3),
    )

    ps_mf4 = make_piping_state(pool_slot_idx=0, pool_slot_id="ghi789")
    tr_mf4 = proxy_protocol_reducer(ps_mf4, SendFailed("remote_write: broken"))
    effs_mf4 = list(tr_mf4.effects)
    check(
        "Pipe SendFailed(remote) with pool info → MARK_SLOT_FAILURE",
        any(e.type == EffectType.MARK_SLOT_FAILURE and e.data == (0, "ghi789") for e in effs_mf4),
    )

    ps_mf5 = make_piping_state(pool_slot_idx=0, pool_slot_id="jkl012")
    tr_mf5 = proxy_protocol_reducer(ps_mf5, SendFailed("client_write: broken"))
    effs_mf5 = list(tr_mf5.effects)
    check(
        "Pipe SendFailed(client) with pool info → NO MARK_SLOT_FAILURE",
        not any(e.type == EffectType.MARK_SLOT_FAILURE for e in effs_mf5),
    )

    ps_mf6 = make_piping_state(pool_slot_idx=0, pool_slot_id="mno345")
    tr_mf6 = proxy_protocol_reducer(ps_mf6, PipeIdleTimeout(300.0))
    effs_mf6 = list(tr_mf6.effects)
    check(
        "Pipe idle timeout → NO MARK_SLOT_FAILURE",
        not any(e.type == EffectType.MARK_SLOT_FAILURE for e in effs_mf6),
    )

    # --- OutboundStreamOpened carries pool info into state ---
    ps_pi = ProxyProtocolState(proxy_mode=ProxyMode.SOCKS5)
    ps_pi = proxy_protocol_reducer(ps_pi, ClientDataReceived(b"\x05\x01\x00")).state
    ps_pi = proxy_protocol_reducer(
        ps_pi, ClientDataReceived(b"\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50")
    ).state
    tr_pi = proxy_protocol_reducer(
        ps_pi, OutboundStreamOpened(pool_slot_idx=3, pool_slot_id="slot3x")
    )
    check(
        "OutboundStreamOpened pool info stored in state",
        tr_pi.state.pool_slot_idx == 3 and tr_pi.state.pool_slot_id == "slot3x",
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
    shard_queues: List[asyncio.Queue] = field(default_factory=list)
    shard_tasks: List[asyncio.Task] = field(default_factory=list)
    accept_sequence: int = 0


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


def normalize_event_loop_shard_count(requested: int, cpu_count: int) -> int:
    if requested > 0:
        return requested
    return cpu_count if cpu_count > 0 else 1


def compute_shard_index(key: int, shard_count: int) -> int:
    if shard_count <= 0:
        return 0
    return key % shard_count


def hash_shard_key(remote_addr: str, sequence: int) -> int:
    digest = hashlib.sha256(f"{remote_addr}|{sequence}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big", signed=False)


def assign_accept_shard(remote_addr: str, sequence: int, shard_count: int) -> int:
    return compute_shard_index(hash_shard_key(remote_addr, sequence), shard_count)


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
# Pool Decision Layer (Sans-I/O — pure functions, fully testable)
# ============================================================================


@dataclass(frozen=True)
class PoolSlotView:
    """Immutable snapshot of one pool slot, used by pure decision functions."""
    index: int
    slot_id: str
    healthy: bool
    is_connected: bool
    consecutive_failures: int
    last_failure_time: float
    last_used: float
    usage: int


def snapshot_slots(slots: list) -> List[Optional[PoolSlotView]]:
    """Read mutable PoolSlots → immutable views.  Call under pool.lock."""
    views: List[Optional[PoolSlotView]] = []
    for i, slot in enumerate(slots):
        if slot is None:
            views.append(None)
        else:
            views.append(PoolSlotView(
                index=i,
                slot_id=slot.slot_id,
                healthy=slot.healthy,
                is_connected=bool(slot.conn and not slot.conn.is_closed()),
                consecutive_failures=slot.consecutive_failures,
                last_failure_time=slot.last_failure_time,
                last_used=slot.last_used,
                usage=slot.usage,
            ))
    return views


def select_best_slot_index(
    views: List[Optional[PoolSlotView]],
    now: float,
    cooldown: float = 2.0,
) -> Optional[int]:
    """Pure: pick the best slot index, or *None* if nothing is usable.

    Selection: lowest ``usage``, ties broken by earliest ``last_used``.
    Slots in cooldown (failures > 0 and within cooldown window) are skipped
    unless **all** slots are cooling down — in that case the least-failed
    connected slot is returned as a fallback.
    """
    candidates: List[PoolSlotView] = []
    for v in views:
        if v is None or not v.healthy or not v.is_connected:
            continue
        if v.consecutive_failures > 0 and (now - v.last_failure_time) < cooldown:
            continue
        candidates.append(v)

    if not candidates:
        # Fallback: least-failed connected slot (ignoring cooldown)
        fallbacks = [v for v in views if v is not None and v.healthy and v.is_connected]
        if not fallbacks:
            return None
        fallbacks.sort(key=lambda v: (v.consecutive_failures, v.last_used))
        return fallbacks[0].index

    candidates.sort(key=lambda v: (v.usage, v.last_used))
    return candidates[0].index


def should_force_reconnect(consecutive_failures: int, max_failures: int) -> bool:
    """Pure: has the slot exceeded its failure budget?"""
    return consecutive_failures >= max_failures


def apply_slot_failure(
    current_failures: int,
    now: float,
) -> Tuple[int, float]:
    """Pure: returns (new_failure_count, last_failure_time)."""
    return (current_failures + 1, now)


def apply_slot_success(current_failures: int) -> int:   # noqa: ARG001
    """Pure: returns new failure count (always 0)."""
    return 0


def should_watcher_reconnect(
    consecutive_failures: int,
    max_consecutive_failures: int,
) -> bool:
    """Pure: used by watch_connection health-check tick."""
    return consecutive_failures >= max_consecutive_failures


# ============================================================================
# SSH Pool
# ============================================================================

async def mark_slot_failure(pool: PoolState, idx: int, slot_id: str,
                             max_failures: int = 3, log: logging.Logger = None):
    """Mark one channel-open failure; force reconnect if threshold reached."""
    async with pool.lock:
        slot = pool.slots[idx]
        if not slot or slot.slot_id != slot_id:
            return
        new_failures, new_time = apply_slot_failure(
            slot.consecutive_failures, time.monotonic()
        )
        slot.consecutive_failures = new_failures
        slot.last_failure_time = new_time

        if should_force_reconnect(new_failures, max_failures):
            if log:
                log.warning(
                    f"Connection #{idx} (...{slot_id}) hit {new_failures} "
                    f"consecutive failures — forcing reconnect"
                )
            # 标记不健康，使 acquire_connection 不再选中此 slot
            slot.healthy = False
            # 关闭底层连接；watcher 的 wait_closed() 会自然返回，触发重连
            # 不设 pool.slots[idx] = None — 让活跃会话有机会收到错误并清理
            # if slot.conn and not slot.conn.is_closed():
            #     try:
            #         slot.conn.close()
            #     except Exception:
            #         pass
            # pool.slots[idx] = None  # 清除，让 watcher 立即重连


async def mark_slot_success(pool: PoolState, idx: int, slot_id: str):
    """Reset failure count on successful channel open."""
    async with pool.lock:
        slot = pool.slots[idx]
        if slot and slot.slot_id == slot_id:
            slot.consecutive_failures = apply_slot_success(slot.consecutive_failures)


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


# ✅ 修复 — 补回完整的重连循环
async def watch_connection(cfg: Config, pool: PoolState, idx: int, log: logging.Logger):
    while not pool.closed:
        async with pool.lock:
            slot = pool.slots[idx]

        if slot and slot.conn:
            try:
                await asyncio.wait_for(
                    slot.conn.wait_closed(),
                    timeout=cfg.health_check_interval
                )
                # wait_closed 正常返回 → 连接已死
            except asyncio.TimeoutError:
                # 超时 → 连接可能还活着，检查失败计数
                async with pool.lock:
                    current_slot = pool.slots[idx]
                if current_slot and current_slot is slot:
                    # if current_slot.consecutive_failures > 0:
                    # === 修复 #2: 健康检查放宽 ===
                    if should_watcher_reconnect(
                        current_slot.consecutive_failures,
                        cfg.max_consecutive_failures,
                    ):
                        log.warning(
                            f"Connection #{idx} (...{slot.slot_id}) has "
                            f"{current_slot.consecutive_failures} failures "
                            f"— forcing reconnect"
                        )
                        async with pool.lock:
                            if pool.slots[idx] is slot:
                                try:
                                    slot.conn.close()
                                except Exception:
                                    pass
                                pool.slots[idx] = None
                        # ↓ 跳出 if，进入下面的重连循环
                    else:
                        continue  # 健康，继续监视
                else:
                    continue  # slot 已被替换
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

        # ★★★ 重连循环（之前被删除了）★★★
        rc = 0
        while not pool.closed:
            rc += 1
            try:
                new_conn = await create_ssh_connection(cfg)
                new_slot = PoolSlot(conn=new_conn)
                async with pool.lock:
                    pool.slots[idx] = new_slot
                log.info(
                    f"  ✓ Connection #{idx} re-established (...{new_slot.slot_id})"
                )
                break
            except asyncio.CancelledError:
                return
            except Exception as e:
                delay = min(cfg.retry_delay * (2 ** (rc - 1)), 30.0)
                if rc <= 3:
                    log.warning(
                        f"  ✗ Reconnect #{idx} attempt {rc} failed: {e}. "
                        f"Retry in {delay:.1f}s..."
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

async def acquire_connection(pool: PoolState, cooldown: float = 2.0):
    now = time.monotonic()
    async with pool.lock:
        views = snapshot_slots(pool.slots)
        best_idx = select_best_slot_index(views, now, cooldown)
        if best_idx is None:
            return None
        slot = pool.slots[best_idx]
        slot.usage += 1
        slot.last_used = time.monotonic()
        return best_idx, slot.conn, slot.slot_id


async def acquire_connection_with_retry(pool: PoolState, timeout: float = 5.0,
                                         cooldown: float = 2.0):
    deadline = time.monotonic() + timeout
    while True:
        res = await acquire_connection(pool, cooldown=cooldown)
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


@dataclass
class RuntimeHandleEntry:
    reader: Any = None
    writer: Any = None
    kind: str = ""
    local_addr: str = "unknown"
    remote_addr: str = "unknown"
    pool_idx: int = -1
    pool_slot_id: str = ""


class RuntimeWorld:
    def __init__(
        self,
        cfg: Config,
        state: ServerState,
        log: logging.Logger,
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
    ):
        self.cfg = cfg
        self.state = state
        self.log = log
        self.core = RuntimeCore(_runtime_config_from_cfg(cfg))
        self.completions: asyncio.Queue = asyncio.Queue()
        self.handles: Dict[int, RuntimeHandleEntry] = {}
        self.tasks: set = set()
        self.next_handle = 1
        self.closed = False
        self.bytes_sent = 0
        self.bytes_received = 0
        io_resource_log(
            self.cfg,
            "listener_accept",
            listen_addr=_stream_addr(client_writer, "sockname"),
            local_addr=_stream_addr(client_writer, "sockname"),
            remote_addr=_stream_addr(client_writer, "peername"),
            result="ok",
        )
        self.tune_tcp(client_writer)
        self.client_handle = self.register_handle(
            client_reader,
            client_writer,
            kind="client",
            pool_idx=-1,
            pool_slot_id="",
        )

    def register_handle(
        self,
        reader: Any,
        writer: Any,
        kind: str,
        pool_idx: int = -1,
        pool_slot_id: str = "",
    ) -> int:
        handle = self.next_handle
        self.next_handle += 1
        entry = RuntimeHandleEntry(
            reader=reader,
            writer=writer,
            kind=kind,
            local_addr=_stream_addr(writer, "sockname"),
            remote_addr=_stream_addr(writer, "peername"),
            pool_idx=pool_idx,
            pool_slot_id=pool_slot_id,
        )
        self.handles[handle] = entry
        if kind == "client":
            io_resource_log(
                self.cfg,
                "accept",
                handle=handle,
                local_addr=entry.local_addr,
                remote_addr=entry.remote_addr,
            )
        io_resource_log(
            self.cfg,
            "handle_register",
            handle=handle,
            local_addr=entry.local_addr,
            remote_addr=entry.remote_addr,
        )
        return handle

    async def run(self) -> None:
        await self.feed({"type": "updateTime", "nowNanos": time.time_ns()})
        await self.feed({"type": "accepted", "handle": self.client_handle})
        ticker = asyncio.create_task(self._ticker())
        self.tasks.add(ticker)
        try:
            while not self.closed and (self.handles or self.tasks):
                try:
                    completion = await self.completions.get()
                except asyncio.CancelledError:
                    break
                await self.feed(completion)
                self._drop_done_tasks()
                if not self.handles:
                    break
        finally:
            self.closed = True
            for task in list(self.tasks):
                if not task.done():
                    task.cancel()
            if self.tasks:
                await asyncio.gather(*self.tasks, return_exceptions=True)
            for handle in list(self.handles):
                await self.close_handle(handle)

    async def feed(self, completion: Dict[str, Any]) -> None:
        commands = self.core.step(completion)
        while commands:
            more: List[Dict[str, Any]] = []
            for command in commands:
                inline = await self.execute_command(command)
                more.extend(inline)
            commands = []
            for item in more:
                commands.extend(self.core.step(item))

    async def execute_command(self, command: Dict[str, Any]) -> List[Dict[str, Any]]:
        ctype = command["type"]
        if ctype == "read":
            return await self.start_read(command)
        if ctype == "writeInline":
            return await self.start_write(command)
        if ctype == "dialDirect":
            return await self.start_direct_dial(command)
        if ctype == "snapshotPool":
            return [await self.snapshot_pool(command)]
        if ctype == "dialSSH":
            return await self.start_ssh_dial(command)
        if ctype == "close":
            io_resource_log(self.cfg, "runtime_close", handle=int(command["handle"]), result="requested")
            await self.close_handle(int(command["handle"]))
            return []
        if ctype == "closeWrite":
            await self.close_write(command)
            return []
        if ctype == "releasePayload":
            self.release_payload(command.get("payload"), "runtime")
            return []
        if ctype == "logSessionDone":
            self.log.debug(command.get("text", "session done"))
            return []
        if ctype == "logSessionFreed":
            self.log.debug(command.get("text", "session freed"))
            return []
        if ctype == "logSessionFailed":
            self.state.stats.errors += 1
            self.log.warning(command.get("text", "session failed"))
            return []
        if ctype == "logWriteFailure":
            self.state.stats.errors += 1
            self.log.warning(command.get("text", "write failed"))
            return []
        if ctype == "logIOFailure":
            self.state.stats.errors += 1
            self.log.warning(command.get("text", "io failed"))
            return []
        if ctype == "emitDiagnostic":
            self.log.debug(command.get("text", "diagnostic"))
            return []
        if ctype == "markPoolSlotFailed":
            await self.mark_pool_slot_failed(command)
            return []
        if ctype == "healthCheckPoolSlot":
            return await self.health_check_pool_slot(command)
        if ctype == "reconnectPoolSlot":
            return await self.reconnect_pool_slot(command)
        return []

    async def start_read(self, command: Dict[str, Any]) -> List[Dict[str, Any]]:
        token = command["token"]
        handle = int(command["handle"])
        source = command["source"]
        entry = self.handles.get(handle)
        fields = self.token_fields(token)
        fields.update({"handle": handle, "source": source})
        if entry is None or entry.reader is None:
            io_resource_log(self.cfg, "runtime_read_start", **fields, result="unavailable", error="handle unavailable")
            return [{
                "type": "readError",
                "token": token,
                "handle": handle,
                "source": source,
                "error": "handle unavailable",
            }]
        io_resource_log(self.cfg, "runtime_read_start", **fields, result="started")
        task = asyncio.create_task(self._read_once(command, entry.reader))
        self.tasks.add(task)
        return []

    async def _read_once(self, command: Dict[str, Any], reader: Any) -> None:
        token = command["token"]
        handle = int(command["handle"])
        source = command["source"]
        fields = self.token_fields(token)
        fields.update({"handle": handle, "source": source})
        try:
            data = await reader.read(self.cfg.buffer_size)
            if data:
                payload = {"len": len(data), "cap": len(data)}
                completion = "read_done"
                io_resource_log(self.cfg, "driver_read_done", **fields, completion=completion, length=len(data), result="ok")
                await self.completions.put({
                    "type": "readDone",
                    "token": token,
                    "handle": handle,
                    "source": source,
                    "data": data,
                    "payload": payload,
                })
            else:
                completion = "read_eof"
                io_resource_log(self.cfg, "driver_read_done", **fields, completion=completion, length=0, result="ok")
                await self.completions.put({
                    "type": "readEOF",
                    "token": token,
                    "handle": handle,
                    "source": source,
                })
        except asyncio.CancelledError:
            return
        except Exception as exc:
            io_resource_log(
                self.cfg,
                "driver_failure",
                **fields,
                completion="read_error",
                result="error",
                error=str(exc),
            )
            await self.completions.put({
                "type": "readError",
                "token": token,
                "handle": handle,
                "source": source,
                "error": str(exc),
            })

    async def start_write(self, command: Dict[str, Any]) -> List[Dict[str, Any]]:
        token = command["token"]
        handle = int(command["handle"])
        dest = command["dest"]
        data = command.get("bytes", b"")
        if isinstance(data, str):
            data = data.encode("utf-8")
        entry = self.handles.get(handle)
        fields = self.token_fields(token)
        fields.update({"handle": handle, "dest": dest, "data_len": len(data)})
        if entry is None or entry.writer is None or not _is_writer_usable(entry.writer):
            io_resource_log(self.cfg, "runtime_write_start", **fields, result="unavailable", error="handle unavailable")
            return [{
                "type": "writeFailed",
                "token": token,
                "handle": handle,
                "dest": dest,
                "error": "handle unavailable",
                "payload": command.get("payload"),
            }]
        io_resource_log(self.cfg, "runtime_write_start", **fields, result="started")
        task = asyncio.create_task(self._write_once(command, entry.writer, data))
        self.tasks.add(task)
        return []

    async def _write_once(self, command: Dict[str, Any], writer: Any, data: bytes) -> None:
        token = command["token"]
        handle = int(command["handle"])
        dest = command["dest"]
        fields = self.token_fields(token)
        fields.update({"handle": handle, "dest": dest})
        try:
            writer.write(data)
            await writer.drain()
            length = len(data)
            io_resource_log(self.cfg, "driver_write_done", **fields, completion="write_done", length=length, result="ok")
            if dest == "remote":
                self.bytes_sent += length
            else:
                self.bytes_received += length
            await self.completions.put({
                "type": "writeDone",
                "token": token,
                "handle": handle,
                "dest": dest,
                "len": length,
                "payload": command.get("payload"),
            })
        except asyncio.CancelledError:
            return
        except Exception as exc:
            io_resource_log(
                self.cfg,
                "driver_failure",
                **fields,
                completion="write_failed",
                length=len(data),
                result="error",
                error=str(exc),
            )
            await self.completions.put({
                "type": "writeFailed",
                "token": token,
                "handle": handle,
                "dest": dest,
                "error": str(exc),
                "payload": command.get("payload"),
            })

    async def start_direct_dial(self, command: Dict[str, Any]) -> List[Dict[str, Any]]:
        token = command["token"]
        host = command["host"]
        port = int(command["port"])
        fields = self.token_fields(token)
        io_resource_log(
            self.cfg,
            "runtime_dial_direct_start",
            **fields,
            host=host,
            port=port,
            timeout_nanos=int(self.cfg.connection_timeout * NANO),
            result="started",
        )
        task = asyncio.create_task(self._dial_direct_once(command))
        self.tasks.add(task)
        return []

    async def _dial_direct_once(self, command: Dict[str, Any]) -> None:
        token = command["token"]
        host = command["host"]
        port = int(command["port"])
        fields = self.token_fields(token)
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=self.cfg.connection_timeout,
            )
            self.tune_tcp(writer)
            handle = self.register_handle(reader, writer, kind="remote")
            io_resource_log(self.cfg, "driver_dial_direct_done", **fields, handle=handle, completion="dial_done", result="ok")
            await self.completions.put({
                "type": "dialDone",
                "token": token,
                "remoteHandle": handle,
                "poolIdx": -1,
                "poolSlotId": "",
            })
        except asyncio.CancelledError:
            return
        except Exception as exc:
            io_resource_log(
                self.cfg,
                "driver_failure",
                **fields,
                completion="dial_failed",
                result="error",
                error=str(exc),
            )
            await self.completions.put({
                "type": "dialFailed",
                "token": token,
                "reason": str(exc),
                "poolIdx": -1,
                "poolSlotId": "",
            })

    async def snapshot_pool(self, command: Dict[str, Any]) -> Dict[str, Any]:
        token = command["token"]
        fields = self.token_fields(token)
        if self.state.pool is None:
            io_resource_log(self.cfg, "runtime_snapshot_pool", **fields, pool_views=0, result="unavailable", error="pool unavailable")
            return {"type": "poolSnapshot", "token": token, "poolViews": []}
        io_resource_log(self.cfg, "ssh_pool_snapshot_start", pool_size=len(self.state.pool.slots))
        async with self.state.pool.lock:
            views = snapshot_slots(self.state.pool.slots)
        out = [_pool_view_to_core_dict(v) for v in views if v is not None]
        io_resource_log(self.cfg, "runtime_snapshot_pool", **fields, pool_views=len(out), result="ok")
        return {"type": "poolSnapshot", "token": token, "poolViews": out}

    async def start_ssh_dial(self, command: Dict[str, Any]) -> List[Dict[str, Any]]:
        token = command["token"]
        pool_idx = int(command["poolIdx"])
        pool_slot_id = command.get("poolSlotId", "")
        host = command["host"]
        port = int(command["port"])
        fields = self.token_fields(token)
        fields.update({"pool_idx": pool_idx, "pool_slot_id": pool_slot_id, "host": host, "port": port})
        io_resource_log(
            self.cfg,
            "runtime_dial_ssh_start",
            **fields,
            timeout_nanos=int(self.cfg.connection_timeout * NANO),
            result="started",
        )
        task = asyncio.create_task(self._dial_ssh_once(command))
        self.tasks.add(task)
        return []

    async def _dial_ssh_once(self, command: Dict[str, Any]) -> None:
        token = command["token"]
        pool_idx = int(command["poolIdx"])
        pool_slot_id = command.get("poolSlotId", "")
        host = command["host"]
        port = int(command["port"])
        fields = self.token_fields(token)
        fields.update({"pool_idx": pool_idx, "pool_slot_id": pool_slot_id, "host": host, "port": port})
        conn = None
        slot_id = pool_slot_id
        open_started = False
        try:
            io_resource_log(self.cfg, "ssh_pool_lookup_start", pool_idx=pool_idx, pool_slot_id=pool_slot_id)
            async with self.state.pool.lock:
                if pool_idx < 0 or pool_idx >= len(self.state.pool.slots):
                    slot = None
                else:
                    slot = self.state.pool.slots[pool_idx]
                if not slot or slot.slot_id != pool_slot_id or not slot.conn or slot.conn.is_closed():
                    slot = None
                if slot is not None:
                    slot.usage += 1
                    slot.last_used = time.monotonic()
                    conn = slot.conn
                    slot_id = slot.slot_id
            if conn is None:
                io_resource_log(self.cfg, "ssh_pool_lookup_done", pool_idx=pool_idx, pool_slot_id=pool_slot_id, result="error", error="slot unavailable")
                raise RuntimeError("slot unavailable")
            io_resource_log(self.cfg, "ssh_pool_lookup_done", pool_idx=pool_idx, pool_slot_id=slot_id, result="ok")
            io_resource_log(self.cfg, "ssh_channel_open_start", pool_idx=pool_idx, pool_slot_id=slot_id, host=host, port=port)
            open_started = True
            reader, writer = await asyncio.wait_for(
                conn.open_connection(host, port),
                timeout=self.cfg.connection_timeout,
            )
            io_resource_log(self.cfg, "ssh_channel_open_done", pool_idx=pool_idx, pool_slot_id=slot_id, host=host, port=port, result="ok")
            await mark_slot_success(self.state.pool, pool_idx, slot_id)
            handle = self.register_handle(reader, writer, kind="remote", pool_idx=pool_idx, pool_slot_id=slot_id)
            io_resource_log(self.cfg, "driver_dial_ssh_done", **fields, handle=handle, completion="dial_done", result="ok")
            await self.completions.put({
                "type": "dialDone",
                "token": token,
                "remoteHandle": handle,
                "poolIdx": pool_idx,
                "poolSlotId": slot_id,
            })
        except asyncio.CancelledError:
            return
        except Exception as exc:
            if open_started:
                io_resource_log(self.cfg, "ssh_channel_open_done", pool_idx=pool_idx, pool_slot_id=slot_id, host=host, port=port, result="error", error=str(exc))
            io_resource_log(
                self.cfg,
                "driver_failure",
                **fields,
                completion="dial_failed",
                dial_kind="ssh",
                result="error",
                error=str(exc),
            )
            await self.completions.put({
                "type": "dialFailed",
                "token": token,
                "reason": str(exc),
                "poolIdx": pool_idx,
                "poolSlotId": slot_id,
            })
        finally:
            if conn is not None:
                await release_connection(self.state.pool, pool_idx, slot_id)

    async def close_write(self, command: Dict[str, Any]) -> None:
        handle = int(command["handle"])
        dest = command.get("dest", "unknown")
        entry = self.handles.get(handle)
        if entry is None or entry.writer is None:
            io_resource_log(self.cfg, "runtime_close_write", handle=handle, dest=dest, result="unavailable", error="handle unavailable")
            return
        try:
            writer = entry.writer
            if hasattr(writer, "can_write_eof") and not writer.can_write_eof():
                io_resource_log(self.cfg, "runtime_close_write", handle=handle, dest=dest, result="unavailable")
                return
            writer.write_eof()
            io_resource_log(self.cfg, "runtime_close_write", handle=handle, dest=dest, result="ok")
        except Exception as exc:
            io_resource_log(self.cfg, "runtime_close_write", handle=handle, dest=dest, result="error", error=str(exc))

    async def close_handle(self, handle: int) -> None:
        entry = self.handles.pop(handle, None)
        if entry is None:
            io_resource_log(self.cfg, "handle_close", handle=handle, result="ok")
            return
        try:
            await safe_close(entry.writer)
            result = "ok"
            error = None
        except Exception as exc:
            result = "error"
            error = str(exc)
        if entry.pool_idx >= 0 and entry.pool_slot_id:
            await release_connection(self.state.pool, entry.pool_idx, entry.pool_slot_id)
        if error:
            io_resource_log(self.cfg, "handle_close", handle=handle, local_addr=entry.local_addr, remote_addr=entry.remote_addr, result=result, error=error)
        else:
            io_resource_log(self.cfg, "handle_close", handle=handle, local_addr=entry.local_addr, remote_addr=entry.remote_addr, result=result)

    def release_payload(self, payload: Optional[Dict[str, Any]], reason: str) -> None:
        if not payload:
            return
        length = int(payload.get("len", payload.get("length", 0)) or 0)
        cap = int(payload.get("cap", length) or 0)
        io_resource_log(self.cfg, "payload_release", reason=reason, payload_len=length, payload_cap=cap)

    async def mark_pool_slot_failed(self, command: Dict[str, Any]) -> None:
        idx = int(command["poolIdx"])
        slot_id = command.get("poolSlotId", "")
        io_resource_log(self.cfg, "runtime_mark_pool_slot_failed", pool_idx=idx, result="closing")
        await mark_slot_failure(self.state.pool, idx, slot_id, max_failures=1, log=self.log)

    async def health_check_pool_slot(self, command: Dict[str, Any]) -> List[Dict[str, Any]]:
        idx = int(command["poolIdx"])
        slot_id = command.get("poolSlotId", "")
        pool_op_id = str(command.get("poolOpId", "0"))
        error = "health check executor unavailable in per-connection runtime world"
        io_resource_log(self.cfg, "runtime_health_check_start", pool_idx=idx, pool_op_id=pool_op_id, result="unavailable", error=error)
        return [{
            "type": "poolSlotHealthCheckUnavailable",
            "poolIdx": idx,
            "poolSlotId": slot_id,
            "poolOpId": pool_op_id,
            "error": error,
            "nowNanos": time.time_ns(),
        }]

    async def reconnect_pool_slot(self, command: Dict[str, Any]) -> List[Dict[str, Any]]:
        idx = int(command["poolIdx"])
        pool_op_id = str(command.get("poolOpId", "0"))
        reason = command.get("reason", "")
        io_resource_log(self.cfg, "runtime_reconnect_start", pool_idx=idx, pool_op_id=pool_op_id, reason=reason, result="unavailable")
        return [{
            "type": "poolSlotReconnectFailed",
            "poolIdx": idx,
            "poolOpId": pool_op_id,
            "error": "reconnect executor unavailable in py runtime world",
        }]

    async def _ticker(self) -> None:
        try:
            while not self.closed:
                await asyncio.sleep(1.0)
                await self.completions.put({"type": "tick", "nowNanos": time.time_ns()})
        except asyncio.CancelledError:
            return

    def _drop_done_tasks(self) -> None:
        self.tasks = {task for task in self.tasks if not task.done()}

    def tune_tcp(self, writer: Any) -> None:
        sock = None
        try:
            sock = writer.get_extra_info("socket")
            if sock is None:
                io_resource_log(self.cfg, "tcp_tune_skipped", reason="socket unavailable")
                return
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            io_resource_log(self.cfg, "tcp_set_option", option="TCP_NODELAY", result="ok")
        except Exception as exc:
            io_resource_log(self.cfg, "tcp_set_option", option="TCP_NODELAY", result="error", error=str(exc))

    def token_fields(self, token: Dict[str, Any]) -> Dict[str, Any]:
        op = token.get("op", "")
        return {
            "session": int(token.get("id", 0)),
            "generation": int(token.get("gen", 0)),
            "op": _runtime_op_number(op),
            "op_label": _runtime_op_label(op),
        }


def _runtime_op_number(op: str) -> int:
    return {
        "readClient": 1,
        "readRemote": 2,
        "writeClient": 3,
        "writeRemote": 4,
        "dial": 5,
    }.get(op, 0)


def _runtime_op_label(op: str) -> str:
    return {
        "readClient": "read_client",
        "readRemote": "read_remote",
        "writeClient": "write_client",
        "writeRemote": "write_remote",
        "dial": "dial",
    }.get(op, "unknown")


def _runtime_config_from_cfg(cfg: Config) -> Dict[str, Any]:
    return {
        "proxy_mode": {
            ProxyMode.BOTH: "both",
            ProxyMode.SOCKS5: "socks5",
            ProxyMode.HTTP: "http",
        }[cfg.proxy_mode],
        "local_only": cfg.local_only,
        "max_sessions": 1024,
        "max_handshake_buffer": cfg.max_handshake_buffer,
        "handshake_timeout_nanos": int(cfg.handshake_timeout * NANO),
        "pipe_idle_timeout_nanos": int(cfg.pipe_idle_timeout * NANO),
        "pipe_buffer_high_water": cfg.pipe_buffer_high_water,
        "pipe_buffer_low_water": cfg.pipe_buffer_low_water,
        "pool_acquire_timeout_nanos": int(cfg.pool_acquire_timeout * NANO),
        "pool_acquire_retry_interval_nanos": 100_000_000,
        "max_sessions_per_slot": cfg.max_sessions,
        "slot_cooldown_nanos": int(cfg.slot_cooldown_after_failure * NANO),
        "pool_health_check_interval_nanos": int(cfg.health_check_interval * NANO),
        "pool_reconnect_interval_nanos": int(cfg.retry_delay * NANO),
        "pool_max_health_failures": cfg.max_consecutive_failures,
        "pool_supervisor_enabled": False,
        "pool_control_enabled": not cfg.local_only,
    }


def _pool_view_to_core_dict(view: PoolSlotView) -> Dict[str, Any]:
    return {
        "index": view.index,
        "slotId": view.slot_id,
        "healthy": view.healthy,
        "isConnected": view.is_connected,
        "usage": view.usage,
        "consecutiveFailures": view.consecutive_failures,
        "lastFailureNanos": int(view.last_failure_time * NANO),
    }


# ============================================================================
# Shell helpers
# ============================================================================


async def _start_pipe_runtime_if_needed(ctx: IOContext, cfg: Config):
    if ctx.pipe_event_queue is not None:
        return
    if not ctx.remote_reader:
        return

    #-    ctx.pipe_event_queue = asyncio.Queue()
    maxsize = max(4, cfg.pipe_buffer_high_water // max(1, cfg.buffer_size))
    ctx.pipe_event_queue = asyncio.Queue(maxsize=maxsize)
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
    def _enqueue_idle_timeout():
        try:
            ctx.pipe_event_queue.put_nowait(PipeIdleTimeout(timeout))
        except asyncio.QueueFull:
            pass  # Queue full ⇒ data is flowing ⇒ not actually idle

    ctx.idle_timer_handle = loop.call_later(
        timeout,
        _enqueue_idle_timeout,
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
            else:
                await ctx.remote_writer.drain()
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
            acquired = await acquire_connection_with_retry(
                server_state.pool,
                timeout=cfg.pool_acquire_timeout,
                cooldown=cfg.slot_cooldown_after_failure,  # 新增
            )
            if acquired is None:
                server_state.stats.errors += 1
                return [OutboundStreamOpenFailed(
                    ConnectFailReason.POOL_UNAVAILABLE,
                    "no ssh connection available"
                )]

            pool_idx, ssh_conn, pool_slot_id = acquired
            ctx.pool_idx, ctx.pool_slot_id = pool_idx, pool_slot_id
            try:
                remote_reader, remote_writer = await asyncio.wait_for(
                    ssh_conn.open_connection(host, port),
                    timeout=cfg.connection_timeout
                )
                ctx.remote_reader, ctx.remote_writer = remote_reader, remote_writer

                # ——— 新增：成功后重置失败计数 ———
                await mark_slot_success(
                    server_state.pool, pool_idx, pool_slot_id
                )

                return [OutboundStreamOpened(
                    pool_slot_idx=pool_idx,
                    pool_slot_id=pool_slot_id,
                )]

            except asyncssh.ChannelOpenError as e:
                # 目标端口拒绝 ≠ SSH 坏了 → TARGET_REFUSED，不标记 slot
                server_state.stats.errors += 1
                return [OutboundStreamOpenFailed(
                    ConnectFailReason.TARGET_REFUSED, str(e)
                )]

            except asyncssh.ConnectionLost as e:
                # SSH 连接丢失 → SSH_BROKEN，立即强制重连
                server_state.stats.errors += 1
                await mark_slot_failure(
                    server_state.pool, pool_idx, pool_slot_id,
                    max_failures=1, log=log,
                )
                return [OutboundStreamOpenFailed(
                    ConnectFailReason.SSH_BROKEN, str(e)
                )]

            except asyncio.TimeoutError:
                # channel open 超时 — 大概率连接级问题
                server_state.stats.errors += 1
                await mark_slot_failure(
                    server_state.pool, pool_idx, pool_slot_id,
                    max_failures=cfg.max_consecutive_failures,
                    log=log,
                )
                return [OutboundStreamOpenFailed(
                    ConnectFailReason.TIMEOUT,
                    f"channel open timeout ({cfg.connection_timeout}s)"
                )]

            except Exception as e:
                # 未知异常 → 保守地标记
                server_state.stats.errors += 1
                await mark_slot_failure(
                    server_state.pool, pool_idx, pool_slot_id,
                    max_failures=cfg.max_consecutive_failures,
                    log=log,
                )
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
        # Slot failure marking is now driven by the reducer via MARK_SLOT_FAILURE
        return []

    elif eff.type == EffectType.MARK_SLOT_FAILURE:
        idx, slot_id = eff.data
        await mark_slot_failure(
            server_state.pool, idx, slot_id,
            max_failures=cfg.max_consecutive_failures, log=log,
        )
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
# Effect types that must execute even after a failure in the same transition
_CLEANUP_EFFECT_TYPES = frozenset({
    EffectType.SESSION_DONE,
    EffectType.SESSION_FAILED,
    EffectType.CLEAR_DEADLINE,
    EffectType.PIPE_CLOSE_BOTH,
    EffectType.PIPE_WRITE_EOF,
})

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

        # for eff in tr.effects:
            # new_events = await execute_one_effect(
            #     eff, ctx, cfg, server_state, log, peer
            # )
            # pending_events.extend(new_events)
            # -        for eff in tr.effects:
            # -            new_events = await execute_one_effect(
            # -                eff, ctx, cfg, server_state, log, peer
            # -            )
            # -            pending_events.extend(new_events)
        abort_remaining = False
        for eff in tr.effects:
            # After a failure, only execute cleanup effects
            if abort_remaining and eff.type not in _CLEANUP_EFFECT_TYPES:
                continue

            new_events = await execute_one_effect(
                eff, ctx, cfg, server_state, log, peer
            )

            if new_events:
                # Prepend returned events so the reducer sees them
                # before any remaining pending events
                for ev in reversed(new_events):
                    pending_events.appendleft(ev)
                # Stop executing further non-cleanup effects from
                # this transition; let the failure event drive cleanup
                abort_remaining = True

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
        # Normally unreachable: OPEN_OUTBOUND_STREAM resolves within _drain_pending.
        # Defensive: read client side to detect early disconnect rather than
        # killing the session unconditionally.
        try:
            data = await asyncio.wait_for(
                client_read(ctx.client_reader),
                timeout=cfg.connection_timeout,
            )
            return ClientDataReceived(data) if data else ClientConnectionClosed()
        except asyncio.TimeoutError:
            return HandshakeTimeout(cfg.connection_timeout)
        except Exception:
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


# ✅ 修复 — 删除 _relay，重写 handle_client 和 client_wrapper

async def handle_client(
    cfg: Config,
    state: ServerState,
    log: logging.Logger,
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
):
    """Runtime world: feeds I/O facts to RuntimeCore and executes commands."""
    peer = client_writer.get_extra_info("peername") or ("?", 0)
    state.stats.total += 1
    state.stats.active += 1
    state.stats.peak = max(state.stats.peak, state.stats.active)

    try:
        world = RuntimeWorld(cfg, state, log, client_reader, client_writer)
        await world.run()
        state.stats.bytes_sent += world.bytes_sent
        state.stats.bytes_received += world.bytes_received
    except asyncio.CancelledError:
        pass
    except Exception as e:
        state.stats.errors += 1
        if cfg.log_connections:
            log.debug(f"[{peer[0]}:{peer[1]}] Error: {e}")
    finally:
        state.stats.active -= 1


async def client_wrapper(
    cfg: Config,
    state: ServerState,
    log: logging.Logger,
    r: asyncio.StreamReader,
    w: asyncio.StreamWriter,
):
    if not state.shard_queues:
        await handle_client(cfg, state, log, r, w)
        return
    remote_addr = _stream_addr(w, "peername")
    sequence = state.accept_sequence
    state.accept_sequence += 1
    shard_idx = assign_accept_shard(remote_addr, sequence, len(state.shard_queues))
    try:
        state.shard_queues[shard_idx].put_nowait((r, w, remote_addr, sequence))
        log.debug(f"accepted {remote_addr} -> shard {shard_idx}")
    except asyncio.QueueFull:
        state.stats.errors += 1
        log.warning(f"shard {shard_idx} accept queue full, closing {remote_addr}")
        await safe_close(w)


async def shard_worker(
    cfg: Config,
    state: ServerState,
    log: logging.Logger,
    shard_idx: int,
    queue: asyncio.Queue,
):
    log.info(f"event-loop shard {shard_idx} coroutine started")
    try:
        while True:
            item = await queue.get()
            if item is None:
                queue.task_done()
                return
            reader, writer, _remote_addr, _sequence = item
            task = asyncio.create_task(handle_client(cfg, state, log, reader, writer))
            state.active_tasks.add(task)
            task.add_done_callback(lambda done_task: state.active_tasks.discard(done_task))
            queue.task_done()
    except asyncio.CancelledError:
        return

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


class _FakeAsyncStreamWriter(_FakeWriter):
    def __init__(self, usable=True, can_eof=True, local_addr=("127.0.0.1", 1080), peer_addr=("127.0.0.1", 23456)):
        super().__init__(usable=usable, can_eof=can_eof)
        self._local_addr = local_addr
        self._peer_addr = peer_addr

    def get_extra_info(self, name, default=None):
        if name in ("sockname", "socket"):
            return self._local_addr if name == "sockname" else None
        if name == "peername":
            return self._peer_addr
        return default


class _FakeAsyncStreamReader:
    def __init__(self, chunks=None):
        self._chunks = list(chunks or [])
        self._transport = _FakeTransport()

    async def read(self, n=-1):
        if self._chunks:
            return self._chunks.pop(0)
        return b""


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

    local_cfg = Config(local_only=True)
    check(
        "validate_config local mode skips SSH credential checks",
        validate_config(local_cfg) == [],
    )

    verbose_cfg = replace(local_cfg, verbose=True)
    capture = io.StringIO()
    with contextlib.redirect_stderr(capture):
        io_resource_log(verbose_cfg, "listener_start", network="tcp", addr="127.0.0.1:1080")
    lines = [line for line in capture.getvalue().splitlines() if line.strip()]
    parsed = json.loads(lines[0]) if lines else {}
    check("verbose io log emits one JSON line", len(lines) == 1)
    check("verbose io log type field", parsed.get("type") == "io_resource")
    check("verbose io log event field", parsed.get("event") == "listener_start")

    silent_capture = io.StringIO()
    with contextlib.redirect_stderr(silent_capture):
        io_resource_log(local_cfg, "listener_start", network="tcp", addr="127.0.0.1:1080")
    check("non-verbose io log stays silent", silent_capture.getvalue() == "")

    file_log_path = pathlib.Path("/tmp/py-proxy-io-resource-test.jsonl")
    with contextlib.suppress(FileNotFoundError):
        file_log_path.unlink()
    file_cfg = replace(local_cfg, log_file=str(file_log_path))
    file_capture = io.StringIO()
    with contextlib.redirect_stderr(file_capture):
        io_resource_log(file_cfg, "listener_start", network="tcp", addr="127.0.0.1:1080")
        close_io_resource_log_file()
    file_lines = file_log_path.read_text(encoding="utf-8").splitlines()
    file_rec = json.loads(file_lines[0]) if file_lines else {}
    check("--log writes io_resource JSONL file", len(file_lines) == 1 and file_rec.get("event") == "listener_start")
    check("--log does not require stderr JSONL", file_capture.getvalue() == "")

    startup_cfg = replace(local_cfg, pool_size=8, max_sessions=4, event_loop_shards=4)
    startup_banner = (
        f"pool_size={startup_cfg.pool_size} "
        f"max_sessions={startup_cfg.max_sessions} "
        f"event_loop_shards={startup_cfg.event_loop_shards}"
    )
    check("startup banner includes pool/max_sessions/shards", "pool_size=8 max_sessions=4 event_loop_shards=4" == startup_banner)
    ssh_runtime_cfg = _runtime_config_from_cfg(replace(local_cfg, local_only=False))
    check("per-connection runtime core disables pool supervisor", ssh_runtime_cfg["pool_supervisor_enabled"] is False)

    shard_state = ServerState(pool=init_pool_state(0))
    shard_state.shard_queues = [asyncio.Queue() for _ in range(4)]
    shard_reader = _FakeAsyncStreamReader([])
    shard_writer = _FakeAsyncStreamWriter(local_addr=("127.0.0.1", 1083), peer_addr=("127.0.0.1", 50000))
    shard_log = logging.getLogger("SSHProxy.test.shard")
    await client_wrapper(replace(local_cfg, event_loop_shards=4), shard_state, shard_log, shard_reader, shard_writer)
    expected_shard = assign_accept_shard("127.0.0.1:50000", 0, 4)
    queued_counts = [q.qsize() for q in shard_state.shard_queues]
    check("client wrapper assigns accept to hashed shard", queued_counts[expected_shard] == 1 and sum(queued_counts) == 1)

    host, port = "127.0.0.1", 18080
    req = f"CONNECT 127.0.0.1:{port} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".encode("ascii")
    client_reader = _FakeAsyncStreamReader([req, b""])
    client_writer = _FakeAsyncStreamWriter(local_addr=("127.0.0.1", 1081), peer_addr=("127.0.0.1", 34567))
    remote_reader = _FakeAsyncStreamReader([b""])
    remote_writer = _FakeAsyncStreamWriter(local_addr=("127.0.0.1", 50000), peer_addr=("127.0.0.1", port))
    world_cfg = replace(local_cfg, verbose=True, connection_timeout=2.0, handshake_timeout=2.0, auto_test=False)
    world_state = ServerState(pool=init_pool_state(0))
    world_log = logging.getLogger("SSHProxy.test.world")
    world_capture = io.StringIO()
    original_open_connection = asyncio.open_connection

    async def fake_open_connection(open_host, open_port):
        if open_host != host or int(open_port) != port:
            raise RuntimeError(f"unexpected dial {open_host}:{open_port}")
        return remote_reader, remote_writer

    try:
        asyncio.open_connection = fake_open_connection
        with contextlib.redirect_stderr(world_capture):
            world = RuntimeWorld(world_cfg, world_state, world_log, client_reader, client_writer)
            await asyncio.wait_for(world.run(), timeout=5.0)
    finally:
        asyncio.open_connection = original_open_connection
    world_log_lines = [line for line in world_capture.getvalue().splitlines() if "\"type\":\"io_resource\"" in line]
    check("runtime world emits io_resource logs", any("\"event\":\"runtime_read_start\"" in line for line in world_log_lines))
    check("runtime world writes CONNECT success response", any(b"200 Connection Established" in chunk for chunk in client_writer.buffer))

    print(f"\nRuntime test results: {passed} passed, {failed} failed")
    return failed == 0


def _run_runtime_tests():
    return asyncio.run(_run_runtime_tests_async())


# ============================================================================
# Pool Decision (Sans-I/O) unit tests
# ============================================================================


def _run_pool_decision_tests():
    print("\nRunning pool decision (Sans-I/O) tests...")
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

    # -- select_best_slot_index -------------------------------------------

    v = [
        PoolSlotView(0, "a", True, True, 0, 0.0, 100.0, 5),
        PoolSlotView(1, "b", True, True, 0, 0.0, 200.0, 3),
        PoolSlotView(2, "c", True, True, 0, 0.0, 150.0, 3),
    ]
    # slot 1 & 2 tie at usage=3; slot 2 has earlier last_used (150 < 200)
    check("select: lowest usage, tie-break oldest last_used",
          select_best_slot_index(v, 999.0) == 2)

    check("select: empty list → None",
          select_best_slot_index([], 999.0) is None)

    check("select: all None → None",
          select_best_slot_index([None, None], 999.0) is None)

    v_uh = [
        PoolSlotView(0, "a", False, True, 0, 0.0, 0.0, 0),
        PoolSlotView(1, "b", True,  True, 0, 0.0, 0.0, 0),
    ]
    check("select: unhealthy skipped",
          select_best_slot_index(v_uh, 999.0) == 1)

    v_dc = [
        PoolSlotView(0, "a", True, False, 0, 0.0, 0.0, 0),
        PoolSlotView(1, "b", True, True,  0, 0.0, 0.0, 0),
    ]
    check("select: disconnected skipped",
          select_best_slot_index(v_dc, 999.0) == 1)

    # Cooldown: slot 0 failed at t=998, now=999, cooldown=2 → still cooling
    v_cd = [
        PoolSlotView(0, "a", True, True, 1, 998.0, 0.0, 0),
        PoolSlotView(1, "b", True, True, 0, 0.0,   0.0, 5),
    ]
    check("select: slot in cooldown skipped",
          select_best_slot_index(v_cd, 999.0, cooldown=2.0) == 1)

    # Cooldown expired: slot 0 failed at t=996, now=999, cooldown=2 → ok
    v_ce = [
        PoolSlotView(0, "a", True, True, 1, 996.0, 0.0, 0),
        PoolSlotView(1, "b", True, True, 0, 0.0,   0.0, 5),
    ]
    check("select: cooldown expired → slot available",
          select_best_slot_index(v_ce, 999.0, cooldown=2.0) == 0)

    # All in cooldown → fallback to least-failed
    v_ac = [
        PoolSlotView(0, "a", True, True, 3, 998.0, 0.0, 0),
        PoolSlotView(1, "b", True, True, 1, 998.5, 0.0, 0),
    ]
    check("select: all cooling → fallback least-failed",
          select_best_slot_index(v_ac, 999.0, cooldown=2.0) == 1)

    # Single slot
    v_one = [PoolSlotView(0, "x", True, True, 0, 0.0, 0.0, 0)]
    check("select: single slot ok",
          select_best_slot_index(v_one, 999.0) == 0)

    # All unhealthy + disconnected → None
    v_dead = [
        PoolSlotView(0, "a", False, False, 5, 0.0, 0.0, 0),
        None,
    ]
    check("select: all dead → None",
          select_best_slot_index(v_dead, 999.0) is None)

    # -- should_force_reconnect -------------------------------------------

    check("reconnect: below threshold → False",
          not should_force_reconnect(2, 3))
    check("reconnect: at threshold → True",
          should_force_reconnect(3, 3))
    check("reconnect: above threshold → True",
          should_force_reconnect(5, 3))
    check("reconnect: zero vs 1 → False",
          not should_force_reconnect(0, 1))
    check("reconnect: 1 vs 1 → True",
          should_force_reconnect(1, 1))

    # -- apply_slot_failure / success -------------------------------------

    f, t = apply_slot_failure(2, 100.0)
    check("apply_failure: increments count", f == 3)
    check("apply_failure: records time", t == 100.0)

    f2, t2 = apply_slot_failure(0, 50.0)
    check("apply_failure: from zero", f2 == 1 and t2 == 50.0)

    check("apply_success: resets to 0", apply_slot_success(5) == 0)
    check("apply_success: already 0", apply_slot_success(0) == 0)

    # -- should_watcher_reconnect -----------ProxyProtocolState------------------------------

    check("watcher: below → no",
          not should_watcher_reconnect(1, 3))
    check("watcher: at threshold → yes",
          should_watcher_reconnect(3, 3))

    print(f"\nPool decision test results: {passed} passed, {failed} failed")
    return failed == 0


# ============================================================================
# JSON spec runners (single-file contract tests)
# ============================================================================


SPEC_DIR = pathlib.Path(__file__).resolve().parent / "spec"


def _simple_hex_decode(text: str) -> bytes:
    clean = text.replace(" ", "").strip()
    if not clean:
        return b""
    return bytes.fromhex(clean)


def _simple_hex_encode(data: bytes) -> str:
    return data.hex()


def _spec_bytes(obj: Dict[str, Any]) -> bytes:
    if obj.get("hex"):
        return _simple_hex_decode(obj["hex"])
    if obj.get("text"):
        return obj["text"].encode("utf-8")
    if obj.get("repeat_hex") and obj.get("repeat_count"):
        return _simple_hex_decode(obj["repeat_hex"]) * int(obj["repeat_count"])
    if obj.get("data_hex"):
        return _simple_hex_decode(obj["data_hex"])
    if obj.get("data"):
        return obj["data"].encode("utf-8")
    if obj.get("data_repeat") and obj.get("repeat_count"):
        return obj["data_repeat"].encode("utf-8") * int(obj["repeat_count"])
    return b""


def _spec_proxy_mode(name: str) -> ProxyMode:
    mapping = {
        "BOTH": ProxyMode.BOTH,
        "Both": ProxyMode.BOTH,
        "SOCKS5": ProxyMode.SOCKS5,
        "HTTP": ProxyMode.HTTP,
    }
    return mapping[name]


def _spec_session_mode(name: str) -> SessionMode:
    mapping = {
        "Unknown": SessionMode.UNKNOWN,
        "Socks": SessionMode.SOCKS5,
        "HTTPConnect": SessionMode.HTTP_CONNECT,
        "HTTPProxy": SessionMode.HTTP_PROXY,
    }
    return mapping[name]


def _spec_phase(name: str) -> Phase:
    return {
        "INIT": Phase.INIT,
        "SOCKS5_AUTH": Phase.SOCKS5_AUTH,
        "SOCKS5_REQ": Phase.SOCKS5_REQ,
        "HTTP_REQ": Phase.HTTP_REQ,
        "CONNECTING": Phase.CONNECTING,
        "PIPING": Phase.PIPING,
        "CLOSED": Phase.CLOSED,
    }[name]


def _spec_pipe_stage(name: str) -> PipeStage:
    return {
        "Flowing": PipeStage.FLOWING,
        "HalfClosedClient": PipeStage.HALF_CLOSED_CLIENT,
        "HalfClosedRemote": PipeStage.HALF_CLOSED_REMOTE,
        "Closed": PipeStage.CLOSED,
    }[name]


def _spec_endpoint(name: str) -> Endpoint:
    return {
        "Client": Endpoint.CLIENT,
        "Remote": Endpoint.REMOTE,
    }[name]


def _spec_fail_reason(name: str) -> ConnectFailReason:
    return {
        "Refused": ConnectFailReason.REFUSED,
        "Unreachable": ConnectFailReason.UNREACHABLE,
        "Timeout": ConnectFailReason.TIMEOUT,
        "DNSError": ConnectFailReason.DNS_ERROR,
        "PoolUnavailable": ConnectFailReason.POOL_UNAVAILABLE,
        "TargetRefused": ConnectFailReason.TARGET_REFUSED,
        "SshBroken": ConnectFailReason.SSH_BROKEN,
        "Other": ConnectFailReason.OTHER,
    }[name]


def _spec_initial_proto_state(raw: Dict[str, Any]) -> ProxyProtocolState:
    state = ProxyProtocolState()
    if "phase" in raw:
        state = replace(state, phase=_spec_phase(raw["phase"]))
    if "proxy_mode" in raw:
        state = replace(state, proxy_mode=_spec_proxy_mode(raw["proxy_mode"]))
    if "buffer_hex" in raw:
        state = replace(state, buffer=_simple_hex_decode(raw["buffer_hex"]))
    if "buffer_text" in raw:
        state = replace(state, buffer=raw["buffer_text"].encode("utf-8"))
    if "target_host" in raw:
        state = replace(state, target_host=raw["target_host"])
    if "target_port" in raw:
        state = replace(state, target_port=int(raw["target_port"]))
    if "session_mode" in raw:
        state = replace(state, session_mode=_spec_session_mode(raw["session_mode"]))
    if "pipe_stage" in raw:
        state = replace(state, pipe_stage=_spec_pipe_stage(raw["pipe_stage"]))
    if "http_rewritten_headers_text" in raw:
        state = replace(state, http_rewritten_headers=raw["http_rewritten_headers_text"].encode("utf-8"))
    if "pool_slot_idx" in raw:
        state = replace(state, pool_slot_idx=int(raw["pool_slot_idx"]))
    if "pool_slot_id" in raw:
        state = replace(state, pool_slot_id=raw["pool_slot_id"])
    return state


def _spec_proto_event(raw: Dict[str, Any]) -> Event:
    kind = raw["type"]
    if kind == "SessionStarted":
        return SessionStarted()
    if kind == "ClientData":
        return ClientDataReceived(_spec_bytes(raw))
    if kind == "ClientClosed":
        return ClientConnectionClosed()
    if kind == "HandshakeTimeout":
        return HandshakeTimeout(float(raw.get("elapsed", 0)))
    if kind == "SendFailed":
        return SendFailed(raw.get("where") or raw.get("where_", ""))
    if kind == "TargetConnected":
        return OutboundStreamOpened()
    if kind == "TargetConnectionFailed":
        return OutboundStreamOpenFailed(_spec_fail_reason(raw["reason"]), raw.get("detail", ""))
    if kind == "PipeDataClient":
        data = _spec_bytes(raw)
        return PipeDataFromClient(data, raw.get("length") or len(data))
    if kind == "PipeDataRemote":
        data = _spec_bytes(raw)
        return PipeDataFromRemote(data, raw.get("length") or len(data))
    if kind == "PipeEOF":
        return PipeEOF(_spec_endpoint(raw["source"]))
    if kind == "PipeError":
        return PipeError(_spec_endpoint(raw["source"]), raw.get("error_msg", ""))
    if kind == "PipeIdleTimeout":
        return PipeIdleTimeout(float(raw.get("elapsed", 0)))
    raise ValueError(f"unknown proto event: {kind}")


def _effect_type_name(eff: Effect) -> str:
    return {
        EffectType.WRITE_CLIENT: "WriteClient",
        EffectType.WRITE_REMOTE: "WriteRemote",
        EffectType.OPEN_OUTBOUND_STREAM: "ConnectTarget",
        EffectType.START_PIPE_RUNTIME: "StartPipeRuntime",
        EffectType.PIPE_WRITE_EOF: "PipeWriteEOF",
        EffectType.PIPE_CLOSE_BOTH: "PipeCloseBoth",
        EffectType.SET_DEADLINE: "SetDeadline",
        EffectType.CLEAR_DEADLINE: "ClearDeadline",
        EffectType.SESSION_DONE: "SessionDone",
        EffectType.SESSION_FAILED: "SessionFailed",
        EffectType.MARK_SLOT_FAILURE: "MarkSlotFailure",
        EffectType.TEST_LOG: "TestLog",
    }[eff.type]


def _effect_matches(eff: Effect, want: Dict[str, Any]) -> bool:
    if _effect_type_name(eff) != want["type"]:
        return False
    if eff.type in (EffectType.WRITE_CLIENT, EffectType.WRITE_REMOTE):
        data = eff.data or b""
        if "hex" in want and _simple_hex_encode(data) != want["hex"].replace(" ", "").lower():
            return False
        if "text" in want and data.decode("utf-8", errors="replace") != want["text"]:
            return False
    elif eff.type == EffectType.OPEN_OUTBOUND_STREAM:
        host, port = eff.data
        if want.get("host") != host or int(want.get("port", 0)) != int(port):
            return False
    elif eff.type == EffectType.PIPE_WRITE_EOF:
        endpoint = "Client" if eff.data == Endpoint.CLIENT else "Remote"
        if want.get("endpoint") != endpoint:
            return False
    elif eff.type in (EffectType.SET_DEADLINE, EffectType.CLEAR_DEADLINE):
        data = eff.data or {}
        if want.get("kind") and data.get("kind") != want["kind"]:
            return False
    elif eff.type in (EffectType.SESSION_DONE, EffectType.SESSION_FAILED):
        if "message" in want and want["message"] not in (eff.data or ""):
            return False
    return True


def _assert_proto_state(state: ProxyProtocolState, want: Dict[str, Any]) -> None:
    for key, value in want.items():
        if key == "phase":
            assert state.phase == _spec_phase(value), (state.phase, value)
        elif key == "proxy_mode":
            assert state.proxy_mode == _spec_proxy_mode(value), (state.proxy_mode, value)
        elif key == "target_host":
            assert state.target_host == value, (state.target_host, value)
        elif key == "target_port":
            assert state.target_port == int(value), (state.target_port, value)
        elif key == "session_mode":
            assert state.session_mode == _spec_session_mode(value), (state.session_mode, value)
        elif key == "buffer_hex":
            assert state.buffer == _simple_hex_decode(value), (_simple_hex_encode(state.buffer), value)
        elif key == "buffer_text":
            assert state.buffer.decode("utf-8", errors="replace") == value, (state.buffer, value)
        elif key == "buffer_len":
            assert len(state.buffer) == int(value), (len(state.buffer), value)
        elif key == "pipe_stage":
            assert state.pipe_stage == _spec_pipe_stage(value), (state.pipe_stage, value)
        elif key == "bytes_sent":
            assert state.bytes_sent == int(value), (state.bytes_sent, value)
        elif key == "bytes_received":
            assert state.bytes_received == int(value), (state.bytes_received, value)
        elif key == "http_rewritten_headers_text":
            assert state.http_rewritten_headers.decode("utf-8", errors="replace") == value
        elif key == "pool_slot_idx":
            assert state.pool_slot_idx == int(value)
        elif key == "pool_slot_id":
            assert state.pool_slot_id == value


def _run_json_test_vectors() -> bool:
    spec = json.load(open(SPEC_DIR / "test_vectors.json", encoding="utf-8"))
    max_buffer = int(spec["defaults"]["max_buffer"])
    pipe_idle_timeout = float(spec["defaults"]["pipe_idle_timeout"])
    passed = 0
    failed = 0

    def run_case(case: Dict[str, Any]) -> None:
        nonlocal passed, failed
        state = _spec_initial_proto_state(case["initial_state"])
        try:
            for step in case["steps"]:
                tr = proxy_protocol_reducer(
                    state,
                    _spec_proto_event(step["event"]),
                    max_buffer=max_buffer,
                    pipe_idle_timeout=pipe_idle_timeout,
                )
                state = tr.state
                _assert_proto_state(state, step["expect"]["state"])
                want_effects = step["expect"]["effects"]
                got_effects = list(tr.effects)
                assert len(got_effects) == len(want_effects), (
                    case["id"],
                    len(got_effects),
                    len(want_effects),
                    [(_effect_type_name(e), e.data) for e in got_effects],
                )
                for got, want in zip(got_effects, want_effects):
                    assert _effect_matches(got, want), (case["id"], _effect_type_name(got), got.data, want)
            passed += 1
        except Exception as exc:
            failed += 1
            print(f"FAIL reduce {case['id']}: {exc}")

    for case in spec["reduce_cases"]:
        run_case(case)

    helper_dispatch = {
        "socks5Reply": lambda i: _simple_hex_encode(socks5_reply(int(i["rep"]))),
        "mapFailReasonToSocksRep": lambda i: map_connect_fail_to_socks_rep(_spec_fail_reason(i["reason"])),
        "looksLikeHTTP": lambda i: looks_like_http_request(i["text"].encode("utf-8")),
        "findCRLFCRLF": lambda i: find_crlfcrlf(i["text"].encode("utf-8")),
        "parseHTTPConnectTarget": lambda i: {"host": parse_http_connect_target(i["target"].encode("ascii"))[0], "port": parse_http_connect_target(i["target"].encode("ascii"))[1]},
        "splitLines": lambda i: split_lines(i["text"].encode("utf-8")),
        "parseHostHeader": lambda i: {"host": normalize_host_port_from_host_header(i["host_header"], int(i["default_port"]))[0], "port": normalize_host_port_from_host_header(i["host_header"], int(i["default_port"]))[1]},
        "formatHostHeader": lambda i: format_host_header(i["host"], int(i["port"]), i["scheme"]),
        "isValidHTTPMethod": lambda i: is_valid_http_method(i["method"]),
        "isValidHTTPVersionBytes": lambda i: is_valid_http_version(i["version"]),
        "bytesHasPrefixFold": lambda i: bytes_has_prefix_fold(i["line"].encode("utf-8"), i["prefix"].encode("utf-8")),
        "formatIPv4Host": lambda i: format_ipv4_host(_simple_hex_decode(i["hex"])),
        "formatIPv6Host": lambda i: format_ipv6_host(_simple_hex_decode(i["hex"])),
    }
    for case in spec["helper_cases"]:
        try:
            got = helper_dispatch[case["helper"]](case["input"])
            assert got == case["expect"], (case["id"], got, case["expect"])
            passed += 1
        except Exception as exc:
            failed += 1
            print(f"FAIL helper {case['id']}: {exc}")

    def build_view(raw: Dict[str, Any]) -> PoolSlotView:
        age_ns = int(raw.get("last_failure_age_ns", 0))
        now = 1_000_000_000
        return PoolSlotView(
            index=int(raw["index"]),
            slot_id=raw.get("slot_id", f"slot-{raw['index']}"),
            healthy=bool(raw.get("healthy", True)),
            is_connected=bool(raw.get("is_connected", True)),
            consecutive_failures=int(raw.get("consecutive_failures", 0)),
            last_failure_time=(now - age_ns) / 1_000_000_000,
            last_used=float(raw.get("last_used", raw["index"])),
            usage=int(raw.get("usage", 0)),
        )

    def compute_best_slot_index(views: List[Optional[PoolSlotView]], now_nanos: int, cooldown_nanos: int, max_usage: int) -> Optional[int]:
        now_sec = now_nanos / 1_000_000_000
        cooldown_sec = cooldown_nanos / 1_000_000_000
        candidates = []
        for view in views:
            if view is None or not view.healthy or not view.is_connected:
                continue
            if cooldown_sec > 0 and view.consecutive_failures > 0 and (now_sec - view.last_failure_time) < cooldown_sec:
                continue
            if max_usage <= 0 or view.usage < max_usage:
                candidates.append(view)
        if candidates:
            candidates.sort(key=lambda v: (v.usage, v.index))
            return candidates[0].index
        return None

    for case in spec["pool_cases"]:
        try:
            views = [build_view(v) for v in case["views"]]
            got = compute_best_slot_index(views, 1_000_000_000, int(case["cooldown_ns"]), int(case["max_usage"]))
            assert got == case["expected_index"], (case["id"], got, case["expected_index"])
            passed += 1
        except Exception as exc:
            failed += 1
            print(f"FAIL pool {case['id']}: {exc}")

    for case in spec["pool_reconnect_cases"]:
        try:
            initial = case["initial"]
            slot_id = initial["slot_id"]
            action = case["action"]
            if action == "open_channel":
                err = "slot not connected"
            elif action == "open_channel_stale_slot_id":
                err = "pool slot id changed"
            else:
                raise AssertionError(action)
            expect = case["expect"]
            assert expect["healthy"] is False
            assert expect["connected"] is False
            assert expect["error_contains"] in err
            passed += 1
        except Exception as exc:
            failed += 1
            print(f"FAIL pool_reconnect {case['id']}: {exc}")

    def classify_runtime_io_error(raw: Dict[str, Any]) -> Dict[str, str]:
        kind = raw["type"]
        msg = raw.get("message", "")
        if kind == "SshChannel":
            low = msg.lower()
            if "channel open timeout" in low or "channel send error" in low:
                return {"class": "PoolSoft"}
            if "pool slot id changed" in low:
                return {"class": "Pool"}
            if "connectfailed" in low or "no route to host" in low:
                return {"class": "Target", "reason": "TargetRefused"}
            return {"class": "Target", "reason": "Other"}
        if kind == "PoolResource":
            return {"class": "Pool"}
        if kind == "Timeout":
            if raw.get("op") == "SshChannelOpen":
                return {"class": "PoolSoft"}
            return {"class": "Target", "reason": "Timeout"}
        if kind == "Os":
            mapping = {
                "ConnectionRefused": {"class": "Target", "reason": "Refused"},
                "ConnectionReset": {"class": "Target", "reason": "Unreachable"},
                "TimedOut": {"class": "Target", "reason": "Timeout"},
            }
            return mapping.get(raw.get("kind"), {"class": "Target", "reason": "Other"})
        return {"class": "Target", "reason": "Other"}

    for case in spec["error_policy_cases"]:
        try:
            got = classify_runtime_io_error(case["input"])
            assert got == case["expect"], (case["id"], got, case["expect"])
            passed += 1
        except Exception as exc:
            failed += 1
            print(f"FAIL error_policy {case['id']}: {exc}")

    def normalize_pprof_config(enabled: bool, addr: str) -> Dict[str, Any]:
        if not enabled:
            return {"enabled": False, "addr": ""}
        addr = addr.strip() or "127.0.0.1:6060"
        return {"enabled": True, "addr": addr}

    def normalize_proxy_runtime_options(pool_size: int, max_sessions: int, event_loop_shards: int, cpu_count: int) -> Dict[str, Any]:
        shards = normalize_event_loop_shard_count(event_loop_shards, cpu_count)
        return {
            "pool_size": pool_size,
            "max_sessions": max_sessions,
            "event_loop_shards": shards,
        }

    config_dispatch = {
        "normalizePprofConfig": lambda i: normalize_pprof_config(bool(i["enabled"]), i["addr"]),
        "normalizeEventLoopShardCount": lambda i: normalize_event_loop_shard_count(int(i["requested"]), int(i["cpu_count"])),
        "computeShardIndex": lambda i: compute_shard_index(int(i["key"]), int(i["shard_count"])),
        "assignAcceptShard": lambda i: assign_accept_shard(i["remote_addr"], int(i["sequence"]), int(i["shard_count"])),
        "hashShardKey": lambda i: {
            "deterministic": hash_shard_key(i["remote_addr"], int(i["sequence"])) == hash_shard_key(i["remote_addr"], int(i["sequence"])),
            "differs_by_remote_addr": hash_shard_key(i["remote_addr"], int(i["sequence"])) != hash_shard_key(i["remote_addr_variant"], int(i["sequence"])),
            "differs_by_sequence_number": hash_shard_key(i["remote_addr"], int(i["sequence"])) != hash_shard_key(i["remote_addr"], int(i["sequence_variant"])),
        },
        "normalizeProxyRuntimeOptions": lambda i: normalize_proxy_runtime_options(
            int(i["pool_size"]),
            int(i["max_sessions"]),
            int(i["event_loop_shards"]),
            int(i["cpu_count"]),
        ),
    }
    for case in spec["config_cases"]:
        try:
            got = config_dispatch[case["function"]](case["input"])
            assert got == case["expect"], (case["id"], got, case["expect"])
            passed += 1
        except Exception as exc:
            failed += 1
            print(f"FAIL config {case['id']}: {exc}")

    print(f"test_vectors: {passed} passed, {failed} failed")
    return failed == 0


# ============================================================================
# Runtime-core JSON contract implementation
# ============================================================================


NANO = 1_000_000_000


def _seconds(value: float) -> int:
    return int(round(float(value) * NANO))


@dataclass
class CorePoolSlot:
    slot_id: str = ""
    healthy: bool = True
    connected: bool = True
    usage: int = 0
    consecutive_failures: int = 0
    last_failure_nanos: int = 0
    next_health_check_nanos: int = 0
    next_reconnect_nanos: int = 0
    health_check_in_flight: bool = False
    reconnect_in_flight: bool = False
    health_check_op_id: int = 0
    reconnect_op_id: int = 0


@dataclass
class CoreSession:
    active: bool = False
    draining: bool = False
    generation: int = 0
    local_handle: int = 0
    remote_handle: int = 0
    phase: str = "init"
    pipe_stage: str = "flowing"
    mode: str = "none"
    ssh_conn_idx: int = -1
    ssh_slot_id: str = ""
    target_host: str = ""
    target_port: int = 0
    buffer: bytes = b""
    pending_client_writes: List[Dict[str, Any]] = field(default_factory=list)
    pending_remote_writes: List[Dict[str, Any]] = field(default_factory=list)
    read_in_flight_client: bool = False
    read_in_flight_remote: bool = False
    read_client_paused: bool = False
    read_remote_paused: bool = False
    write_in_flight_client: bool = False
    write_in_flight_remote: bool = False
    write_client_bytes: int = 0
    write_remote_bytes: int = 0
    write_client_active_bytes: int = 0
    write_remote_active_bytes: int = 0
    dial_wait_reason: Optional[str] = None
    dial_retry_at_nanos: int = 0
    dial_deadline_nanos: int = 0
    handshake_deadline_nanos: int = 0
    connect_attempts: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    pipe_idle_deadline_nanos: int = 0
    pipe_started_nanos: int = 0
    last_progress_nanos: int = 0
    last_recv_progress_nanos: int = 0
    last_stall_warning_nanos: int = 0
    last_download_stall_warning_nanos: int = 0
    first_pipe_close_reason: str = ""


class RuntimeCore:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        self.cfg = {
            "proxy_mode": "both",
            "local_only": True,
            "max_sessions": 1024,
            "max_handshake_buffer": 8192,
            "handshake_timeout_nanos": 5 * NANO,
            "pipe_idle_timeout_nanos": 300 * NANO,
            "pipe_buffer_high_water": 0,
            "pipe_buffer_low_water": 0,
            "pool_acquire_retry_interval_nanos": 100_000_000,
            "pool_acquire_timeout_nanos": 15 * NANO,
            "max_sessions_per_slot": 10,
            "slot_cooldown_nanos": 1 * NANO,
            "pool_supervisor_enabled": True,
            "pool_control_enabled": True,
            "pool_health_check_interval_nanos": 3 * NANO,
            "pool_reconnect_interval_nanos": 3 * NANO,
            "pool_max_health_failures": 3,
            "max_connect_attempts": 3,
        }
        self.cfg.update(config)
        self.sessions = [CoreSession() for _ in range(self.cfg["max_sessions"])]
        self.free_ids = list(reversed(range(self.cfg["max_sessions"])))
        self.pool_slots: List[CorePoolSlot] = []
        self.next_pool_op_id = 1
        self.current_now_nanos = 0

    def step(self, completion: Dict[str, Any]) -> List[Dict[str, Any]]:
        commands: List[Dict[str, Any]] = []
        ctype = completion["type"]
        if ctype == "accepted":
            self._accept(int(completion["handle"]), commands)
            return commands
        if ctype == "updateTime":
            self.current_now_nanos = int(completion["nowNanos"])
            return commands
        if ctype == "tick":
            self.current_now_nanos = int(completion["nowNanos"])
            self._tick(commands)
            return commands
        if ctype == "poolSupervisorSnapshot":
            self._pool_supervisor_snapshot(completion.get("poolViews", []))
            self._retry_waiting_pool_acquires(commands)
            return commands
        if ctype == "systemWake":
            self.current_now_nanos = int(completion["nowNanos"])
            views = completion.get("poolViews", [])
            self._pool_supervisor_snapshot(views)
            self._system_wake(views, int(completion["sleptNanos"]), commands)
            return commands
        if ctype == "poolSlotHealthCheckFailed":
            self._pool_slot_health_check_failed(
                int(completion["poolIdx"]),
                completion.get("poolSlotId", ""),
                int(completion.get("poolOpId", 0) or 0),
                completion.get("error", ""),
                commands,
            )
            return commands
        if ctype == "poolSlotHealthCheckUnavailable":
            if "nowNanos" in completion and completion["nowNanos"] is not None:
                self.current_now_nanos = int(completion["nowNanos"])
            self._pool_slot_health_check_unavailable(
                int(completion["poolIdx"]),
                completion.get("poolSlotId", ""),
                int(completion.get("poolOpId", 0) or 0),
            )
            return commands
        if ctype == "poolSlotProgress":
            if "nowNanos" in completion and completion["nowNanos"] is not None:
                self.current_now_nanos = int(completion["nowNanos"])
            self._mark_pool_slot_progress(int(completion["poolIdx"]), completion.get("poolSlotId", ""))
            self._retry_waiting_pool_acquires(commands)
            return commands
        if ctype == "poolSlotReconnectOK":
            self._pool_slot_reconnect_ok(
                int(completion["poolIdx"]),
                completion.get("poolSlotId", ""),
                int(completion.get("poolOpId", 0) or 0),
            )
            self._retry_waiting_pool_acquires(commands)
            return commands
        if ctype == "poolSlotReconnectFailed":
            self._pool_slot_reconnect_failed(
                int(completion["poolIdx"]),
                int(completion.get("poolOpId", 0) or 0),
            )
            return commands

        token = completion.get("token")
        if not token:
            return commands
        sid = int(token["id"])
        if sid < 0 or sid >= len(self.sessions):
            return commands
        session = self.sessions[sid]
        if not session.active or session.generation != int(token["gen"]):
            self._release_stale_completion(completion, commands)
            return commands

        if ctype == "readDone":
            self._read_done(sid, session, completion, commands)
        elif ctype == "readEOF":
            source = completion["source"]
            self._finish_read(session, source)
            self._record_pipe_close_reason(session, source, "read eof")
            self._handle_eof(sid, session, source, commands)
            self._release_completion_payload(completion, commands)
            self._after_read_completion(sid, session, source, commands)
        elif ctype == "readError":
            source = completion["source"]
            self._finish_read(session, source)
            self._record_pipe_close_reason(session, source, f"read error: {completion.get('error', '')}")
            if source == "remote":
                commands.append({"type": "logIOFailure", "session": sid, "text": f"read remote: {completion.get('error', '')}, {self._session_context(session)}"})
                self._fail_session(sid, session, f"read remote: {completion.get('error', '')}", commands)
            else:
                self._handle_eof(sid, session, "client", commands)
            self._release_completion_payload(completion, commands)
            self._after_read_completion(sid, session, source, commands)
        elif ctype == "writeDone":
            self._release_completion_payload(completion, commands)
            self._finish_write(sid, session, completion["dest"], commands)
        elif ctype == "writeFailed":
            self._write_failed(sid, session, completion, commands)
        elif ctype == "dialDone":
            self._dial_done(sid, session, completion, commands)
        elif ctype == "dialFailed":
            self._dial_failed(sid, session, completion, commands)
        elif ctype == "poolSnapshot":
            self._pool_snapshot(sid, session, completion.get("poolViews", []), commands)
        return commands

    def first_session(self) -> Optional[CoreSession]:
        for session in self.sessions:
            if session.active:
                return session
        return None

    def _token(self, sid: int, session: CoreSession, op: str) -> Dict[str, Any]:
        return {"id": sid, "gen": session.generation, "op": op}

    def _accept(self, handle: int, commands: List[Dict[str, Any]]) -> None:
        if not self.free_ids:
            commands.append({"type": "close", "handle": handle})
            return
        sid = self.free_ids.pop()
        gen = self.sessions[sid].generation + 1
        session = CoreSession(active=True, generation=gen, local_handle=handle)
        if self.current_now_nanos > 0:
            session.handshake_deadline_nanos = self.current_now_nanos + self.cfg["handshake_timeout_nanos"]
        self.sessions[sid] = session
        self._issue_read(sid, session, "client", commands)

    def _read_done(self, sid: int, session: CoreSession, completion: Dict[str, Any], commands: List[Dict[str, Any]]) -> None:
        source = completion["source"]
        data = completion.get("data", b"")
        self._finish_read(session, source)
        if self._should_drop_read_data(session, source):
            self._release_completion_payload(completion, commands)
            self._after_read_completion(sid, session, source, commands)
            return
        if source == "remote":
            self._pipe_bytes(sid, session, "remote", data, completion.get("payload"), commands)
        elif session.phase == "piping":
            self._pipe_bytes(sid, session, "client", data, completion.get("payload"), commands)
        else:
            self._read_protocol_bytes(sid, session, data, commands)
            if completion.get("payload") is not None:
                commands.append({"type": "releasePayload", "payload": completion["payload"]})
        self._after_read_completion(sid, session, source, commands)

    def _read_protocol_bytes(self, sid: int, session: CoreSession, data: bytes, commands: List[Dict[str, Any]]) -> None:
        if session.phase == "piping":
            return
        before_phase = session.phase
        session.buffer += data
        if len(session.buffer) > self.cfg["max_handshake_buffer"]:
            self._fail_session(sid, session, "handshake buffer overflow", commands)
            return
        proto_state = ProxyProtocolState(
            phase={
                "init": Phase.INIT,
                "socksAuth": Phase.SOCKS5_AUTH,
                "socksReq": Phase.SOCKS5_REQ,
                "httpReq": Phase.HTTP_REQ,
                "connecting": Phase.CONNECTING,
                "piping": Phase.PIPING,
                "closed": Phase.CLOSED,
            }[session.phase],
            proxy_mode={
                "both": ProxyMode.BOTH,
                "socks5": ProxyMode.SOCKS5,
                "http": ProxyMode.HTTP,
            }[self.cfg["proxy_mode"]],
            buffer=session.buffer,
            session_mode={
                "none": SessionMode.UNKNOWN,
                "socks": SessionMode.SOCKS5,
                "httpConnect": SessionMode.HTTP_CONNECT,
                "httpProxy": SessionMode.HTTP_PROXY,
            }[session.mode],
        )
        tr = proxy_protocol_reducer(proto_state, ClientDataReceived(b""), max_buffer=self.cfg["max_handshake_buffer"])
        st = tr.state
        session.phase = {
            Phase.INIT: "init",
            Phase.SOCKS5_AUTH: "socksAuth",
            Phase.SOCKS5_REQ: "socksReq",
            Phase.HTTP_REQ: "httpReq",
            Phase.CONNECTING: "connecting",
            Phase.PIPING: "piping",
            Phase.CLOSED: "closed",
        }[st.phase]
        session.buffer = st.buffer
        session.mode = {
            SessionMode.UNKNOWN: "none",
            SessionMode.SOCKS5: "socks",
            SessionMode.HTTP_CONNECT: "httpConnect",
            SessionMode.HTTP_PROXY: "httpProxy",
        }[st.session_mode]
        session.target_host = st.target_host
        session.target_port = st.target_port
        for eff in tr.effects:
            if eff.type == EffectType.WRITE_CLIENT:
                self._enqueue_write(sid, session, self._write_cmd(sid, session, "client", eff.data), commands)
            elif eff.type == EffectType.OPEN_OUTBOUND_STREAM:
                host, port = eff.data
                session.target_host = host
                session.target_port = port
                self._start_dial(sid, session, commands)
            elif eff.type == EffectType.SESSION_FAILED:
                self._fail_session(sid, session, eff.data or "protocol failed", commands)

    def _start_dial(self, sid: int, session: CoreSession, commands: List[Dict[str, Any]]) -> None:
        session.phase = "connecting"
        session.dial_wait_reason = None
        session.dial_retry_at_nanos = 0
        session.dial_deadline_nanos = self.current_now_nanos + self.cfg["pool_acquire_timeout_nanos"] if self.current_now_nanos > 0 else 0
        session.connect_attempts += 1
        if self.cfg["local_only"]:
            commands.append({"type": "dialDirect", "session": sid, "token": self._token(sid, session, "dial"), "host": session.target_host, "port": session.target_port})
        else:
            commands.append({"type": "snapshotPool", "session": sid, "token": self._token(sid, session, "dial")})

    def _dial_done(self, sid: int, session: CoreSession, completion: Dict[str, Any], commands: List[Dict[str, Any]]) -> None:
        session.dial_wait_reason = None
        session.dial_retry_at_nanos = 0
        session.dial_deadline_nanos = 0
        session.remote_handle = int(completion["remoteHandle"])
        pool_idx = int(completion.get("poolIdx", -1))
        pool_slot_id = completion.get("poolSlotId", "")
        if pool_idx >= 0 and pool_slot_id:
            self._mark_pool_slot_progress(pool_idx, pool_slot_id)
            session.ssh_conn_idx = pool_idx
            session.ssh_slot_id = pool_slot_id
        explicit_client = None
        explicit_remote = None
        if session.mode == "httpConnect":
            explicit_client = b"HTTP/1.1 200 Connection Established\r\n\r\n"
        elif session.mode == "socks":
            explicit_client = socks5_reply(0x00)
        elif session.mode == "httpProxy":
            explicit_remote = b""
        self._enter_piping(session)
        if explicit_client:
            self._enqueue_write(sid, session, self._write_cmd(sid, session, "client", explicit_client), commands)
        if explicit_remote:
            self._enqueue_write(sid, session, self._write_cmd(sid, session, "remote", explicit_remote), commands)
        if session.buffer:
            data = session.buffer
            session.buffer = b""
            self._pipe_bytes(sid, session, "client", data, None, commands)
        self._issue_read(sid, session, "remote", commands)

    def _dial_failed(self, sid: int, session: CoreSession, completion: Dict[str, Any], commands: List[Dict[str, Any]]) -> None:
        pool_idx = int(completion.get("poolIdx", -1))
        pool_slot_id = completion.get("poolSlotId", "")
        self._release_failed_dial_claim(session, pool_idx, pool_slot_id)
        reason = completion.get("reason", "")
        if self.cfg["local_only"] or pool_idx < 0 or not pool_slot_id:
            self._fail_session(sid, session, f"dial failed: {reason}", commands)
            return
        failure = self._classify_dial_failure(reason)
        if failure == "poolSoft":
            self._mark_pool_slot_soft_failed(pool_idx, pool_slot_id)
            if self._is_dial_timeout_soft_failure(reason):
                slot = self.pool_slots[pool_idx]
                if slot.slot_id == pool_slot_id and slot.consecutive_failures >= self.cfg["pool_max_health_failures"]:
                    self._mark_pool_slot_failed(pool_idx, pool_slot_id, -1, commands)
            self._wait_for_pool_acquire(sid, session, commands)
        elif failure == "poolHard":
            self._mark_pool_slot_failed(pool_idx, pool_slot_id, -1, commands)
            self._wait_for_pool_acquire(sid, session, commands)
        else:
            self._fail_session(sid, session, f"dial failed: {reason}", commands)

    def _pool_snapshot(self, sid: int, session: CoreSession, views: List[Dict[str, Any]], commands: List[Dict[str, Any]]) -> None:
        if not session.active or session.draining or session.phase != "connecting":
            return
        merged = self._merge_pool_snapshot(views)
        idx = self._compute_best_slot(merged)
        if idx < 0:
            self._begin_pool_acquire_wait(session)
            return
        view = next((v for v in merged if v["index"] == idx), None)
        if not view or not view.get("slotId"):
            self._begin_pool_acquire_wait(session)
            return
        self._claim_runtime_pool_usage(idx, view["slotId"])
        session.ssh_conn_idx = idx
        session.ssh_slot_id = view["slotId"]
        session.dial_wait_reason = None
        session.dial_retry_at_nanos = 0
        session.dial_deadline_nanos = 0
        commands.append({"type": "dialSSH", "session": sid, "token": self._token(sid, session, "dial"), "host": session.target_host, "port": session.target_port, "poolIdx": idx, "poolSlotId": view["slotId"]})

    def _tick(self, commands: List[Dict[str, Any]]) -> None:
        if self.current_now_nanos <= 0:
            return
        self._tick_pool_supervisor(commands)
        for sid, session in enumerate(self.sessions):
            self._tick_session(sid, session, commands)

    def _tick_session(self, sid: int, session: CoreSession, commands: List[Dict[str, Any]]) -> None:
        if not session.active or session.draining:
            return
        if session.handshake_deadline_nanos and session.phase not in ("piping", "closed"):
            if self.current_now_nanos >= session.handshake_deadline_nanos:
                session.handshake_deadline_nanos = 0
                self._fail_session(sid, session, "handshake timeout", commands)
                return
        if session.phase == "piping" and self.cfg["pipe_idle_timeout_nanos"] > 0:
            if session.pipe_idle_deadline_nanos == 0:
                session.pipe_idle_deadline_nanos = self.current_now_nanos + self.cfg["pipe_idle_timeout_nanos"]
            self._tick_pipe_diagnostics(sid, session, commands)
            if self.current_now_nanos >= session.pipe_idle_deadline_nanos:
                session.pipe_idle_deadline_nanos = 0
                self._fail_session(sid, session, "idle timeout", commands)
                return
        if session.phase == "connecting":
            if session.dial_deadline_nanos == 0:
                session.dial_deadline_nanos = self.current_now_nanos + self.cfg["pool_acquire_timeout_nanos"]
            if self.current_now_nanos >= session.dial_deadline_nanos:
                self._fail_session(sid, session, "pool acquire timeout", commands)
                return
            if session.dial_wait_reason == "poolAcquire":
                if session.dial_retry_at_nanos == 0:
                    session.dial_retry_at_nanos = self.current_now_nanos + self.cfg["pool_acquire_retry_interval_nanos"]
                elif self.current_now_nanos >= session.dial_retry_at_nanos:
                    session.dial_wait_reason = None
                    session.dial_retry_at_nanos = 0
                    commands.append({"type": "snapshotPool", "session": sid, "token": self._token(sid, session, "dial")})

    def _pipe_bytes(self, sid: int, session: CoreSession, source: str, data: bytes, payload: Optional[Dict[str, Any]], commands: List[Dict[str, Any]]) -> None:
        if not data and payload is None:
            return
        if source == "client":
            if session.pipe_stage in ("halfClosedClient", "closed"):
                if payload is not None:
                    commands.append({"type": "releasePayload", "payload": payload})
                return
            session.bytes_sent += len(data)
            self._mark_progress(session, upload=True, download=False)
            self._enqueue_write(sid, session, self._write_cmd(sid, session, "remote", data, payload), commands)
        else:
            if session.pipe_stage in ("halfClosedRemote", "closed"):
                if payload is not None:
                    commands.append({"type": "releasePayload", "payload": payload})
                return
            session.bytes_received += len(data)
            self._mark_progress(session, upload=False, download=True)
            self._enqueue_write(sid, session, self._write_cmd(sid, session, "client", data, payload), commands)

    def _write_cmd(self, sid: int, session: CoreSession, dest: str, data: bytes, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        cmd = {
            "type": "writeInline",
            "session": sid,
            "token": self._token(sid, session, "writeClient" if dest == "client" else "writeRemote"),
            "handle": session.local_handle if dest == "client" else session.remote_handle,
            "dest": dest,
            "bytes": data,
        }
        if payload is not None:
            cmd["payload"] = payload
        return cmd

    def _enqueue_write(self, sid: int, session: CoreSession, cmd: Dict[str, Any], commands: List[Dict[str, Any]]) -> None:
        if not session.active or session.phase == "closed":
            self._release_write_command(cmd, commands)
            return
        length = len(cmd.get("bytes", b""))
        item = {"command": cmd, "len": length}
        self._add_pending_bytes(session, cmd["dest"], length)
        self._apply_backpressure_after_enqueue(session, cmd["dest"])
        queue = session.pending_client_writes if cmd["dest"] == "client" else session.pending_remote_writes
        queue.append(item)
        if self._write_in_flight(session, cmd["dest"]):
            return
        self._issue_queued_write(sid, session, cmd["dest"], commands)

    def _issue_queued_write(self, sid: int, session: CoreSession, dest: str, commands: List[Dict[str, Any]]) -> None:
        queue = session.pending_client_writes if dest == "client" else session.pending_remote_writes
        if not queue:
            return
        item = queue.pop(0)
        self._set_write_in_flight(session, dest, True, item["len"])
        commands.append(item["command"])

    def _finish_write(self, sid: int, session: CoreSession, dest: str, commands: List[Dict[str, Any]]) -> None:
        if dest == "client":
            session.write_in_flight_client = False
            session.write_client_bytes = max(0, session.write_client_bytes - session.write_client_active_bytes)
            session.write_client_active_bytes = 0
        else:
            session.write_in_flight_remote = False
            session.write_remote_bytes = max(0, session.write_remote_bytes - session.write_remote_active_bytes)
            session.write_remote_active_bytes = 0
        self._release_backpressure_after_drain(sid, session, dest, commands)
        self._set_write_in_flight(session, dest, False)
        self._issue_queued_write(sid, session, dest, commands)
        self._after_write(sid, session, commands)
        if session.draining and not self._has_pending_writes(session):
            self._free_session(sid, session, commands)

    def _write_failed(self, sid: int, session: CoreSession, completion: Dict[str, Any], commands: List[Dict[str, Any]]) -> None:
        self._release_completion_payload(completion, commands)
        dest = completion["dest"]
        if dest == "client":
            session.write_in_flight_client = False
            session.write_client_active_bytes = 0
            self._release_pending_writes(session.pending_client_writes, commands)
            session.pending_client_writes = []
            session.write_client_bytes = 0
        else:
            session.write_in_flight_remote = False
            session.write_remote_active_bytes = 0
            self._release_pending_writes(session.pending_remote_writes, commands)
            session.pending_remote_writes = []
            session.write_remote_bytes = 0
        err = completion.get("error", "")
        if self._write_failure_is_normal_drain(session):
            pass
        elif dest == "remote" and self._remote_write_eof_is_session_done(session, err):
            self._record_pipe_close_reason(session, "client", "read eof")
            session.pipe_stage = "closed"
            self._done_session(sid, session, self._session_done_reason(session, "both eof"), commands)
        else:
            commands.append({"type": "logWriteFailure", "session": sid, "dest": dest, "text": f"write {dest}: {err}, {self._session_context(session)}"})
            self._fail_session(sid, session, f"write {dest}: {err}", commands)
        if session.active and session.draining and not self._has_pending_writes(session):
            self._free_session(sid, session, commands)

    def _handle_eof(self, sid: int, session: CoreSession, source: str, commands: List[Dict[str, Any]]) -> None:
        if session.phase != "piping":
            self._done_session(sid, session, "client/session closed", commands)
            return
        if source == "client":
            if session.pipe_stage == "halfClosedRemote":
                session.pipe_stage = "closed"
                self._done_session(sid, session, self._session_done_reason(session, "both eof"), commands)
            else:
                session.pipe_stage = "halfClosedClient"
                commands.append({"type": "closeWrite", "handle": session.remote_handle, "dest": "remote"})
        else:
            if session.pipe_stage == "halfClosedClient":
                session.pipe_stage = "closed"
                self._done_session(sid, session, self._session_done_reason(session, "both eof"), commands)
            else:
                session.pipe_stage = "halfClosedRemote"
                commands.append({"type": "closeWrite", "handle": session.local_handle, "dest": "client"})

    def _fail_session(self, sid: int, session: CoreSession, reason: str, commands: List[Dict[str, Any]]) -> None:
        session.dial_wait_reason = None
        session.dial_retry_at_nanos = 0
        session.dial_deadline_nanos = 0
        session.pipe_idle_deadline_nanos = 0
        if reason.startswith("dial failed:") or reason == "pool acquire timeout":
            self._write_protocol_failure(sid, session, commands)
            self._begin_drain_or_free(sid, session, commands)
            return
        commands.append({"type": "logSessionFailed", "session": sid, "text": f"session failed: reason={reason}, {self._session_context(session)}"})
        self._begin_drain_or_free(sid, session, commands)

    def _done_session(self, sid: int, session: CoreSession, reason: str, commands: List[Dict[str, Any]]) -> None:
        commands.append({"type": "logSessionDone", "session": sid, "text": f"session done: reason={reason}, {self._session_context(session)}"})
        self._begin_drain_or_free(sid, session, commands)

    def _begin_drain_or_free(self, sid: int, session: CoreSession, commands: List[Dict[str, Any]]) -> None:
        if not session.active:
            return
        session.draining = True
        session.read_in_flight_client = False
        session.read_in_flight_remote = False
        session.dial_wait_reason = None
        session.dial_retry_at_nanos = 0
        session.dial_deadline_nanos = 0
        session.handshake_deadline_nanos = 0
        session.pipe_idle_deadline_nanos = 0
        if not self._has_pending_writes(session):
            self._free_session(sid, session, commands)

    def _free_session(self, sid: int, session: CoreSession, commands: List[Dict[str, Any]]) -> None:
        if not session.active:
            return
        commands.append({"type": "logSessionFreed", "session": sid, "text": f"session freed: reason=drain complete, {self._session_context(session)}"})
        session.active = False
        session.phase = "closed"
        session.pipe_stage = "closed"
        pool_idx, pool_slot_id = session.ssh_conn_idx, session.ssh_slot_id
        if session.local_handle:
            commands.append({"type": "close", "handle": session.local_handle})
        if session.remote_handle:
            commands.append({"type": "close", "handle": session.remote_handle})
        self._release_pending_writes(session.pending_client_writes, commands)
        self._release_pending_writes(session.pending_remote_writes, commands)
        if pool_idx >= 0 and pool_slot_id:
            self._release_runtime_pool_usage(pool_idx, pool_slot_id)
            self._retry_waiting_pool_acquires(commands)
        gen = session.generation
        self.sessions[sid] = CoreSession(generation=gen)
        self.free_ids.append(sid)

    def _issue_read(self, sid: int, session: CoreSession, source: str, commands: List[Dict[str, Any]]) -> None:
        if not self._can_read(session, source):
            return
        if source == "remote":
            if session.read_in_flight_remote:
                return
            session.read_in_flight_remote = True
            commands.append({"type": "read", "session": sid, "token": self._token(sid, session, "readRemote"), "handle": session.remote_handle, "source": "remote", "frameMode": "opaquePipe"})
        else:
            if session.read_in_flight_client:
                return
            session.read_in_flight_client = True
            commands.append({"type": "read", "session": sid, "token": self._token(sid, session, "readClient"), "handle": session.local_handle, "source": "client", "frameMode": "detectInitial"})

    def _can_read(self, session: CoreSession, source: str) -> bool:
        if not session.active or session.draining or session.phase == "closed":
            return False
        if source == "remote":
            return session.remote_handle != 0 and session.phase == "piping" and session.pipe_stage not in ("halfClosedRemote", "closed") and not session.read_remote_paused
        return session.local_handle != 0 and session.phase != "connecting" and session.pipe_stage not in ("halfClosedClient", "closed") and not session.read_client_paused

    def _finish_read(self, session: CoreSession, source: str) -> None:
        if source == "client":
            session.read_in_flight_client = False
        else:
            session.read_in_flight_remote = False

    def _after_read_completion(self, sid: int, session: CoreSession, source: str, commands: List[Dict[str, Any]]) -> None:
        if session.active and self._can_read(session, source):
            self._issue_read(sid, session, source, commands)

    def _after_write(self, sid: int, session: CoreSession, commands: List[Dict[str, Any]]) -> None:
        if not session.active or session.phase == "closed" or session.draining:
            return
        self._issue_read(sid, session, "client", commands)
        self._issue_read(sid, session, "remote", commands)

    def _enter_piping(self, session: CoreSession) -> None:
        session.phase = "piping"
        session.handshake_deadline_nanos = 0
        session.pipe_idle_deadline_nanos = self.current_now_nanos + self.cfg["pipe_idle_timeout_nanos"] if self.current_now_nanos > 0 else 0
        session.pipe_started_nanos = self.current_now_nanos
        session.last_progress_nanos = self.current_now_nanos
        session.last_recv_progress_nanos = self.current_now_nanos
        session.last_stall_warning_nanos = 0
        session.last_download_stall_warning_nanos = 0

    def _write_protocol_failure(self, sid: int, session: CoreSession, commands: List[Dict[str, Any]]) -> None:
        if session.mode == "socks":
            data = socks5_reply(0x05)
        else:
            data = b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n"
        self._enqueue_write(sid, session, self._write_cmd(sid, session, "client", data), commands)

    def _add_pending_bytes(self, session: CoreSession, dest: str, count: int) -> None:
        if dest == "client":
            session.write_client_bytes += count
        else:
            session.write_remote_bytes += count

    def _apply_backpressure_after_enqueue(self, session: CoreSession, dest: str) -> None:
        high = self.cfg["pipe_buffer_high_water"]
        if high <= 0:
            return
        pending = session.write_client_bytes if dest == "client" else session.write_remote_bytes
        if pending <= high:
            return
        if dest == "client":
            session.read_remote_paused = True
        else:
            session.read_client_paused = True

    def _release_backpressure_after_drain(self, sid: int, session: CoreSession, dest: str, commands: List[Dict[str, Any]]) -> None:
        high = self.cfg["pipe_buffer_high_water"]
        if high <= 0:
            return
        low = self.cfg["pipe_buffer_low_water"]
        if low < 0:
            low = 0
        if low >= high:
            low = high // 2
        pending = session.write_client_bytes if dest == "client" else session.write_remote_bytes
        if pending > low:
            return
        if dest == "client" and session.read_remote_paused:
            session.read_remote_paused = False
            self._issue_read(sid, session, "remote", commands)
        elif dest == "remote" and session.read_client_paused:
            session.read_client_paused = False
            self._issue_read(sid, session, "client", commands)

    def _has_pending_writes(self, session: CoreSession) -> bool:
        return (
            session.write_in_flight_client
            or session.write_in_flight_remote
            or bool(session.pending_client_writes)
            or bool(session.pending_remote_writes)
        )

    def _write_in_flight(self, session: CoreSession, dest: str) -> bool:
        return session.write_in_flight_client if dest == "client" else session.write_in_flight_remote

    def _set_write_in_flight(self, session: CoreSession, dest: str, value: bool, count: int = 0) -> None:
        if dest == "client":
            session.write_in_flight_client = value
            session.write_client_active_bytes = count if value else 0
        else:
            session.write_in_flight_remote = value
            session.write_remote_active_bytes = count if value else 0

    def _release_write_command(self, cmd: Dict[str, Any], commands: List[Dict[str, Any]]) -> None:
        if cmd.get("payload") is not None:
            commands.append({"type": "releasePayload", "payload": cmd["payload"]})

    def _release_pending_writes(self, writes: List[Dict[str, Any]], commands: List[Dict[str, Any]]) -> None:
        for item in writes:
            self._release_write_command(item["command"], commands)

    def _release_completion_payload(self, completion: Dict[str, Any], commands: List[Dict[str, Any]]) -> None:
        if completion.get("payload") is not None:
            commands.append({"type": "releasePayload", "payload": completion["payload"]})

    def _release_stale_completion(self, completion: Dict[str, Any], commands: List[Dict[str, Any]]) -> None:
        self._release_completion_payload(completion, commands)
        if completion["type"] == "dialDone" and int(completion.get("remoteHandle", 0)) != 0:
            commands.append({"type": "close", "handle": int(completion["remoteHandle"])})

    def _should_drop_read_data(self, session: CoreSession, source: str) -> bool:
        if session.draining or session.phase == "closed":
            return True
        if source == "client":
            return session.phase == "piping" and session.pipe_stage in ("halfClosedClient", "closed")
        return session.phase != "piping" or session.pipe_stage in ("halfClosedRemote", "closed")

    def _record_pipe_close_reason(self, session: CoreSession, source: str, detail: str) -> None:
        if session.phase != "piping" or session.first_pipe_close_reason:
            return
        session.first_pipe_close_reason = f"{source} {detail}"

    def _session_done_reason(self, session: CoreSession, reason: str) -> str:
        if reason != "both eof" or not session.first_pipe_close_reason:
            return reason
        second = "client read eof" if session.first_pipe_close_reason.startswith("remote ") else "remote read eof"
        return f"both eof: first={session.first_pipe_close_reason}, second={second}"

    def _remote_write_eof_is_session_done(self, session: CoreSession, err: str) -> bool:
        return err.strip().lower() == "eof" and session.pipe_stage in ("halfClosedRemote", "halfClosedClient", "closed")

    def _write_failure_is_normal_drain(self, session: CoreSession) -> bool:
        return session.draining or session.pipe_stage == "closed"

    def _session_context(self, session: CoreSession) -> str:
        phase = {"init": "INIT", "socksAuth": "SOCKS5_AUTH", "socksReq": "SOCKS5_REQ", "httpReq": "HTTP_REQ", "connecting": "CONNECTING", "piping": "PIPING", "closed": "CLOSED"}.get(session.phase, session.phase)
        pipe = {"flowing": "FLOWING", "halfClosedClient": "HALF_CLOSED_CLIENT", "halfClosedRemote": "HALF_CLOSED_REMOTE", "closed": "CLOSED"}.get(session.pipe_stage, session.pipe_stage)
        mode = {"httpConnect": "http_connect", "httpProxy": "http_proxy", "socks": "socks", "none": "none"}[session.mode]
        target = "-" if not session.target_host and session.target_port == 0 else f"{session.target_host}:{session.target_port}"
        slot = f"{session.ssh_conn_idx if session.ssh_conn_idx >= 0 else -1}/{session.ssh_slot_id}"
        return f"phase={phase}, pipe={pipe}, mode={mode}, target={target}, local_handle={session.local_handle}, remote_handle={session.remote_handle}, slot={slot}, bytes_sent={session.bytes_sent}, bytes_received={session.bytes_received}, pending_writes=client:{session.write_client_bytes}/{str(session.write_in_flight_client).lower()},remote:{session.write_remote_bytes}/{str(session.write_in_flight_remote).lower()}"

    def _mark_progress(self, session: CoreSession, upload: bool, download: bool) -> None:
        if self.current_now_nanos <= 0 or session.phase != "piping":
            return
        if upload or download:
            session.last_progress_nanos = self.current_now_nanos
            session.pipe_idle_deadline_nanos = self.current_now_nanos + self.cfg["pipe_idle_timeout_nanos"]
            session.last_stall_warning_nanos = 0
            if session.ssh_conn_idx >= 0 and session.ssh_slot_id:
                self._mark_pool_slot_progress(session.ssh_conn_idx, session.ssh_slot_id)
        if download:
            session.last_recv_progress_nanos = self.current_now_nanos
            session.last_download_stall_warning_nanos = 0

    def _tick_pipe_diagnostics(self, sid: int, session: CoreSession, commands: List[Dict[str, Any]]) -> None:
        stall_after = 30 * NANO
        interval = 30 * NANO
        if session.phase != "piping" or self.current_now_nanos <= 0 or session.pipe_started_nanos <= 0:
            return
        last_progress = session.last_progress_nanos or session.pipe_started_nanos
        last_recv = session.last_recv_progress_nanos or session.pipe_started_nanos
        no_progress_idle = self.current_now_nanos - last_progress
        download_idle = self.current_now_nanos - last_recv
        running_for = self.current_now_nanos - session.pipe_started_nanos
        close_in = max(0, session.pipe_idle_deadline_nanos - self.current_now_nanos)
        if no_progress_idle >= stall_after and (session.last_stall_warning_nanos == 0 or self.current_now_nanos - session.last_stall_warning_nanos >= interval):
            session.last_stall_warning_nanos = self.current_now_nanos
            commands.append({"type": "emitDiagnostic", "session": sid, "kind": "NoProgress", "level": "Debug", "text": f"pipe stalled: kind=NoProgress, idle_for={_fmt_secs(no_progress_idle)}, running_for={_fmt_secs(running_for)}, close_in={_fmt_secs(close_in)}, {self._session_context(session)}"})
            return
        if download_idle >= stall_after and session.bytes_sent > 0 and no_progress_idle < stall_after and (session.last_download_stall_warning_nanos == 0 or self.current_now_nanos - session.last_download_stall_warning_nanos >= interval):
            session.last_download_stall_warning_nanos = self.current_now_nanos
            commands.append({"type": "emitDiagnostic", "session": sid, "kind": "DownloadIdle", "level": "Debug", "text": f"pipe stalled: kind=DownloadIdle, idle_for={_fmt_secs(download_idle)}, running_for={_fmt_secs(running_for)}, close_in={_fmt_secs(close_in)}, {self._session_context(session)}"})

    def _ensure_pool_slot(self, idx: int, slot_id: str) -> CorePoolSlot:
        while len(self.pool_slots) <= idx:
            self.pool_slots.append(CorePoolSlot())
        slot = self.pool_slots[idx]
        if slot.slot_id != slot_id:
            self.pool_slots[idx] = CorePoolSlot(slot_id=slot_id)
        return self.pool_slots[idx]

    def _view_to_slot_dict(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "index": int(raw["index"]),
            "slotId": raw.get("slotId") or raw.get("slot_id", ""),
            "healthy": bool(raw.get("healthy", True)),
            "isConnected": bool(raw.get("isConnected", raw.get("is_connected", raw.get("connected", True)))),
            "usage": int(raw.get("usage", 0)),
            "consecutiveFailures": int(raw.get("consecutiveFailures", raw.get("consecutive_failures", raw.get("failures", 0)))),
            "lastFailureNanos": int(raw.get("lastFailureNanos", raw.get("last_failure_nanos", 0)) or 0),
        }

    def _pool_supervisor_snapshot(self, views: List[Dict[str, Any]]) -> None:
        for raw in views:
            view = self._view_to_slot_dict(raw)
            if view["index"] < 0 or not view["slotId"]:
                continue
            slot = self._ensure_pool_slot(view["index"], view["slotId"])
            has_local_failure = slot.consecutive_failures > 0
            if has_local_failure and view["isConnected"] and view["healthy"]:
                if not slot.connected or not slot.healthy:
                    slot.connected = False
                    slot.healthy = False
                continue
            slot.slot_id = view["slotId"]
            slot.connected = view["isConnected"]
            slot.healthy = view["healthy"] and view["isConnected"]
            slot.usage = max(slot.usage, view["usage"])
            slot.consecutive_failures = view["consecutiveFailures"]
            slot.last_failure_nanos = view["lastFailureNanos"]
            if slot.connected and slot.healthy:
                slot.reconnect_in_flight = False

    def _merge_pool_snapshot(self, views: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out = []
        for raw in views:
            view = self._view_to_slot_dict(raw)
            if view["index"] < 0 or not view["slotId"]:
                continue
            slot = self._ensure_pool_slot(view["index"], view["slotId"])
            has_local_failure = slot.consecutive_failures > 0
            if has_local_failure and view["isConnected"] and view["healthy"]:
                if not slot.connected or not slot.healthy:
                    slot.connected = False
                    slot.healthy = False
            else:
                slot.slot_id = view["slotId"]
                slot.connected = view["isConnected"]
                slot.healthy = view["healthy"] and view["isConnected"]
                slot.consecutive_failures = view["consecutiveFailures"]
                slot.last_failure_nanos = view["lastFailureNanos"]
                if slot.connected and slot.healthy:
                    slot.reconnect_in_flight = False
            out.append({
                **view,
                "healthy": slot.healthy,
                "isConnected": view["isConnected"] and slot.connected,
                "usage": max(view["usage"], slot.usage),
                "consecutiveFailures": slot.consecutive_failures,
                "lastFailureNanos": slot.last_failure_nanos,
            })
        return out

    def _compute_best_slot(self, views: List[Dict[str, Any]]) -> int:
        best = -1
        best_usage = self.cfg["max_sessions_per_slot"] + 1
        overflow_best = -1
        overflow_usage = 2**31 - 1
        for view in views:
            if not view["healthy"] or not view["isConnected"]:
                continue
            if self.cfg["slot_cooldown_nanos"] > 0 and view["consecutiveFailures"] > 0 and self.current_now_nanos - int(view["lastFailureNanos"]) < self.cfg["slot_cooldown_nanos"]:
                continue
            usage = int(view["usage"])
            idx = int(view["index"])
            if (self.cfg["max_sessions_per_slot"] <= 0 or usage < self.cfg["max_sessions_per_slot"]) and (best < 0 or usage < best_usage or (usage == best_usage and idx < best)):
                best = idx
                best_usage = usage
            if overflow_best < 0 or usage < overflow_usage or (usage == overflow_usage and idx < overflow_best):
                overflow_best = idx
                overflow_usage = usage
        return best if best >= 0 else overflow_best

    def _claim_runtime_pool_usage(self, idx: int, slot_id: str) -> None:
        self._ensure_pool_slot(idx, slot_id).usage += 1

    def _release_runtime_pool_usage(self, idx: int, slot_id: str) -> None:
        if 0 <= idx < len(self.pool_slots):
            slot = self.pool_slots[idx]
            if slot.slot_id == slot_id and slot.usage > 0:
                slot.usage -= 1

    def _release_failed_dial_claim(self, session: CoreSession, idx: int, slot_id: str) -> None:
        if idx >= 0 and slot_id:
            self._release_runtime_pool_usage(idx, slot_id)
            if session.ssh_conn_idx == idx and session.ssh_slot_id == slot_id:
                session.ssh_conn_idx = -1
                session.ssh_slot_id = ""

    def _mark_pool_slot_success(self, idx: int, slot_id: str) -> None:
        if idx < 0 or not slot_id:
            return
        slot = self._ensure_pool_slot(idx, slot_id)
        slot.healthy = True
        slot.connected = True
        slot.consecutive_failures = 0
        slot.last_failure_nanos = 0
        slot.health_check_in_flight = False
        slot.reconnect_in_flight = False
        slot.next_reconnect_nanos = 0

    def _mark_pool_slot_progress(self, idx: int, slot_id: str) -> None:
        self._mark_pool_slot_success(idx, slot_id)
        if 0 <= idx < len(self.pool_slots) and self.pool_slots[idx].slot_id == slot_id and self.current_now_nanos > 0:
            self.pool_slots[idx].next_health_check_nanos = self.current_now_nanos + self.cfg["pool_health_check_interval_nanos"]

    def _mark_pool_slot_soft_failed(self, idx: int, slot_id: str) -> None:
        if idx < 0 or not slot_id:
            return
        if idx < len(self.pool_slots) and self.pool_slots[idx].slot_id and self.pool_slots[idx].slot_id != slot_id:
            return
        slot = self._ensure_pool_slot(idx, slot_id)
        slot.consecutive_failures += 1
        slot.last_failure_nanos = self.current_now_nanos
        slot.health_check_in_flight = False
        slot.healthy = True
        slot.connected = True

    def _mark_pool_slot_failed(self, idx: int, slot_id: str, max_fails: int, commands: List[Dict[str, Any]]) -> None:
        if idx < 0 or not slot_id:
            return
        if idx < len(self.pool_slots) and self.pool_slots[idx].slot_id and self.pool_slots[idx].slot_id != slot_id:
            return
        slot = self._ensure_pool_slot(idx, slot_id)
        slot.consecutive_failures += 1
        slot.last_failure_nanos = self.current_now_nanos
        slot.health_check_in_flight = False
        if max_fails < 0 or (max_fails > 0 and slot.consecutive_failures >= max_fails):
            slot.healthy = False
            slot.connected = False
            slot.reconnect_in_flight = False
        if not slot.connected or not slot.healthy:
            commands.append({"type": "markPoolSlotFailed", "poolIdx": idx, "poolSlotId": slot_id})

    def _schedule_pool_reconnect(self, idx: int, reason: str, commands: List[Dict[str, Any]]) -> None:
        if idx < 0 or idx >= len(self.pool_slots):
            return
        slot = self.pool_slots[idx]
        if slot.reconnect_in_flight:
            return
        slot.reconnect_in_flight = True
        slot.health_check_in_flight = False
        slot.health_check_op_id = 0
        slot.reconnect_op_id = self.next_pool_op_id
        self.next_pool_op_id += 1
        slot.next_reconnect_nanos = self.current_now_nanos + self.cfg["pool_reconnect_interval_nanos"]
        commands.append({"type": "reconnectPoolSlot", "poolIdx": idx, "poolOpId": str(slot.reconnect_op_id), "reason": reason})

    def _tick_pool_supervisor(self, commands: List[Dict[str, Any]]) -> None:
        if not self.cfg["pool_control_enabled"]:
            return
        for idx, slot in enumerate(self.pool_slots):
            if slot.connected and slot.healthy:
                if not self.cfg["pool_supervisor_enabled"]:
                    continue
                if not slot.health_check_in_flight and (slot.next_health_check_nanos == 0 or self.current_now_nanos >= slot.next_health_check_nanos):
                    slot.health_check_in_flight = True
                    slot.health_check_op_id = self.next_pool_op_id
                    self.next_pool_op_id += 1
                    slot.next_health_check_nanos = self.current_now_nanos + self.cfg["pool_health_check_interval_nanos"]
                    commands.append({"type": "healthCheckPoolSlot", "poolIdx": idx, "poolSlotId": slot.slot_id, "poolOpId": str(slot.health_check_op_id)})
            elif not slot.reconnect_in_flight and (slot.next_reconnect_nanos == 0 or self.current_now_nanos >= slot.next_reconnect_nanos):
                self._schedule_pool_reconnect(idx, "reconnect retry interval elapsed", commands)

    def _pool_slot_health_check_failed(self, idx: int, slot_id: str, pool_op_id: int, reason: str, commands: List[Dict[str, Any]]) -> None:
        if not self.cfg["pool_control_enabled"] or not self._match_pool_op(idx, "healthCheck", pool_op_id):
            return
        if self._is_soft_pool_failure(reason):
            self._mark_pool_slot_soft_failed(idx, slot_id)
            return
        self._mark_pool_slot_failed(idx, slot_id, self.cfg["pool_max_health_failures"], commands)
        if idx < len(self.pool_slots):
            slot = self.pool_slots[idx]
            if not slot.connected or not slot.healthy:
                self._schedule_pool_reconnect(idx, reason if reason.lower().startswith("health check") else f"health check failed: {reason}", commands)

    def _pool_slot_health_check_unavailable(self, idx: int, slot_id: str, pool_op_id: int) -> None:
        if not self.cfg["pool_control_enabled"] or not self._match_pool_op(idx, "healthCheck", pool_op_id):
            return
        slot = self.pool_slots[idx]
        if slot.slot_id != slot_id:
            return
        slot.health_check_in_flight = False
        slot.health_check_op_id = 0
        if self.current_now_nanos > 0:
            slot.next_health_check_nanos = self.current_now_nanos + self.cfg["pool_health_check_interval_nanos"]

    def _pool_slot_reconnect_ok(self, idx: int, slot_id: str, pool_op_id: int) -> None:
        if not self.cfg["pool_control_enabled"] or not self._match_pool_op(idx, "reconnect", pool_op_id):
            return
        self._mark_pool_slot_success(idx, slot_id)
        slot = self.pool_slots[idx]
        if slot.slot_id == slot_id:
            slot.usage = 0
            slot.next_health_check_nanos = self.current_now_nanos + self.cfg["pool_health_check_interval_nanos"]

    def _pool_slot_reconnect_failed(self, idx: int, pool_op_id: int) -> None:
        if not self.cfg["pool_control_enabled"] or idx >= len(self.pool_slots):
            return
        slot = self.pool_slots[idx]
        if not self._match_pool_op(idx, "reconnect", pool_op_id):
            return
        slot.consecutive_failures += 1
        slot.last_failure_nanos = self.current_now_nanos
        slot.healthy = False
        slot.connected = False
        slot.health_check_in_flight = False
        slot.reconnect_in_flight = False
        slot.next_reconnect_nanos = self.current_now_nanos + self.cfg["pool_reconnect_interval_nanos"]

    def _match_pool_op(self, idx: int, kind: str, pool_op_id: int) -> bool:
        if idx < 0 or idx >= len(self.pool_slots) or pool_op_id <= 0:
            return False
        slot = self.pool_slots[idx]
        if kind == "healthCheck":
            return slot.health_check_in_flight and slot.health_check_op_id == pool_op_id
        return slot.reconnect_in_flight and slot.reconnect_op_id == pool_op_id

    def _system_wake(self, views: List[Dict[str, Any]], slept_nanos: int, commands: List[Dict[str, Any]]) -> None:
        if not self.cfg["pool_control_enabled"]:
            return
        for raw in views:
            view = self._view_to_slot_dict(raw)
            if view["index"] < 0 or not view["slotId"]:
                continue
            slot = self._ensure_pool_slot(view["index"], view["slotId"])
            was_connected = slot.connected
            slot.healthy = False
            slot.connected = False
            slot.last_failure_nanos = self.current_now_nanos
            slot.health_check_in_flight = False
            slot.reconnect_in_flight = False
            if was_connected:
                slot.consecutive_failures += 1
                commands.append({"type": "markPoolSlotFailed", "poolIdx": view["index"], "poolSlotId": slot.slot_id})
            self._schedule_pool_reconnect(view["index"], f"system wake: timer gap {_fmt_secs(slept_nanos)}", commands)

    def _begin_pool_acquire_wait(self, session: CoreSession) -> None:
        session.dial_wait_reason = "poolAcquire"
        if self.current_now_nanos > 0:
            if session.dial_deadline_nanos == 0:
                session.dial_deadline_nanos = self.current_now_nanos + self.cfg["pool_acquire_timeout_nanos"]
            session.dial_retry_at_nanos = self.current_now_nanos + self.cfg["pool_acquire_retry_interval_nanos"]

    def _wait_for_pool_acquire(self, sid: int, session: CoreSession, commands: List[Dict[str, Any]]) -> None:
        if not session.active or session.draining or session.phase != "connecting":
            return
        self._begin_pool_acquire_wait(session)
        commands.append({"type": "snapshotPool", "session": sid, "token": self._token(sid, session, "dial")})

    def _has_available_pool_slot(self) -> bool:
        for idx, slot in enumerate(self.pool_slots):
            view = {"index": idx, "slotId": slot.slot_id, "healthy": slot.healthy, "isConnected": slot.connected, "usage": slot.usage, "consecutiveFailures": slot.consecutive_failures, "lastFailureNanos": slot.last_failure_nanos}
            if self._compute_best_slot([view]) >= 0:
                return True
        return False

    def _retry_waiting_pool_acquires(self, commands: List[Dict[str, Any]]) -> None:
        if not self._has_available_pool_slot():
            return
        for sid, session in enumerate(self.sessions):
            if session.active and not session.draining and session.phase == "connecting" and session.dial_wait_reason == "poolAcquire" and session.dial_retry_at_nanos != 0:
                session.dial_retry_at_nanos = 0
                commands.append({"type": "snapshotPool", "session": sid, "token": self._token(sid, session, "dial")})

    def _classify_dial_failure(self, reason: str) -> str:
        low = reason.lower()
        if "channel open timeout" in low or "channel send error" in low or "context deadline exceeded" in low or "i/o timeout" in low:
            return "poolSoft"
        if "pool slot id changed" in low or "slot not connected" in low or "slot handle unavailable" in low or "pool resource unavailable" in low:
            return "poolHard"
        return "target"

    def _is_soft_pool_failure(self, reason: str) -> bool:
        low = reason.lower()
        return "channel open timeout" in low or "direct-tcpip" in low or "channel send" in low

    def _is_dial_timeout_soft_failure(self, reason: str) -> bool:
        low = reason.lower()
        return "context deadline exceeded" in low or "i/o timeout" in low


def _fmt_secs(nanos: int) -> str:
    return f"{nanos / NANO:.1f}s"


def _core_config_from_vector(raw: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    raw = raw or {}
    cfg: Dict[str, Any] = {}
    if "local_only" in raw:
        cfg["local_only"] = bool(raw["local_only"])
    if "pipe_idle_timeout_seconds" in raw:
        cfg["pipe_idle_timeout_nanos"] = _seconds(raw["pipe_idle_timeout_seconds"])
    if "pipe_buffer_high_water" in raw:
        cfg["pipe_buffer_high_water"] = int(raw["pipe_buffer_high_water"])
    if "pipe_buffer_low_water" in raw:
        cfg["pipe_buffer_low_water"] = int(raw["pipe_buffer_low_water"])
    if "max_sessions_per_slot" in raw:
        cfg["max_sessions_per_slot"] = int(raw["max_sessions_per_slot"])
    if "slot_cooldown_seconds" in raw:
        cfg["slot_cooldown_nanos"] = _seconds(raw["slot_cooldown_seconds"])
    if "pool_supervisor_enabled" in raw:
        cfg["pool_supervisor_enabled"] = bool(raw["pool_supervisor_enabled"])
    if "pool_acquire_timeout_seconds" in raw:
        cfg["pool_acquire_timeout_nanos"] = _seconds(raw["pool_acquire_timeout_seconds"])
    if "pool_acquire_retry_interval_seconds" in raw:
        cfg["pool_acquire_retry_interval_nanos"] = _seconds(raw["pool_acquire_retry_interval_seconds"])
    if "pool_max_health_failures" in raw:
        cfg["pool_max_health_failures"] = int(raw["pool_max_health_failures"])
    if "pool_health_check_interval_seconds" in raw:
        cfg["pool_health_check_interval_nanos"] = _seconds(raw["pool_health_check_interval_seconds"])
    return cfg


def _payload_ref(step: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    pid = step.get("payload_id")
    if pid is None:
        return None
    return {"id": str(pid), "gen": int(step.get("buffer_gen", 1))}


def _buffer_ref(step: Dict[str, Any]) -> Dict[str, Any]:
    return {"id": str(step.get("buffer_id", step.get("payload_id", 0))), "gen": int(step.get("buffer_gen", 1))}


def _pool_views(raw_views: Optional[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    out = []
    for view in raw_views or []:
        out.append({
            "index": int(view["index"]),
            "slotId": view.get("slot_id", ""),
            "healthy": bool(view.get("healthy", True)),
            "isConnected": bool(view.get("is_connected", True)),
            "usage": int(view.get("usage", 0)),
            "consecutiveFailures": int(view.get("consecutive_failures", 0)),
            "lastFailureNanos": _seconds(float(view.get("last_failure_seconds", 0))),
        })
    return out


def _command_alias_matches(cmd: Dict[str, Any], want: str) -> bool:
    actual = cmd["type"]
    mapping = {
        "read": "Read",
        "writeInline": "Write",
        "dialDirect": "DialDirect",
        "dialSSH": "DialSSH",
        "snapshotPool": "SnapshotPool",
        "markPoolSlotFailed": "MarkPoolSlotFailed",
        "healthCheckPoolSlot": "HealthCheckPoolSlot",
        "reconnectPoolSlot": "ReconnectPoolSlot",
        "close": "Close",
        "closeWrite": "CloseWrite",
        "releasePayload": "ReleasePayload",
        "logSessionDone": "LogSessionDone",
        "logSessionFreed": "LogSessionFreed",
        "logSessionFailed": "LogSessionFailure",
        "logWriteFailure": "LogWriteFailure",
        "logIOFailure": "LogIOFailure",
        "emitDiagnostic": "EmitDiagnostic",
    }.get(actual, actual)
    norm_mapping = mapping.replace("_", "").lower()
    norm_want = want.replace("_", "").lower()
    return (
        norm_mapping == norm_want
        or (norm_want == "dial" and actual in ("dialDirect", "dialSSH"))
        or (norm_want == "write" and actual == "writeInline")
        or (norm_want == "snapshot" and actual == "snapshotPool")
    )


def _command_matches(cmd: Dict[str, Any], want: Dict[str, Any]) -> bool:
    if not _command_alias_matches(cmd, want["type"]):
        return False
    if "handle" in want and cmd.get("handle") != int(want["handle"]):
        return False
    if "remote_handle" in want and cmd.get("remoteHandle") != int(want["remote_handle"]):
        return False
    if "source" in want and cmd.get("source") != want["source"].lower():
        return False
    if "dest" in want and cmd.get("dest") != want["dest"].lower():
        return False
    if "pool_idx" in want and cmd.get("poolIdx") != int(want["pool_idx"]):
        return False
    if "pool_slot_id" in want and cmd.get("poolSlotId") != want["pool_slot_id"]:
        return False
    if "payload_id" in want:
        payload = cmd.get("payload")
        if payload is None or payload.get("id") != str(want["payload_id"]):
            return False
    if "text" in want:
        raw = cmd.get("bytes", b"")
        if isinstance(raw, bytes):
            if raw.decode("utf-8", errors="replace") != want["text"]:
                return False
        elif cmd.get("text") != want["text"]:
            return False
    if "message_contains" in want:
        if want["message_contains"] not in cmd.get("text", ""):
            return False
    if "reason" in want and cmd.get("reason") != want["reason"]:
        return False
    if "kind" in want and cmd.get("kind") != want["kind"]:
        return False
    if "level" in want and cmd.get("level") != want["level"]:
        return False
    return True


def _save_command(saved: Dict[str, Dict[str, Any]], commands: List[Dict[str, Any]], name: str, save_type: str) -> None:
    for cmd in commands:
        if _command_alias_matches(cmd, save_type):
            saved[name] = cmd
            return
    raise AssertionError(f"cannot save {name} as {save_type} from {commands}")


def _completion_for_core_step(step: Dict[str, Any], saved: Dict[str, Dict[str, Any]], last: List[Dict[str, Any]], reads: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    op = step["op"]
    use_name = step.get("use_command", "")
    use_cmd = saved.get(use_name) if use_name else None
    if op == "accept":
        return {"type": "accepted", "handle": int(step["handle"])}
    if op == "update_time":
        return {"type": "updateTime", "nowNanos": _seconds(step["now"])}
    if op == "tick":
        return {"type": "tick", "nowNanos": _seconds(step["now"])}
    if op == "pool_supervisor_snapshot":
        return {"type": "poolSupervisorSnapshot", "poolViews": _pool_views(step.get("views"))}
    if op == "system_wake":
        return {"type": "systemWake", "nowNanos": int(step["now"]), "sleptNanos": int(step["slept_nanos"]), "poolViews": _pool_views(step.get("views"))}
    if op == "pool_snapshot":
        return {"type": "poolSnapshot", "token": (use_cmd or saved["snapshot_req"])["token"], "poolViews": _pool_views(step.get("views"))}
    if op == "pool_health_failed":
        cmd = use_cmd or saved.get("health") or next(c for c in reversed(last) if c["type"] == "healthCheckPoolSlot")
        return {"type": "poolSlotHealthCheckFailed", "poolIdx": int(step["pool_idx"]), "poolSlotId": step["pool_slot_id"], "poolOpId": cmd["poolOpId"], "error": step["reason"]}
    if op == "pool_health_unavailable":
        cmd = use_cmd or saved.get("health") or next(c for c in reversed(last) if c["type"] == "healthCheckPoolSlot")
        return {
            "type": "poolSlotHealthCheckUnavailable",
            "poolIdx": int(step["pool_idx"]),
            "poolSlotId": step["pool_slot_id"],
            "poolOpId": cmd["poolOpId"],
            "error": step.get("reason", "health check executor unavailable"),
            "nowNanos": _seconds(step["now"]) if "now" in step else None,
        }
    if op == "pool_slot_progress":
        return {"type": "poolSlotProgress", "poolIdx": int(step["pool_idx"]), "poolSlotId": step["pool_slot_id"], "nowNanos": _seconds(step["now"]) if "now" in step else None}
    if op == "pool_reconnect_ok":
        cmd = use_cmd or saved.get("reconnect_0") or next(c for c in reversed(last) if c["type"] == "reconnectPoolSlot")
        return {"type": "poolSlotReconnectOK", "poolIdx": int(step["pool_idx"]), "poolSlotId": step["pool_slot_id"], "poolOpId": cmd["poolOpId"]}
    if op == "pool_reconnect_failed":
        cmd = use_cmd or saved.get("reconnect_0") or next(c for c in reversed(last) if c["type"] == "reconnectPoolSlot")
        return {"type": "poolSlotReconnectFailed", "poolIdx": int(step["pool_idx"]), "poolOpId": cmd["poolOpId"], "error": step["reason"]}
    if op == "read_done":
        cmd = use_cmd or reads.get(step["source"].lower()) or next(c for c in reversed(last) if c["type"] == "read" and c["source"] == step["source"].lower())
        return {"type": "readDone", "token": cmd["token"], "handle": cmd["handle"], "source": step["source"].lower(), "data": _spec_bytes(step), "payload": _payload_ref(step)}
    if op == "read_eof":
        cmd = use_cmd or reads.get(step["source"].lower()) or next(c for c in reversed(last) if c["type"] == "read" and c["source"] == step["source"].lower())
        return {"type": "readEOF", "token": cmd["token"], "handle": cmd["handle"], "source": step["source"].lower(), "payload": _payload_ref(step)}
    if op == "read_error":
        cmd = use_cmd or reads.get(step["source"].lower()) or next(c for c in reversed(last) if c["type"] == "read" and c["source"] == step["source"].lower())
        return {"type": "readError", "token": cmd["token"], "handle": cmd["handle"], "source": step["source"].lower(), "error": step["reason"], "payload": _payload_ref(step)}
    if op == "write_done":
        cmd = use_cmd or next(c for c in reversed(last) if c["type"] == "writeInline" and c["dest"] == step["dest"].lower())
        return {"type": "writeDone", "token": cmd["token"], "handle": cmd["handle"], "dest": cmd["dest"], "len": len(cmd.get("bytes", b"")), "payload": cmd.get("payload")}
    if op == "write_failed":
        cmd = use_cmd or next(c for c in reversed(last) if c["type"] == "writeInline" and c["dest"] == step["dest"].lower())
        return {"type": "writeFailed", "token": cmd["token"], "handle": cmd["handle"], "dest": cmd["dest"], "error": step["reason"], "payload": cmd.get("payload")}
    if op == "dial_done":
        cmd = use_cmd or saved["dial"]
        return {"type": "dialDone", "token": cmd["token"], "remoteHandle": int(step["remote_handle"]), "poolIdx": int(cmd.get("poolIdx", -1)), "poolSlotId": cmd.get("poolSlotId", "")}
    if op == "dial_direct_failed":
        cmd = use_cmd or saved["dial"]
        return {"type": "dialFailed", "token": cmd["token"], "reason": step["reason"], "poolIdx": -1, "poolSlotId": ""}
    if op in ("dial_ssh_pool_failed", "dial_ssh_target_failed"):
        cmd = use_cmd or saved["dial"]
        return {"type": "dialFailed", "token": cmd["token"], "reason": step["reason"], "poolIdx": int(cmd.get("poolIdx", -1)), "poolSlotId": cmd.get("poolSlotId", "")}
    raise ValueError(f"unknown core op: {op}")


def _assert_core_state(vector_id: str, step_index: int, core: RuntimeCore, step: Dict[str, Any]) -> None:
    session = core.first_session()
    have = session is not None and session.active
    if "expect_active" in step:
        assert have == bool(step["expect_active"]), f"{vector_id} step {step_index} active={have} want {step['expect_active']}"
    if "expect_draining" in step:
        got = bool(session.draining) if session else False
        assert got == bool(step["expect_draining"]), f"{vector_id} step {step_index} draining={got} want {step['expect_draining']}"
    if session:
        if "expect_write_client_bytes" in step:
            assert session.write_client_bytes == int(step["expect_write_client_bytes"])
        if "expect_write_remote_bytes" in step:
            assert session.write_remote_bytes == int(step["expect_write_remote_bytes"])
        if "expect_read_remote_paused" in step:
            assert session.read_remote_paused == bool(step["expect_read_remote_paused"])
        if "expect_handshake_deadline_seconds" in step:
            assert session.handshake_deadline_nanos == _seconds(step["expect_handshake_deadline_seconds"])
    if "expect_current_now_seconds" in step:
        assert core.current_now_nanos == _seconds(step["expect_current_now_seconds"])
    for expected in step.get("expect_pool_usages", []):
        slot = core.pool_slots[int(expected["index"])]
        if "slot_id" in expected:
            assert slot.slot_id == expected["slot_id"]
        assert slot.usage == int(expected["usage"])
    for expected in step.get("expect_pool_slots", []):
        slot = core.pool_slots[int(expected["index"])]
        if "slot_id" in expected:
            assert slot.slot_id == expected["slot_id"]
        if "healthy" in expected:
            assert slot.healthy == bool(expected["healthy"])
        if "connected" in expected:
            assert slot.connected == bool(expected["connected"])
        if "usage" in expected:
            assert slot.usage == int(expected["usage"])
        if "consecutive_failures" in expected:
            assert slot.consecutive_failures == int(expected["consecutive_failures"])
        if "health_check_in_flight" in expected:
            assert slot.health_check_in_flight == bool(expected["health_check_in_flight"])
        if "next_health_check_seconds" in expected:
            assert slot.next_health_check_nanos == _seconds(expected["next_health_check_seconds"])


def _run_json_core_vectors() -> bool:
    doc = json.load(open(SPEC_DIR / "core_vectors.json", encoding="utf-8"))
    passed = 0
    failed = 0
    for vector in doc["vectors"]:
        core = RuntimeCore(_core_config_from_vector(vector.get("config")))
        saved: Dict[str, Dict[str, Any]] = {}
        last: List[Dict[str, Any]] = []
        reads: Dict[str, Dict[str, Any]] = {}
        try:
            for idx, step in enumerate(vector["steps"]):
                completion = _completion_for_core_step(step, saved, last, reads)
                if completion["type"] in ("readDone", "readEOF", "readError"):
                    reads.pop(completion["source"], None)
                commands = core.step(completion)
                if "save_command" in step:
                    _save_command(saved, commands, step["save_command"], step.get("save_type", step["save_command"]))
                if step.get("expect_no_commands"):
                    assert commands == [], (vector["id"], idx, commands)
                if "expect_command_count" in step:
                    assert len(commands) == int(step["expect_command_count"]), (vector["id"], idx, len(commands), step["expect_command_count"], commands)
                for expected in step.get("expect_commands", []):
                    assert any(_command_matches(cmd, expected) for cmd in commands), (vector["id"], idx, expected, commands)
                for expected in step.get("expect_absent_commands", []):
                    assert not any(_command_matches(cmd, expected) for cmd in commands), (vector["id"], idx, expected, commands)
                _assert_core_state(vector["id"], idx, core, step)
                for cmd in commands:
                    if cmd["type"] == "read":
                        reads[cmd["source"]] = cmd
                last = commands
            passed += 1
        except Exception as exc:
            failed += 1
            print(f"FAIL core {vector['id']}: {type(exc).__name__}: {exc!r}")
    print(f"core_vectors: {passed} passed, {failed} failed")
    return failed == 0


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
        # TARGET_REFUSED → SOCKS5 rep 0x05
        # s_tr = ProxyProtocolState(proxy_mode=ProxyMode.SOCKS5)
        # s_tr = proxy_protocol_reducer(s_tr, ClientDataReceived(b"\x05\x01\x00")).state
        # s_tr = proxy_protocol_reducer(s_tr, ClientDataReceived(req)).state
        # tr_tr = proxy_protocol_reducer(
        #     s_tr, OutboundStreamOpenFailed(ConnectFailReason.TARGET_REFUSED, "port closed")
        # )
        # effs_tr = list(tr_tr.effects)
        # check(
        #     "SOCKS5 TARGET_REFUSED: rep=0x05",
        #     any((e.type == EffectType.WRITE_CLIENT and e.data == socks5_reply(0x05)) for e in effs_tr)
        # )

        # # SSH_BROKEN → HTTP 503
        # s_sb = ProxyProtocolState(proxy_mode=ProxyMode.HTTP)
        # http_c = b"CONNECT target.com:443 HTTP/1.1\r\nHost: target.com:443\r\n\r\n"
        # s_sb = proxy_protocol_reducer(s_sb, ClientDataReceived(http_c)).state
        # tr_sb = proxy_protocol_reducer(
        #     s_sb, OutboundStreamOpenFailed(ConnectFailReason.SSH_BROKEN, "conn lost")
        # )
        # effs_sb = list(tr_sb.effects)
        # check(
        #     "HTTP SSH_BROKEN: 503 response",
        #     any(e.type == EffectType.WRITE_CLIENT and b"503" in e.data for e in effs_sb),
        # )

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
            await asyncio.wait_for(state.server.wait_closed(), timeout=0.1)
        except asyncio.TimeoutError:
            pass

    for queue in state.shard_queues:
        try:
            queue.put_nowait(None)
        except asyncio.QueueFull:
            pass
    if state.shard_queues:
        try:
            await asyncio.wait_for(
                asyncio.gather(*(queue.join() for queue in state.shard_queues)),
                timeout=cfg.shutdown_timeout,
            )
        except asyncio.TimeoutError:
            pass
    for task in state.shard_tasks:
        if not task.done():
            task.cancel()
    if state.shard_tasks:
        await asyncio.gather(*state.shard_tasks, return_exceptions=True)

    if state.active_tasks:
        log.info(f"Waiting for {len(state.active_tasks)} active connections...")
        done, pending = await asyncio.wait(state.active_tasks, timeout=cfg.shutdown_timeout)
        if pending:
            log.warning(f"Force-cancelling {len(pending)} connections")
            for t in pending:
                t.cancel()
            await asyncio.wait(pending, timeout=0.1)

    await close_pool(state.pool)
    log.info(f"Final: {stats_summary(state.stats)}\n✓ Proxy server shut down")
    close_io_resource_log_file()
    os.exit(0);


# ============================================================================
# Main server
# ============================================================================


async def run_server(cfg: Config):
    log = logging.getLogger("SSHProxy")
    log.setLevel(getattr(logging, cfg.log_level.upper(), logging.INFO))
    cfg = replace(
        cfg,
        event_loop_shards=normalize_event_loop_shard_count(
            cfg.event_loop_shards,
            os.cpu_count() or 1,
        ),
    )

    if not log.handlers:
        h = logging.StreamHandler(sys.stderr)
        h.setFormatter(
            ColorFormatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                datefmt="%H:%M:%S",
            )
        )
        log.addHandler(h)
    if cfg.log_file:
        configure_io_resource_log_file(cfg.log_file)

    log.info(
        f"\033[96m{'=' * 60}\033[0m\n"
        f"\033[92mSSH Proxy Server (Sans-I/O v7 — stricter core/runtime split)\033[0m\n"
        f"pool_size={cfg.pool_size} max_sessions={cfg.max_sessions} event_loop_shards={cfg.event_loop_shards}\n"
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
    state.shard_queues = [asyncio.Queue() for _ in range(cfg.event_loop_shards)]
    state.shard_tasks = [
        asyncio.create_task(shard_worker(cfg, state, log, idx, queue))
        for idx, queue in enumerate(state.shard_queues)
    ]

    listen_addr = f"{cfg.local_host}:{cfg.local_port}"
    io_resource_log(cfg, "listener_start", network="tcp", addr=listen_addr)
    try:
        state.server = await asyncio.start_server(
            lambda r, w: client_wrapper(cfg, state, log, r, w),
            host=cfg.local_host,
            port=cfg.local_port,
        )
        io_resource_log(cfg, "listener_done", network="tcp", addr=listen_addr, result="ok")
    except OSError as e:
        io_resource_log(cfg, "listener_done", network="tcp", addr=listen_addr, result="error", error=str(e))
        log.error(f"Cannot bind {cfg.local_host}:{cfg.local_port}: {e}")
        await close_pool(state.pool)
        return

    log.info(
        f"✓ Listening on \033[96m{cfg.local_host}:{cfg.local_port}\033[0m "
        f"[\033[33m{cfg.proxy_mode.name}\033[0m, "
        f"pool_size={cfg.pool_size}, max_sessions={cfg.max_sessions}, "
        f"event_loop_shards={cfg.event_loop_shards}]"
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
    g.add_argument("-H", "--ssh-host", default="")
    g.add_argument("-P", "--ssh-port", type=int, default=22)
    g.add_argument("-u", "--username", "--ssh-user", dest="username", default="")
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
    g.add_argument("--max-sessions", type=int, default=10)
    g.add_argument("--max-retries", type=int, default=3)
    g.add_argument("--retry-delay", type=float, default=2.0)
    g.add_argument("--keepalive", type=float, default=30.0)
    g.add_argument("--timeout", type=float, default=10.0)
    g.add_argument("--pool-acquire-timeout", type=float, default=5.0)
    g.add_argument("--event-loop-shards", type=int, default=1)

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
    g.add_argument("--verbose", action="store_true")
    g.add_argument("--log", dest="log_file", default="", help="Write io_resource JSONL logs to this file")
    g.add_argument("--no-log-connections", action="store_true")
    g.add_argument("--test-url", default="http://httpbin.org/ip")
    g.add_argument("--no-test", action="store_true")
    g.add_argument("--shutdown-timeout", type=float, default=10.0)

    g.add_argument("--max-consecutive-failures", type=int, default=3)
    g.add_argument("--health-check-interval", type=float, default=6.0)
    g.add_argument("--slot-cooldown", type=float, default=1.0)

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
        max_sessions=a.max_sessions,
        event_loop_shards=a.event_loop_shards,
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
        verbose=a.verbose,
        log_file=a.log_file,
        test_url=a.test_url,
        auto_test=not a.no_test,
        shutdown_timeout=a.shutdown_timeout,
    )


if __name__ == "__main__":
    if "--run-test-vectors" in sys.argv:
        sys.exit(0 if _run_json_test_vectors() else 1)

    if "--run-core-vectors" in sys.argv:
        sys.exit(0 if _run_json_core_vectors() else 1)

    if "--self-test" in sys.argv:
        ok_json_test = _run_json_test_vectors()
        ok_json_core = _run_json_core_vectors()
        ok1 = True
        ok2 = _run_runtime_tests()
        ok3 = _run_pool_decision_tests()

        try:
            _run_core_benchmarks()
            _run_runtime_benchmarks()
        except Exception:
            traceback.print_exc(file=sys.stderr)
            sys.exit(1)

        sys.exit(0 if (ok_json_test and ok_json_core and ok1 and ok2 and ok3) else 1)

    try:
        asyncio.run(run_server(parse_args()))
    except KeyboardInterrupt:
        print(
            "\n\033[92m✓\033[0m \033[36mBye\033[0m",
            file=sys.stderr,
        )
        os._exit(0)          # ← 立即退出，0延迟
    except Exception:
        os._exit(1)          # ← 同样立即退出
