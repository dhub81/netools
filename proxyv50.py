import asyncio
import argparse
import sys
import socket
import ipaddress
import time
import base64
import json
from typing import Tuple, Dict, Any, List, Optional, NamedTuple
from urllib.parse import urlparse
from dataclasses import dataclass, field
from collections import OrderedDict
from dns import message as dns_message
import colorama
import aiohttp
from aiohttp.abc import AbstractResolver
import ssl
import logging
from logging.handlers import RotatingFileHandler

# Linux: use uvloop for higher throughput (if available)
if sys.platform.startswith('linux'):
    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except Exception:
        pass

# =========================
# 初始化
# =========================
colorama.init(autoreset=True)

class Color:
    RESET = colorama.Style.RESET_ALL
    RED = colorama.Fore.RED
    GREEN = colorama.Fore.GREEN
    YELLOW = colorama.Fore.YELLOW
    BLUE = colorama.Fore.BLUE
    CYAN = colorama.Fore.CYAN
    DIM = colorama.Style.DIM

# =========================
# 配置数据类
# =========================
@dataclass
class ProxyConfig:
    """代理服务器配置"""
    host: str = '127.0.0.1'
    port: int = 8080
    doh_server: Optional[str] = None
    connect_timeout: float = 10.0
    header_timeout: float = 15.0
    bufsize: int = 8192
    max_connections: int = 100
    max_request_size: int = 10 * 1024 * 1024  # 10MB
    dns_cache_ttl: int = 300  # 5 minutes
    dns_cache_size: int = 1000
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    ssl_verify: bool = True
    enable_websocket: bool = True
    enable_http2: bool = False
    log_file: Optional[str] = None
    log_level: str = 'INFO'
    verbose: int = 0
    blacklist_domains: List[str] = field(default_factory=list)
    whitelist_domains: List[str] = field(default_factory=list)
    # 新增：出站连接偏好与端口复用（Linux）
    prefer_ipv4: bool = True
    reuse_port: Optional[bool] = None  # None=按平台默认（Linux=True，其他=False）

    @classmethod
    def from_file(cls, config_file: str) -> 'ProxyConfig':
        """从配置文件加载配置"""
        with open(config_file, 'r') as f:
            config_data = json.load(f)
        return cls(**config_data)

# =========================
# DNS缓存优化
# =========================
class DNSCacheEntry(NamedTuple):
    ip: str
    timestamp: float
    ttl: int = 300

class LRUDNSCache:
    """带TTL和LRU淘汰的DNS缓存"""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 300):
        self.cache: OrderedDict[Tuple[str, str], DNSCacheEntry] = OrderedDict()
        self.max_size = max_size
        self.default_ttl = default_ttl
        self.lock = asyncio.Lock()
        self.stats = {'hits': 0, 'misses': 0}
    
    async def get(self, key: Tuple[str, str]) -> Optional[str]:
        async with self.lock:
            if key not in self.cache:
                self.stats['misses'] += 1
                return None
            
            entry = self.cache[key]
            if time.time() - entry.timestamp > entry.ttl:
                # 过期了
                del self.cache[key]
                self.stats['misses'] += 1
                return None
            
            # 移到最后（最近使用）
            self.cache.move_to_end(key)
            self.stats['hits'] += 1
            return entry.ip
    
    async def set(self, key: Tuple[str, str], ip: str, ttl: Optional[int] = None):
        async with self.lock:
            if ttl is None:
                ttl = self.default_ttl
            
            # LRU淘汰
            if len(self.cache) >= self.max_size and key not in self.cache:
                self.cache.popitem(last=False)
            
            self.cache[key] = DNSCacheEntry(ip, time.time(), ttl)
    
    def get_stats(self) -> Dict[str, int]:
        return self.stats.copy()

# =========================
# 增强的日志系统
# =========================
class ProxyLogger:
    """统一的日志管理器"""
    
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.logger = logging.getLogger('proxy')
        self.logger.setLevel(getattr(logging, config.log_level.upper()))
        
        # 控制台输出
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(self._get_colored_formatter())
        self.logger.addHandler(console_handler)
        
        # 文件输出
        if config.log_file:
            file_handler = RotatingFileHandler(
                config.log_file, 
                maxBytes=10*1024*1024,  # 10MB
                backupCount=5
            )
            file_handler.setFormatter(self._get_file_formatter())
            self.logger.addHandler(file_handler)
    
    def _get_colored_formatter(self):
        """获取带颜色的格式化器"""
        class ColoredFormatter(logging.Formatter):
            COLORS = {
                'DEBUG': Color.DIM,
                'INFO': Color.CYAN,
                'WARNING': Color.YELLOW,
                'ERROR': Color.RED,
                'CRITICAL': Color.RED + colorama.Style.BRIGHT
            }
            
            def format(self, record):
                color = self.COLORS.get(record.levelname, '')
                record.levelname = f"{color}{record.levelname}{Color.RESET}"
                return super().format(record)
        
        return ColoredFormatter('[%(asctime)s] %(levelname)s - %(message)s')
    
    def _get_file_formatter(self):
        return logging.Formatter(
            '[%(asctime)s] %(levelname)s - %(funcName)s:%(lineno)d - %(message)s'
        )
    
    def debug(self, msg, *args, **kwargs):
        if self.config.verbose >= 3:
            self.logger.debug(msg, *args, **kwargs)
    
    def info(self, msg, *args, **kwargs):
        if self.config.verbose >= 1:
            self.logger.info(msg, *args, **kwargs)
    
    def warning(self, msg, *args, **kwargs):
        self.logger.warning(msg, *args, **kwargs)
    
    def error(self, msg, *args, **kwargs):
        self.logger.error(msg, *args, **kwargs)

# =========================
# 认证支持
# =========================
class ProxyAuthenticator:
    """HTTP基本认证"""
    
    def __init__(self, username: Optional[str], password: Optional[str]):
        self.enabled = bool(username and password)
        if self.enabled:
            self.expected_auth = base64.b64encode(
                f"{username}:{password}".encode()
            ).decode()
    
    def check_auth(self, headers: Dict[str, str]) -> Tuple[bool, Optional[str]]:
        """检查认证，返回(是否通过, 错误消息)"""
        if not self.enabled:
            return True, None
        
        auth_header = headers.get('proxy-authorization', '')
        if not auth_header.startswith('Basic '):
            return False, "Proxy authentication required"
        
        provided_auth = auth_header[6:]
        if provided_auth != self.expected_auth:
            return False, "Invalid credentials"
        
        return True, None
    
    def get_challenge_response(self) -> bytes:
        """获取407响应"""
        return (
            b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            b"Proxy-Authenticate: Basic realm=\"Proxy\"\r\n"
            b"Content-Length: 0\r\n"
            b"\r\n"
        )

# =========================
# 域名过滤器
# =========================
class DomainFilter:
    """域名黑白名单过滤"""
    
    def __init__(self, blacklist: List[str], whitelist: List[str]):
        self.blacklist = set(blacklist)
        self.whitelist = set(whitelist)
        self.use_whitelist = bool(whitelist)
    
    def is_allowed(self, domain: str) -> bool:
        """检查域名是否允许访问"""
        # 处理子域名
        parts = domain.lower().split('.')
        for i in range(len(parts)):
            test_domain = '.'.join(parts[i:])
            
            if self.use_whitelist:
                if test_domain in self.whitelist:
                    return True
            else:
                if test_domain in self.blacklist:
                    return False
        
        return not self.use_whitelist

# =========================
# 统计收集器
# =========================
class ProxyStats:
    """代理统计信息"""
    
    def __init__(self):
        self.requests_total = 0
        self.requests_success = 0
        self.requests_failed = 0
        self.bytes_sent = 0
        self.bytes_received = 0
        self.connections_active = 0
        self.connections_total = 0
        self.start_time = time.time()
        self.lock = asyncio.Lock()
    
    async def record_request(self, success: bool):
        async with self.lock:
            self.requests_total += 1
            if success:
                self.requests_success += 1
            else:
                self.requests_failed += 1
    
    async def record_bytes(self, sent: int, received: int):
        async with self.lock:
            self.bytes_sent += sent
            self.bytes_received += received
    
    async def connection_started(self):
        async with self.lock:
            self.connections_active += 1
            self.connections_total += 1
    
    async def connection_ended(self):
        async with self.lock:
            self.connections_active -= 1
    
    def get_stats(self) -> Dict[str, Any]:
        uptime = time.time() - self.start_time
        return {
            'uptime_seconds': uptime,
            'requests': {
                'total': self.requests_total,
                'success': self.requests_success,
                'failed': self.requests_failed,
                'success_rate': self.requests_success / max(1, self.requests_total)
            },
            'connections': {
                'active': self.connections_active,
                'total': self.connections_total
            },
            'bandwidth': {
                'sent_bytes': self.bytes_sent,
                'received_bytes': self.bytes_received,
                'sent_rate': self.bytes_sent / max(1, uptime),
                'received_rate': self.bytes_received / max(1, uptime)
            }
        }

# =========================
# WebSocket支持
# =========================
async def handle_websocket(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    target_host: str,
    target_port: int,
    headers: Dict[str, str],
    logger: ProxyLogger,
    stats: ProxyStats
):
    """处理WebSocket连接"""
    target_writer = None
    try:
        # 连接到目标服务器
        target_reader, target_writer = await asyncio.open_connection(target_host, target_port)
        
        # 转发升级请求
        request = f"GET / HTTP/1.1\r\n"
        for key, value in headers.items():
            if key.lower() not in ['proxy-authorization', 'proxy-connection']:
                request += f"{key}: {value}\r\n"
        request += "\r\n"
        
        target_writer.write(request.encode())
        await target_writer.drain()
        
        # 读取响应
        response_line = await target_reader.readline()
        client_writer.write(response_line)
        
        # 转发响应头
        while True:
            line = await target_reader.readline()
            client_writer.write(line)
            if line in (b'\r\n', b'\n'):
                break
        await client_writer.drain()
        
        # 双向转发数据
        async def forward(reader, writer, direction):
            bytes_since_drain = 0
            try:
                while True:
                    data = await reader.read(8192)
                    if not data:
                        break
                    writer.write(data)
                    bytes_since_drain += len(data)
                    if bytes_since_drain >= 64 * 1024:
                        await writer.drain()
                        bytes_since_drain = 0
                    if direction == 'client->target':
                        await stats.record_bytes(len(data), 0)
                    else:
                        await stats.record_bytes(0, len(data))
            except Exception as e:
                logger.debug(f"WebSocket forwarding error ({direction}): {e}")
            finally:
                try:
                    if bytes_since_drain:
                        await writer.drain()
                    if hasattr(writer, 'can_write_eof') and writer.can_write_eof():
                        writer.write_eof()
                        await writer.drain()
                    else:
                        writer.close()
                except Exception:
                    pass
        
        await asyncio.gather(
            forward(client_reader, target_writer, 'client->target'),
            forward(target_reader, client_writer, 'target->client')
        )
        
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
    finally:
        if target_writer:
            target_writer.close()

# =========================
# 改进的DoH解析器（用于 aiohttp）
# =========================
class EnhancedDohResolver(AbstractResolver):
    def __init__(self, config: ProxyConfig, dns_cache: LRUDNSCache, 
                 doh_session: aiohttp.ClientSession, logger: ProxyLogger):
        self.config = config
        self.dns_cache = dns_cache
        self.doh_session = doh_session
        self.logger = logger
    
    async def resolve(self, host: str, port: int = 0, family: int = 0):
        if is_ip_literal(host):
            return [{
                'hostname': host, 'host': host, 'port': port,
                'family': socket.AF_INET6 if ':' in host else socket.AF_INET,
                'proto': 0, 'flags': 0
            }]
        
        # 检查缓存
        cache_key = (host, 'A' if family != socket.AF_INET6 else 'AAAA')
        ip = await self.dns_cache.get(cache_key)
        
        if not ip:
            # DoH查询
            ip = await self._doh_query(host, cache_key[1])
            if ip:
                await self.dns_cache.set(cache_key, ip)
        
        if ip:
            return [{
                'hostname': host, 'host': ip, 'port': port,
                'family': socket.AF_INET6 if ':' in ip else socket.AF_INET,
                'proto': 0, 'flags': 0
            }]
        
        raise OSError(f"Could not resolve {host}")
    
    async def _doh_query(self, hostname: str, qtype: str) -> Optional[str]:
        """执行DoH查询"""
        if not self.config.doh_server:
            return None
        
        try:
            return await resolve_with_doh(
                hostname, qtype, self.config.doh_server, 
                self.doh_session, self.logger
            )
        except Exception as e:
            self.logger.error(f"DoH query failed for {hostname}/{qtype}: {e}")
            return None
    
    async def close(self):
        pass

# =========================
# 主代理服务器类
# =========================
class ProxyServer:
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.logger = ProxyLogger(config)
        self.stats = ProxyStats()
        self.dns_cache = LRUDNSCache(config.dns_cache_size, config.dns_cache_ttl)
        self.authenticator = ProxyAuthenticator(config.auth_username, config.auth_password)
        self.domain_filter = DomainFilter(config.blacklist_domains, config.whitelist_domains)
        self.semaphore = asyncio.Semaphore(config.max_connections)
        self.active_tasks: set = set()
        self.server = None
        self.doh_session = None
        self.http_session = None
    
    async def start(self):
        """启动代理服务器"""
        self.logger.info(f"Starting proxy server on {self.config.host}:{self.config.port}")
        
        # 初始化会话
        await self._init_sessions()
        
        # 启动服务器（Linux: backlog/reuse_port/TFO；其它平台自动回退）
        use_reuse_port = (sys.platform.startswith('linux') and (self.config.reuse_port if self.config.reuse_port is not None else True))
        try:
            self.server = await asyncio.start_server(
                self._handle_client,
                self.config.host,
                self.config.port,
                backlog=2048,
                reuse_port=use_reuse_port
            )
            if sys.platform.startswith('linux'):
                for s in self.server.sockets or []:
                    try:
                        TCP_FASTOPEN = getattr(socket, "TCP_FASTOPEN", 23)
                        s.setsockopt(socket.IPPROTO_TCP, TCP_FASTOPEN, 4096)
                    except Exception:
                        pass
        except Exception as e:
            self.logger.warning(f"start_server with reuse_port/backlog failed ({e}), falling back to defaults")
            self.server = await asyncio.start_server(self._handle_client, self.config.host, self.config.port)
        
        # 启动统计报告任务
        asyncio.create_task(self._report_stats())
        
        self.logger.info(f"Proxy server started successfully")
        
        async with self.server:
            await self.server.serve_forever()
    
    async def _init_sessions(self):
        """初始化HTTP会话"""
        # SSL上下文
        ssl_context = ssl.create_default_context()
        if not self.config.ssl_verify:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        # DoH会话
        if self.config.doh_server:
            connector = aiohttp.TCPConnector(ssl=ssl_context, limit=50)
            self.doh_session = aiohttp.ClientSession(connector=connector)
            self.logger.info(f"DoH enabled: {self.config.doh_server}")
        
        # HTTP会话 - 使用自定义解析器
        if self.config.doh_server:
            resolver = EnhancedDohResolver(
                self.config, self.dns_cache, self.doh_session, self.logger
            )
            connector = aiohttp.TCPConnector(
                resolver=resolver, 
                ssl=ssl_context,
                limit=self.config.max_connections,
                ttl_dns_cache=self.config.dns_cache_ttl
            )
        else:
            connector = aiohttp.TCPConnector(
                ssl=ssl_context,
                limit=self.config.max_connections,
                ttl_dns_cache=self.config.dns_cache_ttl
            )
        
        # 更合理的超时配置：避免 total=connect_timeout 导致大文件下载被提前中断
        self.http_session = aiohttp.ClientSession(
            connector=connector,
            auto_decompress=False,
            timeout=aiohttp.ClientTimeout(
                connect=self.config.connect_timeout,
                sock_connect=self.config.connect_timeout,
                sock_read=None  # 或设为较大的值，如 300
            )
        )
    
    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """处理客户端连接"""
        conn_id = hex(id(writer))
        await self.stats.connection_started()
        
        try:
            self.logger.info(f"[{conn_id}] New connection from {writer.get_extra_info('peername')}")
            
            # 入站 socket 低延迟设置
            try:
                csock = writer.get_extra_info('socket')
                if csock:
                    csock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    if sys.platform.startswith('linux') and hasattr(socket, "TCP_QUICKACK"):
                        csock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
                    csock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except Exception:
                pass
            
            # 处理请求
            await self._process_client_requests(reader, writer, conn_id)
            
        except Exception as e:
            self.logger.error(f"[{conn_id}] Connection error: {e}")
        finally:
            await self.stats.connection_ended()
            writer.close()
            await writer.wait_closed()
            self.logger.info(f"[{conn_id}] Connection closed")
    
    async def _process_client_requests(self, reader: asyncio.StreamReader, 
                                       writer: asyncio.StreamWriter, conn_id: str):
        """处理客户端的多个请求（HTTP/1.1 keep-alive）"""
        while True:
            try:
                # 读取请求行
                request_line = await asyncio.wait_for(
                    reader.readline(), 
                    timeout=self.config.header_timeout
                )
                
                if not request_line:
                    break
                
                # 解析请求
                request = self._parse_request(request_line)
                if not request:
                    writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                    await writer.drain()
                    break
                
                # 读取请求头
                headers = await self._read_headers(reader)
                
                # 认证检查
                auth_ok, auth_msg = self.authenticator.check_auth(headers)
                if not auth_ok:
                    writer.write(self.authenticator.get_challenge_response())
                    await writer.drain()
                    continue
                
                # 域名过滤
                host = headers.get('host', '')
                if not self.domain_filter.is_allowed(host):
                    self.logger.warning(f"[{conn_id}] Blocked domain: {host}")
                    writer.write(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                    await writer.drain()
                    continue
                
                # 处理请求
                if request['method'] == 'CONNECT':
                    await self._handle_connect(reader, writer, request, headers, conn_id)
                    break  # CONNECT后连接被隧道接管
                elif self.config.enable_websocket and self._is_websocket(headers):
                    await self._handle_websocket(reader, writer, request, headers, conn_id)
                    break  # WebSocket后连接被接管
                else:
                    keep_alive = await self._handle_http(reader, writer, request, headers, conn_id)
                    if not keep_alive:
                        break
                        
            except asyncio.TimeoutError:
                self.logger.debug(f"[{conn_id}] Client timeout")
                break
            except Exception as e:
                self.logger.error(f"[{conn_id}] Request processing error: {e}")
                break
    
    def _parse_request(self, request_line: bytes) -> Optional[Dict[str, str]]:
        """解析HTTP请求行"""
        try:
            parts = request_line.decode('latin-1').strip().split()
            if len(parts) != 3:
                return None
            return {
                'method': parts[0].upper(),
                'url': parts[1],
                'version': parts[2]
            }
        except Exception:
            return None
    
    async def _read_headers(self, reader: asyncio.StreamReader) -> Dict[str, str]:
        """读取HTTP请求头"""
        headers = {}
        total_size = 0
        
        while True:
            line = await asyncio.wait_for(
                reader.readline(),
                timeout=self.config.header_timeout
            )
            
            if line in (b'\r\n', b'\n', b''):
                break
            
            total_size += len(line)
            if total_size > 8192:  # 防止头部过大
                raise ValueError("Headers too large")
            
            try:
                key, value = line.decode('latin-1').strip().split(':', 1)
                headers[key.strip().lower()] = value.strip()
            except Exception:
                continue
        
        return headers
    
    def _is_websocket(self, headers: Dict[str, str]) -> bool:
        """检查是否是WebSocket升级请求"""
        return (
            headers.get('upgrade', '').lower() == 'websocket' and
            'websocket' in headers.get('connection', '').lower()
        )
    
    async def _handle_connect(self, reader, writer, request, headers, conn_id):
        """处理CONNECT请求（HTTPS代理）"""
        try:
            # 解析目标地址
            host, _, port = request['url'].partition(':')
            port = int(port) if port else 443
            
            self.logger.info(f"[{conn_id}] CONNECT to {host}:{port}")
            
            # 连接目标服务器（DoH/系统解析 + 并发抢“首个成功连接”）
            async with self.semaphore:
                target_reader, target_writer = await asyncio.wait_for(
                    self._connect_happy_eyeballs(host, port, self.config.connect_timeout),
                    timeout=self.config.connect_timeout
                )
            
            # 出站 socket 低延迟设置
            try:
                tsock = target_writer.get_extra_info('socket')
                if tsock:
                    tsock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    if sys.platform.startswith('linux') and hasattr(socket, "TCP_QUICKACK"):
                        tsock.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
                    tsock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except Exception:
                pass
            
            # 发送200响应
            writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
            await writer.drain()
            
            # 双向转发
            await self._relay_tunnel(reader, writer, target_reader, target_writer, conn_id)
            
            await self.stats.record_request(True)
            
        except Exception as e:
            self.logger.error(f"[{conn_id}] CONNECT error: {e}")
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            await self.stats.record_request(False)
    
    async def _handle_websocket(self, reader, writer, request, headers, conn_id):
        """处理WebSocket请求"""
        host = headers.get('host', '')
        port = 80  # 默认端口
        
        if ':' in host:
            host, port_str = host.split(':', 1)
            port = int(port_str)
        
        self.logger.info(f"[{conn_id}] WebSocket upgrade to {host}:{port}")
        
        await handle_websocket(reader, writer, host, port, headers, self.logger, self.stats)
        await self.stats.record_request(True)
    
    async def _handle_http(self, reader, writer, request, headers, conn_id) -> bool:
        """处理普通HTTP请求，返回是否保持连接"""
        try:
            # 读取请求体
            body = None
            if content_length := headers.get('content-length'):
                size = int(content_length)
                if size > self.config.max_request_size:
                    raise ValueError("Request body too large")
                if size > 0:
                    body = await reader.readexactly(size)
            
            # 构造目标URL
            url = request['url']
            if not url.startswith('http'):
                url = f"http://{headers['host']}{url}"
            
            self.logger.info(f"[{conn_id}] {request['method']} {url}")
            
            # 清理代理相关头部
            clean_headers = {
                k: v for k, v in headers.items()
                if k.lower() not in ['proxy-authorization', 'proxy-connection']
            }
            
            # 发送请求
            async with self.http_session.request(
                request['method'],
                url,
                headers=clean_headers,
                data=body,
                allow_redirects=False
            ) as response:
                
                # 写入响应状态行
                status_line = f"HTTP/1.1 {response.status} {response.reason}\r\n"
                writer.write(status_line.encode())
                
                # 写入响应头
                keep_alive = self._write_response_headers(
                    writer, response.headers, request['version'], headers
                )
                
                # 写入响应体（阈值合并 drain）
                bytes_received = 0
                bytes_since_drain = 0
                async for chunk in response.content.iter_chunked(65536):
                    writer.write(chunk)
                    n = len(chunk)
                    bytes_received += n
                    bytes_since_drain += n
                    if bytes_since_drain >= 128 * 1024:
                        await writer.drain()
                        bytes_since_drain = 0
                if bytes_since_drain:
                    await writer.drain()
                
                await self.stats.record_bytes(len(body) if body else 0, bytes_received)
                await self.stats.record_request(True)
                
                return keep_alive
                
        except Exception as e:
            self.logger.error(f"[{conn_id}] HTTP handling error: {e}")
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            await self.stats.record_request(False)
            return False
    
    def _write_response_headers(self, writer, resp_headers, req_version, req_headers) -> bool:
        """写入响应头并判断是否保持连接"""
        # Hop-by-hop headers that should not be forwarded
        hop_by_hop = {
            'connection', 'keep-alive', 'proxy-authenticate',
            'proxy-authorization', 'te', 'trailers',
            'transfer-encoding', 'upgrade'
        }
        
        # 判断是否保持连接
        client_connection = req_headers.get('connection', '').lower()
        server_connection = resp_headers.get('Connection', '').lower()
        
        keep_alive = True
        if req_version == 'HTTP/1.0':
            keep_alive = 'keep-alive' in client_connection
        else:
            keep_alive = 'close' not in client_connection
        
        if 'close' in server_connection:
            keep_alive = False
        
        # 写入响应头
        for key, value in resp_headers.items():
            if key.lower() not in hop_by_hop:
                writer.write(f"{key}: {value}\r\n".encode())
        
        # 添加Connection头
        connection_value = 'keep-alive' if keep_alive else 'close'
        writer.write(f"Connection: {connection_value}\r\n".encode())
        writer.write(b"\r\n")
        
        return keep_alive
    
    async def _relay_tunnel(self, c_reader, c_writer, t_reader, t_writer, conn_id):
        """双向转发数据（用于CONNECT隧道）"""
        async def relay(reader, writer, direction):
            bufsize = 65536 if direction == 'T->C' else max(4096, self.config.bufsize)
            threshold = 128 * 1024 if direction == 'T->C' else 32 * 1024
            sent_since_drain = 0
            total_c2t = total_t2c = 0
            try:
                while True:
                    data = await reader.read(bufsize)
                    if not data:
                        break
                    writer.write(data)
                    sent_since_drain += len(data)
                    if sent_since_drain >= threshold:
                        await writer.drain()
                        sent_since_drain = 0
                    if direction == 'C->T':
                        total_c2t += len(data)
                    else:
                        total_t2c += len(data)
            except Exception:
                pass
            finally:
                try:
                    if sent_since_drain:
                        await writer.drain()
                    if hasattr(writer, "can_write_eof") and writer.can_write_eof():
                        writer.write_eof()
                        await writer.drain()
                    else:
                        writer.close()
                except Exception:
                    pass
                # 聚合后再记账，减少热路径 await
                try:
                    if direction == 'C->T':
                        await self.stats.record_bytes(total_c2t, 0)
                    else:
                        await self.stats.record_bytes(0, total_t2c)
                except Exception:
                    pass
        
        await asyncio.gather(
            relay(c_reader, t_writer, 'C->T'),
            relay(t_reader, c_writer, 'T->C')
        )
    
    async def _report_stats(self):
        """定期报告统计信息"""
        while True:
            await asyncio.sleep(60)  # 每分钟报告一次
            stats = self.stats.get_stats()
            cache_stats = self.dns_cache.get_stats()
            
            self.logger.info(
                f"Stats - Requests: {stats['requests']['total']} "
                f"(success: {stats['requests']['success_rate']:.1%}), "
                f"Active connections: {stats['connections']['active']}, "
                f"Bandwidth: ↑{stats['bandwidth']['sent_bytes']/1024/1024:.1f}MB "
                f"↓{stats['bandwidth']['received_bytes']/1024/1024:.1f}MB "
                # f"DNS cache: {cache_stats['hits']}/{cache_stats['hits']+cache_stats['misses']}"
            )
    
    async def shutdown(self):
        """优雅关闭服务器"""
        self.logger.info("Shutting down proxy server...")
        
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        # 取消所有活动任务
        for task in self.active_tasks:
            task.cancel()
        
        if self.active_tasks:
            await asyncio.gather(*self.active_tasks, return_exceptions=True)
        
        # 关闭会话
        if self.doh_session:
            await self.doh_session.close()
        if self.http_session:
            await self.http_session.close()
        
        self.logger.info("Proxy server shutdown complete")

# =========================
# 辅助函数
# =========================
def is_ip_literal(host: str) -> bool:
    """检查是否是IP地址"""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False

async def resolve_with_doh(hostname: str, qtype: str, doh_server: str, 
                           session: aiohttp.ClientSession, logger: ProxyLogger) -> Optional[str]:
    """使用DoH解析域名（返回单个记录）"""
    try:
        path = urlparse(doh_server).path.rstrip('/')
        if path.endswith('/resolve'):
            # JSON API format
            type_code = 1 if qtype == 'A' else 28
            url = f"{doh_server}?name={hostname}&type={type_code}"
            headers = {'accept': 'application/dns-json'}
            
            async with session.get(url, headers=headers, timeout=10) as response:
                if response.status != 200:
                    return None
                    
                resp_json = await response.json(content_type=None)
                if resp_json.get('Status') == 0 and 'Answer' in resp_json:
                    for answer in resp_json.get('Answer', []):
                        if answer.get('type') == type_code:
                            return answer['data']
        else:
            # RFC8484 binary format
            query = dns_message.make_query(hostname, qtype)
            wire_query = query.to_wire()
            headers = {
                'accept': 'application/dns-message',
                'content-type': 'application/dns-message'
            }
            
            async with session.post(doh_server, headers=headers, data=wire_query, timeout=10) as response:
                if response.status != 200:
                    return None
                    
                wire_response = await response.read()
                dns_response = dns_message.from_wire(wire_response)
                
                for answer in dns_response.answer:
                    if (qtype == 'A' and answer.rdtype == 1) or (qtype == 'AAAA' and answer.rdtype == 28):
                        return answer[0].to_text()
        
        return None
        
    except Exception as e:
        logger.error(f"DoH resolution error for {hostname}/{qtype}: {e}")
        return None

async def resolve_with_doh_multi(hostname: str, qtype: str, doh_server: str, 
                                 session: aiohttp.ClientSession, logger: 'ProxyLogger') -> List[str]:
    """DoH 多记录解析，返回所有 A/AAAA 记录"""
    ips: List[str] = []
    try:
        path = urlparse(doh_server).path.rstrip('/')
        if path.endswith('/resolve'):
            # JSON API
            type_code = 1 if qtype == 'A' else 28
            url = f"{doh_server}?name={hostname}&type={type_code}"
            headers = {'accept': 'application/dns-json'}
            async with session.get(url, headers=headers, timeout=10) as response:
                if response.status != 200:
                    return []
                resp_json = await response.json(content_type=None)
                if resp_json.get('Status') == 0 and 'Answer' in resp_json:
                    for answer in resp_json.get('Answer', []):
                        if answer.get('type') == type_code:
                            ip = answer.get('data')
                            if ip and ip not in ips:
                                ips.append(ip)
        else:
            # RFC8484 binary
            query = dns_message.make_query(hostname, qtype)
            wire_query = query.to_wire()
            headers = {
                'accept': 'application/dns-message',
                'content-type': 'application/dns-message'
            }
            async with session.post(doh_server, headers=headers, data=wire_query, timeout=10) as response:
                if response.status != 200:
                    return []
                wire_response = await response.read()
                dns_response = dns_message.from_wire(wire_response)
                for answer in dns_response.answer:
                    if (qtype == 'A' and answer.rdtype == 1) or (qtype == 'AAAA' and answer.rdtype == 28):
                        ip = answer[0].to_text()
                        if ip and ip not in ips:
                            ips.append(ip)
        return ips
    except Exception as e:
        logger.error(f"DoH multi resolution error for {hostname}/{qtype}: {e}")
        return []

# ========== 连接与解析辅助 ==========
async def getaddrinfo_ips(host: str, port: int) -> List[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(
        host, port, proto=socket.IPPROTO_TCP
    )
    ips: List[str] = []
    for family, _, _, _, sockaddr in infos:
        ip = sockaddr[0]
        if ip not in ips:
            ips.append(ip)
    return ips

# 将 DoH 多记录与系统解析结合，供 CONNECT 并发建连使用
async def resolve_ips_for_connect(host: str, port: int, doh_server: Optional[str],
                                  doh_session: Optional[aiohttp.ClientSession],
                                  logger: ProxyLogger) -> List[str]:
    if is_ip_literal(host):
        return [host]
    ips: List[str] = []
    if doh_server and doh_session:
        v4_task = asyncio.create_task(resolve_with_doh_multi(host, 'A', doh_server, doh_session, logger))
        v6_task = asyncio.create_task(resolve_with_doh_multi(host, 'AAAA', doh_server, doh_session, logger))
        v4, v6 = await asyncio.gather(v4_task, v6_task, return_exceptions=True)
        if isinstance(v4, list):
            ips.extend(v4)
        if isinstance(v6, list):
            ips.extend(v6)
    if not ips:
        ips = await getaddrinfo_ips(host, port)
    return ips

# 并发连接多个 IP，返回第一个成功的连接，正确清理其它任务
async def connect_first_success(ips: List[str], port: int, timeout: float):
    loop = asyncio.get_running_loop()
    tasks = [loop.create_task(asyncio.open_connection(ip, port)) for ip in ips]
    winner_result = None
    last_exc = None
    try:
        for fut in asyncio.as_completed(tasks, timeout=timeout):
            try:
                result = await fut
                winner_result = result
                break
            except Exception as e:
                last_exc = e
                continue
    except asyncio.TimeoutError as e:
        last_exc = e
    finally:
        # 取消并收割其余任务，避免 "Task exception was never retrieved"
        for t in tasks:
            if not t.done():
                t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
    if winner_result:
        return winner_result
    raise last_exc or OSError("All connection attempts failed")

# ========== 供 ProxyServer 使用的 Happy Eyeballs 连接函数 ==========
async def _connect_happy_eyeballs(self, host: str, port: int, timeout: float):
    if is_ip_literal(host):
        return await asyncio.open_connection(host, port)
    ips = await resolve_ips_for_connect(host, port, self.config.doh_server, self.doh_session, self.logger)
    if not ips:
        raise OSError(f"Could not resolve {host}")
    # 根据偏好重排：优先 IPv4 或 IPv6
    if self.config.prefer_ipv4:
        ips = [ip for ip in ips if ':' not in ip] + [ip for ip in ips if ':' in ip]
    else:
        ips = [ip for ip in ips if ':' in ip] + [ip for ip in ips if ':' not in ip]
    return await connect_first_success(ips, port, timeout)

# 动态绑定到类（减少对原结构的侵入）
ProxyServer._connect_happy_eyeballs = _connect_happy_eyeballs

# =========================
# 主函数
# =========================
async def main():
    parser = argparse.ArgumentParser(
        description="Enhanced Asyncio HTTP/HTTPS Proxy Server",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    # 基本选项
    parser.add_argument('--config', help="Configuration file (JSON)")
    parser.add_argument('--host', default='127.0.0.1', help="Host to bind to")
    parser.add_argument('--port', type=int, default=8080, help="Port to listen on")
    
    # DoH选项
    parser.add_argument('--doh-server', help="DoH server URL")
    parser.add_argument('--dns-cache-ttl', type=int, default=300, help="DNS cache TTL in seconds")
    parser.add_argument('--dns-cache-size', type=int, default=1000, help="DNS cache max size")
    
    # 认证选项
    parser.add_argument('--auth-user', help="Username for proxy authentication")
    parser.add_argument('--auth-pass', help="Password for proxy authentication")
    
    # 性能选项
    parser.add_argument('--max-connections', type=int, default=100, help="Max concurrent connections")
    parser.add_argument('--max-request-size', type=int, default=10*1024*1024, help="Max request body size")
    parser.add_argument('--connect-timeout', type=float, default=10.0, help="Connection timeout")
    parser.add_argument('--header-timeout', type=float, default=15.0, help="Header read timeout")
    parser.add_argument('--bufsize', type=int, default=4096, help="Buffer size")
    # 出站连接偏好与端口复用
    parser.add_argument('--prefer-ipv4', action='store_true', help="Prefer IPv4 for outbound connects")
    parser.add_argument('--prefer-ipv6', action='store_true', help="Prefer IPv6 for outbound connects")
    parser.add_argument('--no-reuse-port', action='store_true', help="Disable SO_REUSEPORT on Linux")
    
    # 功能开关
    parser.add_argument('--enable-websocket', action='store_true', help="Enable WebSocket support")
    parser.add_argument('--enable-http2', action='store_true', help="Enable HTTP/2 support (experimental)")
    parser.add_argument('--ssl-verify', action='store_true', help="Verify SSL certificates")
    
    # 过滤选项
    parser.add_argument('--blacklist', nargs='+', help="Blacklisted domains")
    parser.add_argument('--whitelist', nargs='+', help="Whitelisted domains (if set, only these are allowed)")
    
    # 日志选项
    parser.add_argument('--log-file', help="Log file path")
    parser.add_argument('--log-level', default='INFO', 
                       choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       help="Logging level")
    parser.add_argument('-v', '--verbose', action='count', default=0,
                       help="Increase verbosity")
    
    args = parser.parse_args()
    
    # 加载配置
    if args.config:
        config = ProxyConfig.from_file(args.config)
        # 命令行参数覆盖配置文件
        for key, value in vars(args).items():
            if value is not None and key != 'config':
                setattr(config, key, value)
    else:
        config = ProxyConfig(
            host=args.host,
            port=args.port,
            doh_server=args.doh_server,
            dns_cache_ttl=args.dns_cache_ttl,
            dns_cache_size=args.dns_cache_size,
            auth_username=args.auth_user,
            auth_password=args.auth_pass,
            max_connections=args.max_connections,
            max_request_size=args.max_request_size,
            connect_timeout=args.connect_timeout,
            header_timeout=args.header_timeout,
            bufsize=args.bufsize,
            enable_websocket=args.enable_websocket,
            enable_http2=args.enable_http2,
            ssl_verify=args.ssl_verify,
            blacklist_domains=args.blacklist or [],
            whitelist_domains=args.whitelist or [],
            log_file=args.log_file,
            log_level=args.log_level,
            verbose=args.verbose
        )
        # 偏好开关
        if args.prefer_ipv6:
            config.prefer_ipv4 = False
        elif args.prefer_ipv4:
            config.prefer_ipv4 = True
        # reuse_port（仅 Linux 生效）
        if sys.platform.startswith('linux'):
            if args.no_reuse_port:
                config.reuse_port = False
            else:
                config.reuse_port = True
        else:
            config.reuse_port = False
    
    # 创建并启动服务器
    server = ProxyServer(config)
    
    try:
        await server.start()
    except KeyboardInterrupt:
        print("\nReceived interrupt signal")
    finally:
        await server.shutdown()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nGoodbye!")