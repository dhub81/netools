#!/usr/bin/env python3
import sys
import asyncio
if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import argparse
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Optional, Dict, List
import traceback
from collections import deque
import struct

try:
    import asyncssh
except ImportError:
    print("Error: asyncssh library not found. Please install it using 'pip install asyncssh'", file=sys.stderr)
    sys.exit(1)

# ========== 优化1: 无锁统计收集器 ==========
class LockFreeStats:
    """使用原子操作和缓冲区减少锁竞争"""
    def __init__(self):
        self.bytes_sent = 0
        self.bytes_received = 0
        self.total_connections = 0
        self.current_connections = 0
        self.peak_connections = 0
        
        # 使用缓冲区批量更新统计
        self._pending_updates = asyncio.Queue(maxsize=1000)
        self._update_task = None
    
    async def start(self):
        """启动后台统计更新任务"""
        self._update_task = asyncio.create_task(self._batch_update_worker())
    
    async def stop(self):
        """停止统计更新任务"""
        if self._update_task:
            self._update_task.cancel()
            try:
                await self._update_task
            except asyncio.CancelledError:
                pass
    
    async def _batch_update_worker(self):
        """批量处理统计更新，减少锁竞争"""
        while True:
            updates = []
            try:
                # 批量收集更新（最多等待0.1秒或100条）
                deadline = asyncio.get_event_loop().time() + 0.1
                while len(updates) < 100:
                    timeout = deadline - asyncio.get_event_loop().time()
                    if timeout <= 0:
                        break
                    update = await asyncio.wait_for(
                        self._pending_updates.get(), 
                        timeout=timeout
                    )
                    updates.append(update)
            except asyncio.TimeoutError:
                pass
            
            # 批量应用更新
            if updates:
                for update_type, value in updates:
                    if update_type == 'traffic_sent':
                        self.bytes_sent += value
                    elif update_type == 'traffic_received':
                        self.bytes_received += value
                    elif update_type == 'connection':
                        self.current_connections += value
                        if value > 0:
                            self.total_connections += 1
                            self.peak_connections = max(
                                self.peak_connections, 
                                self.current_connections
                            )
    
    async def add_traffic_nowait(self, sent: int = 0, received: int = 0):
        """非阻塞地添加流量统计"""
        try:
            if sent > 0:
                self._pending_updates.put_nowait(('traffic_sent', sent))
            if received > 0:
                self._pending_updates.put_nowait(('traffic_received', received))
        except asyncio.QueueFull:
            # 队列满时直接丢弃统计（在高负载下可接受）
            pass
    
    async def update_connections_nowait(self, delta: int):
        """非阻塞地更新连接数"""
        try:
            self._pending_updates.put_nowait(('connection', delta))
        except asyncio.QueueFull:
            pass

# ========== 优化2: 连接池管理 ==========
class SSHConnectionPool:
    """SSH连接池，支持多个SSH连接以提高带宽"""
    def __init__(self, config: 'ProxyConfig', pool_size: int = 3):
        self.config = config
        self.pool_size = pool_size
        self.connections: List[Optional[asyncssh.SSHClientConnection]] = []
        self.connection_usage = []  # 跟踪每个连接的使用次数
        self._lock = asyncio.Lock()
        self.logger = logging.getLogger(self.__class__.__name__)
    
    async def initialize(self):
        """初始化连接池"""
        for i in range(self.pool_size):
            conn = await self._create_connection(i)
            self.connections.append(conn)
            self.connection_usage.append(0)
    
    async def _create_connection(self, index: int) -> Optional[asyncssh.SSHClientConnection]:
        """创建单个SSH连接"""
        try:
            conn = await asyncio.wait_for(asyncssh.connect(
                host=self.config.ssh_host,
                port=self.config.ssh_port,
                username=self.config.ssh_user,
                password=self.config.ssh_password,
                client_keys=[self.config.ssh_key] if self.config.ssh_key else None,
                known_hosts=None
            ), timeout=15)
            self.logger.info(f"✓ SSH connection #{index} established")
            return conn
        except Exception as e:
            self.logger.error(f"Failed to create SSH connection #{index}: {e}")
            return None
    
    async def get_connection(self) -> Optional[asyncssh.SSHClientConnection]:
        """获取负载最低的可用连接"""
        async with self._lock:
            # 查找使用次数最少的活跃连接
            best_idx = -1
            min_usage = float('inf')
            
            for i, conn in enumerate(self.connections):
                if conn and not conn.is_closed():
                    if self.connection_usage[i] < min_usage:
                        min_usage = self.connection_usage[i]
                        best_idx = i
                elif conn is None or conn.is_closed():
                    # 尝试重建死连接
                    self.connections[i] = await self._create_connection(i)
                    if self.connections[i]:
                        self.connection_usage[i] = 0
                        return self.connections[i]
            
            if best_idx >= 0:
                self.connection_usage[best_idx] += 1
                return self.connections[best_idx]
            
            return None
    
    async def release_connection(self, conn: asyncssh.SSHClientConnection):
        """释放连接（减少使用计数）"""
        async with self._lock:
            for i, c in enumerate(self.connections):
                if c is conn:
                    self.connection_usage[i] = max(0, self.connection_usage[i] - 1)
                    break
    
    def close_all(self):
        """关闭所有连接"""
        for conn in self.connections:
            if conn and not conn.is_closed():
                conn.close()

# ========== 优化3: 自适应缓冲区 ==========
class AdaptiveBuffer:
    """根据网络速度自动调整缓冲区大小"""
    def __init__(self, min_size: int = 4096, max_size: int = 262144):  # 4KB - 256KB
        self.min_size = min_size
        self.max_size = max_size
        self.current_size = min_size
        self.last_read_time = time.monotonic()
        self.throughput_history = deque(maxlen=10)
    
    def adjust_size(self, bytes_read: int, time_taken: float):
        """根据吞吐量动态调整缓冲区大小"""
        if time_taken > 0:
            throughput = bytes_read / time_taken
            self.throughput_history.append(throughput)
            
            if len(self.throughput_history) >= 3:
                avg_throughput = sum(self.throughput_history) / len(self.throughput_history)
                
                # 根据平均吞吐量调整缓冲区
                if avg_throughput > 1024 * 1024:  # > 1MB/s
                    self.current_size = min(self.current_size * 2, self.max_size)
                elif avg_throughput < 100 * 1024 and self.current_size > self.min_size:  # < 100KB/s
                    self.current_size = max(self.current_size // 2, self.min_size)
    
    def get_size(self) -> int:
        return self.current_size

# ========== 优化4: 改进的ProxyServer ==========
@dataclass
class ProxyConfig:
    ssh_host: str
    ssh_user: str
    ssh_port: int = 22
    ssh_password: str = None
    ssh_key: str = None
    local_host: str = '127.0.0.1'
    local_port: int = 3128
    remote_proxy_host: str = '127.0.0.1'
    remote_proxy_port: int = 3128
    test_url: str = 'https://www.google.com'
    reconnect_delay: int = 5
    max_retries: int = 5
    # 新增配置项
    pool_size: int = 3  # SSH连接池大小
    buffer_size: str = 'adaptive'  # 'fixed' 或 'adaptive'
    log_connections: bool = False  # 是否记录每个连接

class OptimizedProxyServer:
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.stats = LockFreeStats()
        self.logger = logging.getLogger(self.__class__.__name__)
        self.ssh_pool = SSHConnectionPool(config, config.pool_size)
        self._server: asyncio.AbstractServer = None
        self._shutdown_event = asyncio.Event()
        
        # 性能监控
        self.perf_metrics = {
            'avg_latency': deque(maxlen=100),
            'throughput': deque(maxlen=100),
        }
    
    async def start(self):
        """启动代理服务器"""
        self.logger.info(f"Initializing SSH connection pool (size={self.config.pool_size})...")
        await self.ssh_pool.initialize()
        await self.stats.start()
        
        try:
            self._server = await asyncio.start_server(
                self.handle_client, 
                self.config.local_host, 
                self.config.local_port
            )
            server_addr = self._server.sockets[0].getsockname()
            self.logger.info(f"✓ Optimized proxy server started on {server_addr[0]}:{server_addr[1]}")
            
            # 启动监控任务
            monitor_task = asyncio.create_task(self._monitor_performance())
            
            await self._run_proxy_test()
            await self._shutdown_event.wait()
            
            monitor_task.cancel()
            
        except OSError as e:
            self.logger.critical(f"Failed to start server: {e}")
        finally:
            await self.stop()
    
    async def stop(self):
        """停止服务器"""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        
        await self.stats.stop()
        self.ssh_pool.close_all()
        self._shutdown_event.set()
        
        self.logger.info("Server stopped.")
        self._log_final_stats()
    
    async def handle_client(self, client_reader: asyncio.StreamReader, 
                           client_writer: asyncio.StreamWriter):
        """处理客户端连接（优化版）"""
        client_addr = client_writer.get_extra_info('peername')
        
        await self.stats.update_connections_nowait(1)
        
        if self.config.log_connections:
            self.logger.info(f"Connection from {client_addr}")
        
        remote_writer = None
        ssh_conn = None
        
        try:
            # 从连接池获取SSH连接
            ssh_conn = await self.ssh_pool.get_connection()
            if not ssh_conn:
                self.logger.error(f"[{client_addr}] No available SSH connection")
                return
            
            # 建立远程连接
            remote_reader, remote_writer = await ssh_conn.open_connection(
                self.config.remote_proxy_host, 
                self.config.remote_proxy_port
            )
            
            # 创建自适应缓冲区
            c2s_buffer = AdaptiveBuffer() if self.config.buffer_size == 'adaptive' else None
            s2c_buffer = AdaptiveBuffer() if self.config.buffer_size == 'adaptive' else None
            
            # 并行数据传输
            pipe1 = self._optimized_pipe_data(
                client_reader, remote_writer, 'C->S', c2s_buffer
            )
            pipe2 = self._optimized_pipe_data(
                remote_reader, client_writer, 'S->C', s2c_buffer
            )
            
            await asyncio.gather(pipe1, pipe2)
            
        except Exception as e:
            if self.config.log_connections:
                self.logger.debug(f"[{client_addr}] Connection error: {e}")
        finally:
            # 清理资源
            if remote_writer:
                remote_writer.close()
                await remote_writer.wait_closed()
            
            if not client_writer.is_closing():
                client_writer.close()
                await client_writer.wait_closed()
            
            if ssh_conn:
                await self.ssh_pool.release_connection(ssh_conn)
            
            await self.stats.update_connections_nowait(-1)
    
    async def _optimized_pipe_data(self, reader: asyncio.StreamReader, 
                                  writer: asyncio.StreamWriter, 
                                  direction: str,
                                  adaptive_buffer: Optional[AdaptiveBuffer] = None):
        """优化的数据传输管道"""
        try:
            while not reader.at_eof() and not writer.is_closing():
                # 动态缓冲区大小
                buffer_size = adaptive_buffer.get_size() if adaptive_buffer else 65536
                
                start_time = time.monotonic()
                data = await reader.read(buffer_size)
                if not data:
                    break
                
                writer.write(data)
                await writer.drain()
                
                # 更新统计（非阻塞）
                if direction == 'C->S':
                    await self.stats.add_traffic_nowait(sent=len(data))
                else:
                    await self.stats.add_traffic_nowait(received=len(data))
                
                # 调整缓冲区大小
                if adaptive_buffer:
                    elapsed = time.monotonic() - start_time
                    adaptive_buffer.adjust_size(len(data), elapsed)
                
                # 记录吞吐量
                if len(data) > 0 and (time.monotonic() - start_time) > 0:
                    throughput = len(data) / (time.monotonic() - start_time)
                    self.perf_metrics['throughput'].append(throughput)
                    
        except (OSError, asyncssh.Error, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            if not writer.is_closing():
                writer.close()
                try:
                    await writer.wait_closed()
                except:
                    pass
    
    async def _monitor_performance(self):
        """性能监控任务"""
        start_time = time.monotonic()
        last_bytes_sent = 0
        last_bytes_received = 0
        
        while not self._shutdown_event.is_set():
            await asyncio.sleep(10)
            
            current_time = time.monotonic()
            elapsed = current_time - start_time
            
            # 计算实时速率
            bytes_sent_delta = self.stats.bytes_sent - last_bytes_sent
            bytes_received_delta = self.stats.bytes_received - last_bytes_received
            
            upload_speed = bytes_sent_delta / 10  # 每秒字节数
            download_speed = bytes_received_delta / 10
            
            last_bytes_sent = self.stats.bytes_sent
            last_bytes_received = self.stats.bytes_received
            
            # 格式化输出
            uptime = f"[{int(elapsed//3600):02d}h{int((elapsed%3600)//60):02d}m{int(elapsed%60):02d}s]"
            total_traffic = (f"↑{self._format_bytes(self.stats.bytes_sent)} "
                             f"↓{self._format_bytes(self.stats.bytes_received)}")
            upload_speed_str = f"↑{self._format_bytes(upload_speed)}/s"
            download_speed_str = f"↓{self._format_bytes(download_speed)}/s"
            speed = f"Speed: {upload_speed_str:<14} {download_speed_str}"
            conns = f"Conns: {self.stats.current_connections}/{self.stats.peak_connections}"
            # Pad total_traffic for '|' alignment, and upload_speed_str is padded within 'speed'
            self.logger.info(f"{uptime} {total_traffic:<24} | {speed} | {conns}",
                             extra={'log_type': 'stats'})
    
    def _log_final_stats(self):
        """记录最终统计"""
        sent = self._format_bytes(self.stats.bytes_sent)
        recv = self._format_bytes(self.stats.bytes_received)
        
        # 计算平均指标
        avg_throughput = (sum(self.perf_metrics['throughput']) / 
                         len(self.perf_metrics['throughput'])) if self.perf_metrics['throughput'] else 0
        
        self.logger.info(f"===== Final Statistics =====")
        self.logger.info(f"Total connections: {self.stats.total_connections}")
        self.logger.info(f"Peak concurrent connections: {self.stats.peak_connections}")
        self.logger.info(f"Total data: ↑{sent} ↓{recv}")
        if avg_throughput > 0:
            self.logger.info(f"Average throughput: {self._format_bytes(avg_throughput)}/s")
        self.logger.info(f"============================")
    
    @staticmethod
    def _format_bytes(size: float) -> str:
        """格式化字节数"""
        if size < 1024:
            s = f"{size:.0f}B"
        else:
            for unit in ['KB', 'MB', 'GB', 'TB']:
                size /= 1024.0
                if size < 1024.0:
                    s = f"{size:.2f}{unit}"
                    break
            else: # Should not be reached unless size is huge (PB+)
                s = f"{size:.2f}PB"
        # Return the string right-aligned in a 9-character field
        return f"{s:>9}"
    
    async def _run_proxy_test(self):
        """运行代理测试"""
        if not self.config.test_url:
            return
        
        self.logger.info(f"Running proxy self-test against {self.config.test_url}...")
        writer = None
        
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection('127.0.0.1', self.config.local_port),
                timeout=5
            )
            
            # 解析URL
            from urllib.parse import urlparse
            parsed = urlparse(self.config.test_url)
            host = parsed.netloc or parsed.path
            
            # 发送HTTP请求
            request = f"GET {self.config.test_url} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()
            
            # 读取响应
            response = await asyncio.wait_for(reader.read(1024), timeout=5)
            status_line = response.decode('utf-8', errors='ignore').split('\r\n')[0]
            
            if "200" in status_line:
                self.logger.info(f"✓ Proxy test successful (Status: 200)")
            else:
                self.logger.warning(f"Proxy test returned: {status_line}")
                
        except asyncio.TimeoutError:
            self.logger.error("✗ Proxy self-test timed out")
        except Exception as e:
            self.logger.error(f"✗ Proxy self-test failed: {e}")
        finally:
            if writer:
                writer.close()
                await writer.wait_closed()

# ========== 保留原有的SmartColoredFormatter ==========
class SmartColoredFormatter(logging.Formatter):
    """智能颜色日志格式化器"""
    RESET_SEQ = '\033[0m'
    
    COLORS = {
        'GREY':       '\033[90m',
        'GREEN':      '\033[92m',
        'YELLOW':     '\033[93m',
        'RED':        '\033[91m',
        'BOLD_RED':   '\033[1;91m',
        'BOLD_GREEN': '\033[1;92m',
        'CYAN':       '\033[96m',  # 新增：用于性能指标
    }

    LEVEL_COLORS = {
        logging.DEBUG:    COLORS['GREY'],
        logging.INFO:     '',
        logging.WARNING:  COLORS['YELLOW'],
        logging.ERROR:    COLORS['RED'],
        logging.CRITICAL: COLORS['BOLD_RED'],
    }

    def format(self, record):
        log_message = super().format(record)
        
        # 统计日志使用黄色
        if hasattr(record, 'log_type') and record.log_type == 'stats':
            return f"{self.COLORS['CYAN']}{log_message}{self.RESET_SEQ}"
        
        # 重要信息使用绿色
        if record.levelno == logging.INFO and record.getMessage().strip().startswith('✓'):
            return f"{self.COLORS['BOLD_GREEN']}{log_message}{self.RESET_SEQ}"

        # 默认颜色
        color = self.LEVEL_COLORS.get(record.levelno, '')
        return f"{color}{log_message}{self.RESET_SEQ}" if color else log_message

# ========== 主函数 ==========
def main():
    """主函数"""
    parser = argparse.ArgumentParser(
        description="High-performance asynchronous SSH to SOCKS5/HTTP proxy tunnel.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Performance Options:
  --pool-size N        Number of SSH connections in pool (default: 3)
  --buffer-mode MODE   Buffer mode: 'fixed' or 'adaptive' (default: adaptive)
  --no-log-connections Don't log individual connections (improves performance)
  
Examples:
  # Basic usage with password
  %(prog)s --ssh-host server.com --ssh-user root --ssh-password pass123 \\
           --local-port 3128 --remote-proxy-port 3128
  
  # High performance mode with SSH key
  %(prog)s --ssh-host server.com --ssh-user root --ssh-key ~/.ssh/id_rsa \\
           --local-port 3128 --remote-proxy-port 3128 \\
           --pool-size 5 --no-log-connections
        """
    )
    
    # 必需参数
    parser.add_argument('--ssh-host', required=True, help='SSH server hostname or IP')
    parser.add_argument('--ssh-user', required=True, help='SSH username')
    parser.add_argument('--local-port', type=int, required=True, 
                       help='Local port to listen on')
    parser.add_argument('--remote-proxy-port', type=int, required=True,
                       help='Remote proxy port on SSH server')
    
    # 认证方式
    auth = parser.add_mutually_exclusive_group(required=True)
    auth.add_argument('--ssh-password', help='SSH password')
    auth.add_argument('--ssh-key', help='Path to SSH private key')
    
    # 可选参数
    parser.add_argument('--ssh-port', type=int, default=22, 
                       help='SSH server port (default: 22)')
    parser.add_argument('--local-host', default='127.0.0.1',
                       help='Local interface to bind (default: 127.0.0.1)')
    parser.add_argument('--remote-proxy-host', default='127.0.0.1',
                       help='Remote proxy host (default: 127.0.0.1)')
    parser.add_argument('--test-url', default='https://www.google.com',
                       help='URL for proxy self-test (default: https://www.google.com)')
    
    # 性能选项
    parser.add_argument('--pool-size', type=int, default=3,
                       help='SSH connection pool size (default: 3)')
    parser.add_argument('--buffer-mode', choices=['fixed', 'adaptive'], 
                       default='adaptive',
                       help='Buffer sizing mode (default: adaptive)')
    parser.add_argument('--no-log-connections', action='store_true',
                       help="Don't log individual connections")
    
    # 调试选项
    parser.add_argument('--debug', action='store_true',
                       help='Enable debug logging')
    
    args = parser.parse_args()
    
    # Windows颜色支持
    if sys.platform == "win32":
        try:
            import colorama
            colorama.init()
        except ImportError:
            pass
    
    # 配置日志
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG if args.debug else logging.INFO)
    
    handler = logging.StreamHandler()
    formatter = SmartColoredFormatter(
        '%(asctime)s - %(levelname)-8s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    handler.setFormatter(formatter)
    root_logger.addHandler(handler)
    
    # 调整asyncssh日志级别
    logging.getLogger('asyncssh').setLevel(
        logging.INFO if args.debug else logging.WARNING
    )
    
    # 验证SSH密钥文件
    if args.ssh_key:
        args.ssh_key = os.path.expanduser(args.ssh_key)
        if not os.path.exists(args.ssh_key):
            print(f"Error: SSH key file not found at {args.ssh_key}", file=sys.stderr)
            sys.exit(1)
    
    # 创建配置
    config = ProxyConfig(
        ssh_host=args.ssh_host,
        ssh_user=args.ssh_user,
        ssh_port=args.ssh_port,
        ssh_password=args.ssh_password,
        ssh_key=args.ssh_key,
        local_host=args.local_host,
        local_port=args.local_port,
        remote_proxy_host=args.remote_proxy_host,
        remote_proxy_port=args.remote_proxy_port,
        test_url=args.test_url,
        pool_size=args.pool_size,
        buffer_size=args.buffer_mode,
        log_connections=not args.no_log_connections
    )
    
    # 启动服务器
    proxy_server = OptimizedProxyServer(config)
    
    try:
        asyncio.run(proxy_server.start())
    except KeyboardInterrupt:
        print("\n✓ Proxy server shutting down gracefully...", file=sys.stderr)
    except Exception:
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
