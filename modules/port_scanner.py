"""
Port scanning module for NetScan.

This module provides functionality to scan ports on target IP addresses.
"""

import socket
import logging
import time
import concurrent.futures
from typing import List, Dict, Any

logger = logging.getLogger("netscan")

def check_port(ip: str, port: int, timeout: float) -> bool:
    """
    Check if a specific port is open on the target IP.
    
    Args:
        ip: The target IP address
        port: The port to check
        timeout: Connection timeout in seconds
        
    Returns:
        True if the port is open, False otherwise
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    
    try:
        # Attempt to connect to the port
        result = sock.connect_ex((ip, port))
        return result == 0
    except socket.error:
        return False
    finally:
        sock.close()

def scan_port_worker(ip: str, port: int, timeout: float) -> Dict[str, Any]:
    """
    Worker function for threaded port scanning.
    
    Args:
        ip: The target IP address
        port: The port to scan
        timeout: Connection timeout in seconds
        
    Returns:
        Dictionary with port scanning results
    """
    start_time = time.time()
    is_open = check_port(ip, port, timeout)
    scan_time = time.time() - start_time
    
    return {
        'port': port,
        'is_open': is_open,
        'scan_time': scan_time
    }

def scan_ports(ip: str, ports: List[int], timeout: float = 1.0, max_threads: int = 10) -> List[int]:
    """
    Scan multiple ports on a target IP address, potentially in parallel.
    
    Args:
        ip: The target IP address
        ports: List of ports to scan
        timeout: Connection timeout in seconds
        max_threads: Maximum number of concurrent scanning threads
        
    Returns:
        List of open ports
    """
    open_ports = []
    total_ports = len(ports)
    
    logger.debug(f"Scanning {total_ports} ports on {ip} with timeout {timeout}s")
    
    # Use a thread pool for concurrent scanning
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Submit all scan tasks
        future_to_port = {
            executor.submit(scan_port_worker, ip, port, timeout): port
            for port in ports
        }
        
        # Process results as they complete
        for i, future in enumerate(concurrent.futures.as_completed(future_to_port), 1):
            try:
                result = future.result()
                if result['is_open']:
                    open_ports.append(result['port'])
                    logger.debug(f"Found open port {result['port']} on {ip}")
                
                # Log progress for larger scans
                if total_ports > 100 and i % 100 == 0:
                    logger.debug(f"Scanned {i}/{total_ports} ports on {ip}")
                    
            except Exception as e:
                port = future_to_port[future]
                logger.error(f"Error scanning port {port} on {ip}: {e}")
    
    # Sort the list of open ports
    open_ports.sort()
    
    return open_ports
