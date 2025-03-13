"""
IP address generation module for NetScan.

This module provides functions to generate random IP addresses and IP ranges.
"""

import random
import ipaddress
import logging
from typing import List, Set, Optional

logger = logging.getLogger("netscan")

# Lists of reserved or special-use IP address ranges to avoid
RESERVED_NETWORKS = [
    # IANA Reserved
    "0.0.0.0/8",        # This host on this network
    "10.0.0.0/8",       # Private-use networks
    "100.64.0.0/10",    # Shared address space
    "127.0.0.0/8",      # Loopback
    "169.254.0.0/16",   # Link-local
    "172.16.0.0/12",    # Private-use networks
    "192.0.0.0/24",     # IETF Protocol Assignments
    "192.0.2.0/24",     # TEST-NET-1
    "192.88.99.0/24",   # 6to4 Relay Anycast
    "192.168.0.0/16",   # Private-use networks
    "198.18.0.0/15",    # Benchmark testing
    "198.51.100.0/24",  # TEST-NET-2
    "203.0.113.0/24",   # TEST-NET-3
    "224.0.0.0/4",      # Multicast
    "240.0.0.0/4",      # Reserved for future use
    "255.255.255.255/32" # Limited broadcast
]

def is_reserved_ip(ip: str) -> bool:
    """
    Check if an IP address is in a reserved or special-use range.
    
    Args:
        ip: The IP address to check
        
    Returns:
        True if the IP is in a reserved range, False otherwise
    """
    ip_obj = ipaddress.ip_address(ip)
    
    # Check if the IP is in any of the reserved networks
    for network in RESERVED_NETWORKS:
        if ip_obj in ipaddress.ip_network(network):
            return True
    
    return False

def generate_random_ip() -> str:
    """
    Generate a random IP address that is not in a reserved range.
    
    Returns:
        A random IP address as a string
    """
    while True:
        # Generate 4 random octets
        octets = [random.randint(0, 255) for _ in range(4)]
        ip = '.'.join(map(str, octets))
        
        # Check if it's not in a reserved range
        if not is_reserved_ip(ip):
            return ip

def generate_random_ips(count: int, excluded_ips: Optional[Set[str]] = None) -> List[str]:
    """
    Generate a list of random IP addresses.
    
    Args:
        count: Number of IP addresses to generate
        excluded_ips: Set of IP addresses to exclude
        
    Returns:
        List of random IP addresses
    """
    if excluded_ips is None:
        excluded_ips = set()
    
    ip_list = []
    attempts = 0
    max_attempts = count * 10  # Limit to avoid infinite loops
    
    while len(ip_list) < count and attempts < max_attempts:
        ip = generate_random_ip()
        attempts += 1
        
        if ip not in excluded_ips and ip not in ip_list:
            ip_list.append(ip)
    
    if len(ip_list) < count:
        logger.warning(f"Only generated {len(ip_list)} IPs after {attempts} attempts")
    
    return ip_list

def generate_ip_range(range_str: str, excluded_ips: Optional[Set[str]] = None) -> List[str]:
    """
    Generate a list of IP addresses from a range specification.
    
    Args:
        range_str: IP range in format "start_ip-end_ip" or CIDR notation
        excluded_ips: Set of IP addresses to exclude
        
    Returns:
        List of IP addresses in the range
    """
    if excluded_ips is None:
        excluded_ips = set()
    
    ip_list = []
    
    try:
        # Check if it's CIDR notation
        if '/' in range_str:
            network = ipaddress.ip_network(range_str, strict=False)
            for ip in network.hosts():
                ip_str = str(ip)
                if ip_str not in excluded_ips:
                    ip_list.append(ip_str)
        
        # Check if it's range notation (start-end)
        elif '-' in range_str:
            start_ip, end_ip = range_str.split('-', 1)
            start_ip = start_ip.strip()
            end_ip = end_ip.strip()
            
            start_int = int(ipaddress.IPv4Address(start_ip))
            end_int = int(ipaddress.IPv4Address(end_ip))
            
            if end_int < start_int:
                raise ValueError("End IP must be greater than or equal to start IP")
            
            # Limit range size to avoid memory issues
            if end_int - start_int > 1000000:
                logger.warning("IP range too large (>1,000,000 addresses). Limiting to first 1,000,000.")
                end_int = start_int + 1000000
            
            for ip_int in range(start_int, end_int + 1):
                ip_str = str(ipaddress.IPv4Address(ip_int))
                if ip_str not in excluded_ips:
                    ip_list.append(ip_str)
        
        else:
            # Assume it's a single IP
            ip = range_str.strip()
            ipaddress.IPv4Address(ip)  # Validate IP format
            if ip not in excluded_ips:
                ip_list.append(ip)
    
    except ValueError as e:
        logger.error(f"Invalid IP range format: {e}")
        return []
    
    return ip_list
