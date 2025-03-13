"""
Service detection module for NetScan.

This module provides functionality to detect services running on open ports.
"""

import socket
import ssl
import re
import logging
from typing import Dict, Any, List, Tuple

logger = logging.getLogger("netscan")

# Common service signatures to match against banner data
SERVICE_SIGNATURES = [
    # HTTP servers
    (re.compile(r'^HTTP/\d\.\d \d{3}'), 'HTTP'),
    (re.compile(r'Server: .*?Apache'), 'Apache HTTP Server'),
    (re.compile(r'Server: .*?nginx'), 'Nginx'),
    (re.compile(r'Server: .*?Microsoft-IIS'), 'IIS'),
    (re.compile(r'Server: .*?LiteSpeed'), 'LiteSpeed'),
    (re.compile(r'Server: .*?lighttpd'), 'lighttpd'),
    
    # SSH 
    (re.compile(r'^SSH-\d\.\d'), 'SSH'),
    (re.compile(r'OpenSSH'), 'OpenSSH'),
    
    # FTP
    (re.compile(r'^220.*?FTP'), 'FTP'),
    (re.compile(r'220.*?FileZilla'), 'FileZilla FTP'),
    (re.compile(r'220.*?Pure-FTPd'), 'Pure-FTPd'),
    (re.compile(r'220.*?ProFTPD'), 'ProFTPD'),
    (re.compile(r'220.*?vsftpd'), 'vsftpd'),
    
    # SMTP
    (re.compile(r'^220.*?SMTP'), 'SMTP'),
    (re.compile(r'220.*?Postfix'), 'Postfix SMTP'),
    (re.compile(r'220.*?Sendmail'), 'Sendmail'),
    (re.compile(r'220.*?Exim'), 'Exim SMTP'),
    
    # Database
    (re.compile(r'MySQL'), 'MySQL'),
    (re.compile(r'MariaDB'), 'MariaDB'),
    (re.compile(r'PostgreSQL'), 'PostgreSQL'),
    (re.compile(r'Microsoft SQL Server'), 'MS SQL Server'),
    (re.compile(r'MongoDB'), 'MongoDB'),
    (re.compile(r'Redis'), 'Redis'),
    
    # Other
    (re.compile(r'^220.*?ESMTP'), 'SMTP'),
    (re.compile(r'\+OK POP3'), 'POP3'),
    (re.compile(r'\* OK.*?IMAP'), 'IMAP'),
    (re.compile(r'^AMQP'), 'AMQP'),
    (re.compile(r'LDAP protocol info'), 'LDAP'),
    (re.compile(r'RFB \d{3}\.\d{3}'), 'VNC'),
    (re.compile(r'^SSH-'), 'SSH')
]

# Common ports and their default services
COMMON_PORTS = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    143: 'IMAP',
    443: 'HTTPS',
    465: 'SMTPS',
    587: 'SMTP Submission',
    993: 'IMAPS',
    995: 'POP3S',
    1433: 'MS SQL',
    1521: 'Oracle',
    3306: 'MySQL',
    3389: 'RDP',
    5432: 'PostgreSQL',
    5900: 'VNC',
    6379: 'Redis',
    8080: 'HTTP-ALT',
    8443: 'HTTPS-ALT',
    27017: 'MongoDB'
}

# HTTP methods to try for probing web servers
HTTP_METHODS = [
    b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n",
    b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n"
]

def get_service_banner(ip: str, port: int, timeout: float) -> Tuple[str, bool]:
    """
    Attempt to retrieve a service banner from a specific port.
    
    Args:
        ip: Target IP address
        port: Target port
        timeout: Connection timeout in seconds
        
    Returns:
        Tuple containing (banner_text, use_ssl_flag)
    """
    # First try standard connection
    banner, is_ssl = try_connect_for_banner(ip, port, timeout, use_ssl=False)
    
    # If no banner was received and this is a common HTTPS port, try SSL
    if not banner and (port == 443 or port == 8443):
        ssl_banner, ssl_flag = try_connect_for_banner(ip, port, timeout, use_ssl=True)
        if ssl_banner:
            return ssl_banner, True
    
    return banner, is_ssl

def try_connect_for_banner(ip: str, port: int, timeout: float, use_ssl: bool = False) -> Tuple[str, bool]:
    """
    Try to connect to a port and get a service banner, optionally using SSL.
    
    Args:
        ip: Target IP address
        port: Target port
        timeout: Connection timeout in seconds
        use_ssl: Whether to use SSL/TLS for the connection
        
    Returns:
        Tuple containing (banner_text, is_ssl_flag)
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    banner = ""
    
    try:
        sock.connect((ip, port))
        
        # Wrap socket in SSL if requested
        if use_ssl:
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                ssl_sock = context.wrap_socket(sock, server_hostname=ip)
                sock = ssl_sock
            except ssl.SSLError:
                return "", False
        
        # Try to receive banner sent by server immediately
        try:
            sock.settimeout(timeout / 2)
            data = sock.recv(1024)
            if data:
                banner = data.decode('utf-8', errors='ignore').strip()
                return banner, use_ssl
        except (socket.timeout, socket.error):
            pass  # No immediate banner, continue with probes
        
        # For ports like HTTP that require a request
        if port in (80, 443, 8080, 8443) or not banner:
            for method in HTTP_METHODS:
                try:
                    sock.send(method)
                    sock.settimeout(timeout / 2)
                    data = sock.recv(1024)
                    if data:
                        banner = data.decode('utf-8', errors='ignore').strip()
                        return banner, use_ssl
                except (socket.timeout, socket.error):
                    continue
        
    except (socket.timeout, socket.error):
        pass
    finally:
        sock.close()
    
    return banner, use_ssl

def identify_service(banner: str, port: int, is_ssl: bool = False) -> Dict[str, Any]:
    """
    Identify service based on banner and port information.
    
    Args:
        banner: Service banner text
        port: Port number
        is_ssl: Whether SSL was used for the connection
        
    Returns:
        Dictionary with service information
    """
    service_info = {
        'name': 'Unknown',
        'banner': banner[:200] if banner else '',
        'is_ssl': is_ssl,
        'is_http': False,
        'details': {}
    }
    
    # Check if it's in common ports
    if port in COMMON_PORTS:
        service_info['name'] = COMMON_PORTS[port]
    
    # Check if it's a HTTP service
    if (port in (80, 443, 8080, 8443) or 
            (banner and (banner.startswith('HTTP/') or 'Server:' in banner))):
        service_info['is_http'] = True
        if is_ssl:
            service_info['name'] = 'HTTPS'
        else:
            service_info['name'] = 'HTTP'
        
        # Extract server header if present
        server_match = re.search(r'Server:\s+([^\r\n]+)', banner, re.IGNORECASE)
        if server_match:
            service_info['details']['server'] = server_match.group(1).strip()
    
    # Match against service signatures if we have a banner
    if banner:
        for pattern, service_name in SERVICE_SIGNATURES:
            if pattern.search(banner):
                service_info['name'] = service_name
                break
    
    # Special case for HTTPS without banner
    if not banner and is_ssl:
        service_info['name'] = 'HTTPS'
        service_info['is_http'] = True
    
    return service_info

def detect_services(ip: str, open_ports: List[int], timeout: float = 1.0) -> Dict[str, Dict[str, Any]]:
    """
    Detect services running on open ports.
    
    Args:
        ip: Target IP address
        open_ports: List of open ports to check
        timeout: Connection timeout in seconds
        
    Returns:
        Dictionary mapping port numbers to service information
    """
    services = {}
    
    for port in open_ports:
        try:
            logger.debug(f"Detecting service on {ip}:{port}")
            banner, is_ssl = get_service_banner(ip, port, timeout)
            
            service_info = identify_service(banner, port, is_ssl)
            services[str(port)] = service_info
            
            logger.debug(f"Detected {service_info['name']} on {ip}:{port}")
            
        except Exception as e:
            logger.error(f"Error detecting service on {ip}:{port}: {e}")
            services[str(port)] = {
                'name': 'Unknown',
                'banner': '',
                'is_ssl': False,
                'is_http': False,
                'details': {'error': str(e)}
            }
    
    return services
