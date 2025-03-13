#!/usr/bin/env python3
"""
NetRaptor - A CLI tool for network scanning and analysis

This tool can generate random IPs, scan ports, detect services, and analyze websites.
"""

import os
import sys
import argparse
import logging
import random
import socket
import time
from datetime import datetime
from colorama import init, Fore, Style, Back

from modules.ip_generator import generate_random_ips, generate_ip_range
from modules.port_scanner import scan_ports
from modules.service_detector import detect_services
from modules.web_analyzer import analyze_website
from utils.output_formatter import format_results, save_results_to_file

# Initialize colorama for cross-platform colored terminal output
init()

def setup_logger():
    """Configure the application logger"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    return logging.getLogger("netscan")

def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description="NetScan - Generate random IPs, scan ports, detect services, and analyze websites",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    # IP generation options
    ip_group = parser.add_argument_group('IP Generation')
    ip_source = ip_group.add_mutually_exclusive_group(required=True)
    ip_source.add_argument('-r', '--random', type=int, metavar='COUNT',
                        help='Generate random IP addresses')
    ip_source.add_argument('-i', '--ip', type=str, metavar='IP',
                        help='Scan a specific IP address')
    ip_source.add_argument('--range', type=str, metavar='RANGE',
                        help='Scan an IP range (e.g., 192.168.1.1-192.168.1.254)')
    ip_group.add_argument('--exclude', type=str, metavar='FILE',
                        help='File containing IPs to exclude')
    
    # Port scanning options
    port_group = parser.add_argument_group('Port Scanning')
    port_group.add_argument('-p', '--ports', type=str, default='1-1000',
                            help='Port range to scan (e.g., 80,443,8000-8100)')
    port_group.add_argument('-t', '--timeout', type=float, default=1.0,
                        help='Timeout for port scanning (seconds)')
    port_group.add_argument('--threads', type=int, default=10,
                        help='Number of threads for concurrent scanning')
    
    # Analysis options
    analysis_group = parser.add_argument_group('Analysis')
    analysis_group.add_argument('--service-detection', action='store_true',
                            help='Enable service detection on open ports')
    analysis_group.add_argument('--web-analysis', action='store_true',
                            help='Analyze websites found on open ports')
    
    # Output options
    output_group = parser.add_argument_group('Output')
    output_group.add_argument('-o', '--output', type=str, metavar='FILE',
                            help='Save results to a file')
    output_group.add_argument('-q', '--quiet', action='store_true',
                            help='Suppress terminal output except for errors')
    output_group.add_argument('-v', '--verbose', action='store_true',
                            help='Enable verbose output')
    
    args = parser.parse_args()
    return args

def print_banner():
    """Display the tool banner"""
    banner = f"""
{Fore.LIGHTGREEN_EX}


 _   _      _  ______            _              
| \ | |    | | | ___ \          | |             
|  \| | ___| |_| |_/ /__ _ _ __ | |_ ___  _ __  
| . ` |/ _ \ __|    // _` | '_ \| __/ _ \| '__| 
| |\  |  __/ |_| |\ \ (_| | |_) | || (_) | |    
\_| \_/\___|\__\_| \_\__,_| .__/ \__\___/|_|    
 Evogix x Geek Institute  | |                   
                          |_|             {Back.RED}v1.0{Style.RESET_ALL}
{Back.MAGENTA}🔥🔍Intelligent IP Hunter & Network Explorer 🚀🔍{Style.RESET_ALL}
A CLI tool for network scanning and analysis
    - Generate random IPs 🏠
    - Scan ports 🔍
    - Detect services ⚡
    - Analyze websites 📝 🔧

{Fore.YELLOW}[!] Use responsibly and ethically. Unauthorized scanning may be illegal.{Style.RESET_ALL}
"""
    print(banner)

def main():
    """Main function for the NetRaptor tool"""
    print_banner()
    args = parse_arguments()
    logger = setup_logger()
    
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    elif args.quiet:
        logger.setLevel(logging.WARNING)
    
    start_time = time.time()
    
    # Process excluded IPs if provided
    excluded_ips = set()
    if args.exclude and os.path.exists(args.exclude):
        with open(args.exclude, 'r') as f:
            excluded_ips = set(line.strip() for line in f if line.strip())
        logger.info(f"Loaded {len(excluded_ips)} IPs to exclude")
    
    # Generate target IP addresses
    target_ips = []
    if args.random:
        logger.info(f"Generating {args.random} random IP addresses...")
        target_ips = generate_random_ips(args.random, excluded_ips)
    elif args.ip:
        if args.ip not in excluded_ips:
            target_ips = [args.ip]
        else:
            logger.warning(f"Skipping {args.ip} (in exclusion list)")
    elif args.range:
        logger.info(f"Generating IPs from range: {args.range}")
        target_ips = generate_ip_range(args.range, excluded_ips)
    
    if not target_ips:
        logger.error("No valid target IPs to scan")
        return 1
    
    logger.info(f"Will scan {len(target_ips)} IP addresses")
    
    # Parse port range
    ports = []
    for part in args.ports.split(','):
        if '-' in part:
            start, end = map(int, part.split('-', 1))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    
    # Initialize results dictionary
    results = {
        'scan_info': {
            'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'command': ' '.join(sys.argv),
            'target_count': len(target_ips),
            'port_count': len(ports)
        },
        'results': []
    }
    
    # Scan each IP
    for i, ip in enumerate(target_ips):
        if not args.quiet:
            progress = f"[{i+1}/{len(target_ips)}]"
            print(f"\n{Fore.GREEN}{progress} Scanning {ip}...{Style.RESET_ALL}")
        
        ip_result = {'ip': ip, 'open_ports': [], 'services': [], 'websites': []}
        
        # Scan ports
        open_ports = scan_ports(ip, ports, args.timeout, args.threads)
        if open_ports:
            ip_result['open_ports'] = open_ports
            logger.info(f"Found {len(open_ports)} open ports on {ip}")
            
            # Detect services
            if args.service_detection:
                services = detect_services(ip, open_ports, args.timeout)
                ip_result['services'] = services
                
                # Analyze web servers
                if args.web_analysis:
                    for port, service_info in services.items():
                        if service_info.get('is_http', False):
                            logger.info(f"Analyzing website at {ip}:{port}")
                            web_analysis = analyze_website(ip, int(port), args.timeout)
                            if web_analysis:
                                ip_result['websites'].append({
                                    'port': port,
                                    'analysis': web_analysis
                                })
        
        results['results'].append(ip_result)
        
        # Display formatted results for this IP
        if not args.quiet:
            format_results({
                'results': [ip_result]
            }, show_scan_info=False)
    
    # Complete the scan info
    results['scan_info']['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    results['scan_info']['duration'] = f"{time.time() - start_time:.2f} seconds"
    results['scan_info']['total_open_ports'] = sum(len(r['open_ports']) for r in results['results'])
    results['scan_info']['total_websites'] = sum(len(r['websites']) for r in results['results'])
    
    # Print final summary
    if not args.quiet:
        print(f"\n{Fore.CYAN}=== Scan Summary ==={Style.RESET_ALL}")
        print(f"Scanned {len(target_ips)} IP addresses in {results['scan_info']['duration']}")
        print(f"Found {results['scan_info']['total_open_ports']} open ports")
        if args.web_analysis:
            print(f"Discovered {results['scan_info']['total_websites']} websites")
    
    # Save results to file if requested
    if args.output:
        save_results_to_file(results, args.output)
        logger.info(f"Results saved to {args.output}")
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user.{Style.RESET_ALL}")
        sys.exit(130)
    except Exception as e:
        print(f"\n{Fore.RED}Error: {e}{Style.RESET_ALL}")
        logging.exception("An unexpected error occurred")
        sys.exit(1)
