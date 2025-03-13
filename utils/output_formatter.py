"""
Output formatting module for NetScan.

This module provides functionality to format and save scan results.
"""

import json
import csv
import os
import logging
from typing import Dict, Any
from datetime import datetime
from colorama import Fore, Style, Back

logger = logging.getLogger("netscan")

def format_results(results: Dict[str, Any], show_scan_info: bool = True) -> None:
    """
    Format and print scan results to the terminal.
    
    Args:
        results: Dictionary with scan results
        show_scan_info: Whether to show scan info summary
    """
    if show_scan_info and 'scan_info' in results:
        info = results['scan_info']
        print(f"\n{Fore.CYAN}===== Scan Information ====={Style.RESET_ALL}")
        print(f"Start time: {info.get('start_time', 'N/A')}")
        if 'end_time' in info:
            print(f"End time: {info.get('end_time', 'N/A')}")
            print(f"Duration: {info.get('duration', 'N/A')}")
        print(f"Target IPs: {info.get('target_count', 'N/A')}")
        print(f"Ports scanned per target: {info.get('port_count', 'N/A')}")
    
    # Print results for each IP
    for ip_result in results['results']:
        ip = ip_result['ip']
        open_ports = ip_result.get('open_ports', [])
        services = ip_result.get('services', {})
        websites = ip_result.get('websites', [])
        
        # Header with IP and open port count
        print(f"\n{Fore.GREEN}===== {ip} ====={Style.RESET_ALL}")
        if open_ports:
            print(f"Open ports: {len(open_ports)}")
            
            # Print table header for ports and services
            if services:
                print(f"\n{Fore.YELLOW}{'PORT':<8} {'SERVICE':<20} {'DETAILS'}{Style.RESET_ALL}")
                print("-" * 60)
                
                # Print each port and service
                for port in sorted(map(int, services.keys())):
                    service_info = services.get(str(port), {})
                    service_name = service_info.get('name', 'Unknown')
                    
                    # Colorize based on service type
                    if service_info.get('is_http', False):
                        port_color = Fore.CYAN
                    elif service_name == 'SSH':
                        port_color = Fore.MAGENTA
                    elif service_name in ('FTP', 'SFTP'):
                        port_color = Fore.BLUE
                    elif service_name in ('SMTP', 'SMTPS'):
                        port_color = Fore.GREEN
                    else:
                        port_color = Fore.WHITE
                    
                    # Print port and service with color
                    print(f"{port_color}{port:<8}{Style.RESET_ALL} {service_name:<20}", end=' ')
                    
                    # Add SSL indicator if applicable
                    if service_info.get('is_ssl', False):
                        print(f"{Fore.GREEN}(SSL){Style.RESET_ALL} ", end='')
                    
                    # Print banner snippet if available
                    banner = service_info.get('banner', '')
                    if banner:
                        # Clean and truncate the banner
                        banner = banner.replace('\n', ' ').replace('\r', '')
                        if len(banner) > 40:
                            banner = banner[:37] + '...'
                        print(f"{Fore.YELLOW}{banner}{Style.RESET_ALL}")
                    else:
                        print()
            else:
                # Just print the list of open ports if no service info
                port_list = ", ".join(map(str, sorted(open_ports)))
                print(f"Open ports: {port_list}")
        else:
            print(f"{Fore.YELLOW}No open ports found{Style.RESET_ALL}")
        
        # Print website information if available
        if websites:
            print(f"\n{Fore.CYAN}--- Websites found: {len(websites)} ---{Style.RESET_ALL}")
            
            for web in websites:
                port = web.get('port', '')
                analysis = web.get('analysis', {})
                
                if analysis:
                    url = analysis.get('url', f"http://{ip}:{port}/")
                    status = analysis.get('status_code', 'Unknown')
                    title = analysis.get('title', 'No title')
                    
                    # Status code color
                    if status and 200 <= status < 300:
                        status_color = Fore.GREEN
                    elif status and 300 <= status < 400:
                        status_color = Fore.BLUE
                    elif status and 400 <= status < 500:
                        status_color = Fore.YELLOW
                    elif status and 500 <= status < 600:
                        status_color = Fore.RED
                    else:
                        status_color = Fore.WHITE
                    
                    # Print website header
                    print(f"\n{Fore.CYAN}Website:{Style.RESET_ALL} {url} "
                          f"{status_color}[{status}]{Style.RESET_ALL}")
                    
                    # Print title and description
                    if title:
                        print(f"{Fore.WHITE}Title:{Style.RESET_ALL} {title}")
                    
                    desc = analysis.get('description', '')
                    if desc:
                        # Truncate long descriptions
                        if len(desc) > 100:
                            desc = desc[:97] + '...'
                        print(f"{Fore.WHITE}Description:{Style.RESET_ALL} {desc}")
                    
                    # Print technologies
                    techs = analysis.get('technologies', [])
                    if techs:
                        tech_str = ", ".join(techs)
                        print(f"{Fore.WHITE}Technologies:{Style.RESET_ALL} {tech_str}")
                    
                    # Print error if any
                    error = analysis.get('error')
                    if error:
                        print(f"{Fore.RED}Error:{Style.RESET_ALL} {error}")

def save_results_to_file(results: Dict[str, Any], filename: str) -> None:
    """
    Save scan results to a file in various formats.
    
    Args:
        results: Dictionary with scan results
        filename: Path to save the results
    """
    try:
        file_ext = os.path.splitext(filename)[1].lower()
        
        # Add datetime to filename if not present
        if not any(c.isdigit() for c in os.path.basename(filename)):
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            basename, ext = os.path.splitext(filename)
            filename = f"{basename}_{timestamp}{ext}"
        
        # Save in the appropriate format
        if file_ext == '.json':
            with open(filename, 'w') as f:
                json.dump(results, f, indent=2)
        elif file_ext == '.csv':
            save_as_csv(results, filename)
        elif file_ext == '.txt':
            save_as_text(results, filename)
        else:
            # Default to JSON if extension not recognized
            with open(f"{filename}.json", 'w') as f:
                json.dump(results, f, indent=2)
            logger.info(f"Unrecognized file extension. Results saved as {filename}.json")
            return
        
        logger.info(f"Results saved to {filename}")
    
    except Exception as e:
        logger.error(f"Error saving results to file: {e}")

def save_as_csv(results: Dict[str, Any], filename: str) -> None:
    """
    Save scan results in CSV format.
    
    Args:
        results: Dictionary with scan results
        filename: Path to save the CSV file
    """
    with open(filename, 'w', newline='') as csvfile:
        # Create main results file with basic information
        writer = csv.writer(csvfile)
        writer.writerow(['IP', 'Open Port Count', 'Services Found', 'Websites Found'])
        
        for ip_result in results['results']:
            ip = ip_result['ip']
            open_ports = ip_result.get('open_ports', [])
            services = ip_result.get('services', {})
            websites = ip_result.get('websites', [])
            
            writer.writerow([
                ip,
                len(open_ports),
                len(services),
                len(websites)
            ])
    
    # Create a detailed CSV with all information
    detailed_filename = os.path.splitext(filename)[0] + '_detailed.csv'
    with open(detailed_filename, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            'IP', 'Port', 'Service', 'Banner', 'Is SSL', 'Is HTTP',
            'Website URL', 'Status Code', 'Title', 'Description', 'Technologies'
        ])
        
        for ip_result in results['results']:
            ip = ip_result['ip']
            services = ip_result.get('services', {})
            websites = ip_result.get('websites', [])
            
            # Create a mapping of port to website info
            website_by_port = {}
            for web in websites:
                if 'port' in web and 'analysis' in web:
                    website_by_port[web['port']] = web['analysis']
            
            # Write a row for each port/service
            for port_str, service_info in services.items():
                port = port_str
                service_name = service_info.get('name', 'Unknown')
                banner = service_info.get('banner', '').replace('\n', ' ').replace('\r', '')
                is_ssl = 'Yes' if service_info.get('is_ssl', False) else 'No'
                is_http = 'Yes' if service_info.get('is_http', False) else 'No'
                
                # Website info if available
                web_info = website_by_port.get(port, {})
                web_url = web_info.get('url', '')
                status_code = web_info.get('status_code', '')
                title = web_info.get('title', '').replace('\n', ' ').replace('\r', '')
                description = web_info.get('description', '').replace('\n', ' ').replace('\r', '')
                technologies = '; '.join(web_info.get('technologies', []))
                
                writer.writerow([
                    ip, port, service_name, banner, is_ssl, is_http,
                    web_url, status_code, title, description, technologies
                ])
    
    logger.info(f"Detailed results saved to {detailed_filename}")

def save_as_text(results: Dict[str, Any], filename: str) -> None:
    """
    Save scan results as a formatted text file.
    
    Args:
        results: Dictionary with scan results
        filename: Path to save the text file
    """
    with open(filename, 'w') as f:
        # Write scan info
        if 'scan_info' in results:
            info = results['scan_info']
            f.write("===== Scan Information =====\n")
            f.write(f"Start time: {info.get('start_time', 'N/A')}\n")
            if 'end_time' in info:
                f.write(f"End time: {info.get('end_time', 'N/A')}\n")
                f.write(f"Duration: {info.get('duration', 'N/A')}\n")
            f.write(f"Target IPs: {info.get('target_count', 'N/A')}\n")
            f.write(f"Ports scanned per target: {info.get('port_count', 'N/A')}\n\n")
        
        # Write results for each IP
        for ip_result in results['results']:
            ip = ip_result['ip']
            open_ports = ip_result.get('open_ports', [])
            services = ip_result.get('services', {})
            websites = ip_result.get('websites', [])
            
            f.write(f"===== {ip} =====\n")
            if open_ports:
                f.write(f"Open ports: {len(open_ports)}\n")
                
                # Write table for ports and services
                if services:
                    f.write("\nPORT     SERVICE             DETAILS\n")
                    f.write("-" * 60 + "\n")
                    
                    for port in sorted(map(int, services.keys())):
                        service_info = services.get(str(port), {})
                        service_name = service_info.get('name', 'Unknown')
                        
                        # Format port and service
                        port_line = f"{port:<8} {service_name:<20}"
                        
                        # Add SSL indicator if applicable
                        if service_info.get('is_ssl', False):
                            port_line += " (SSL)"
                        
                        # Add banner snippet if available
                        banner = service_info.get('banner', '')
                        if banner:
                            # Clean and truncate the banner
                            banner = banner.replace('\n', ' ').replace('\r', '')
                            if len(banner) > 40:
                                banner = banner[:37] + '...'
                            port_line += f" {banner}"
                        
                        f.write(port_line + "\n")
                else:
                    # Just list the open ports if no service info
                    port_list = ", ".join(map(str, sorted(open_ports)))
                    f.write(f"Open ports: {port_list}\n")
            else:
                f.write("No open ports found\n")
            
            # Write website information if available
            if websites:
                f.write(f"\n--- Websites found: {len(websites)} ---\n")
                
                for web in websites:
                    port = web.get('port', '')
                    analysis = web.get('analysis', {})
                    
                    if analysis:
                        url = analysis.get('url', f"http://{ip}:{port}/")
                        status = analysis.get('status_code', 'Unknown')
                        title = analysis.get('title', 'No title')
                        
                        # Write website header
                        f.write(f"\nWebsite: {url} [{status}]\n")
                        
                        # Write title and description
                        if title:
                            f.write(f"Title: {title}\n")
                        
                        desc = analysis.get('description', '')
                        if desc:
                            # Truncate long descriptions
                            if len(desc) > 100:
                                desc = desc + '...'
                            f.write(f"Description: {desc}\n")
                        
                        # Write technologies
                        techs = analysis.get('technologies', [])
                        if techs:
                            tech_str = ", ".join(techs)
                            f.write(f"Technologies: {tech_str}\n")
                        
                        # Write error if any
                        error = analysis.get('error')
                        if error:
                            f.write(f"Error: {error}\n")
            
            f.write("\n")
