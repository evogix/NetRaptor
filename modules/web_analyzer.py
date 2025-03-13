"""
Web analysis module for NetScan.

This module provides functionality to analyze websites found on open ports.
"""

import re
import logging
import socket
import requests
from typing import Dict, Any, List, Optional
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

logger = logging.getLogger("netscan")

# Common technology signatures
TECH_SIGNATURES = {
    # Web servers
    'Apache': [
        {'type': 'header', 'header': 'Server', 'regex': r'Apache/?'},
        {'type': 'html', 'regex': r'<address>Apache/[\d\.]+ Server'}
    ],
    'Nginx': [
        {'type': 'header', 'header': 'Server', 'regex': r'nginx/?'}
    ],
    'IIS': [
        {'type': 'header', 'header': 'Server', 'regex': r'Microsoft-IIS/?'}
    ],
    
    # Frontend frameworks
    'jQuery': [
        {'type': 'html', 'regex': r'jquery[-\.]?\d+\.\d+\.\d+\.js'},
        {'type': 'html', 'regex': r'jquery\.min\.js'}
    ],
    'React': [
        {'type': 'html', 'regex': r'react(-dom)?\.production\.min\.js'},
        {'type': 'html', 'regex': r'_reactRootContainer'}
    ],
    'Angular': [
        {'type': 'html', 'regex': r'ng-app'},
        {'type': 'html', 'regex': r'angular\.js|angular\.min\.js'},
        {'type': 'html', 'regex': r'ng-controller'}
    ],
    'Vue.js': [
        {'type': 'html', 'regex': r'vue\.js|vue\.min\.js'},
        {'type': 'html', 'regex': r'data-v-'}
    ],
    
    # CSS frameworks
    'Bootstrap': [
        {'type': 'html', 'regex': r'bootstrap\.css|bootstrap\.min\.css|bootstrap\.\d+\.\d+\.\d+\.css'},
        {'type': 'html', 'regex': r'class="[^"]*btn[^"]*"'},
        {'type': 'html', 'regex': r'class="[^"]*container[^"]*"'}
    ],
    'Tailwind CSS': [
        {'type': 'html', 'regex': r'tailwind\.css|tailwind\.min\.css'},
        {'type': 'html', 'regex': r'class="[^"]*text-\w+-\d+'}
    ],
    
    # CMS
    'WordPress': [
        {'type': 'html', 'regex': r'wp-content|wp-includes'},
        {'type': 'html', 'regex': r'<link[^>]+wp-|<link[^>]+themes/[^/]+/'},
        {'type': 'html', 'regex': r'<meta name="generator" content="WordPress'}
    ],
    'Joomla': [
        {'type': 'html', 'regex': r'/media/jui/'},
        {'type': 'html', 'regex': r'<meta name="generator" content="Joomla'}
    ],
    'Drupal': [
        {'type': 'html', 'regex': r'Drupal\.settings'},
        {'type': 'html', 'regex': r'jQuery\.extend\(Drupal\.'},
        {'type': 'header', 'header': 'X-Generator', 'regex': r'Drupal'}
    ],
    
    # Server-side languages
    'PHP': [
        {'type': 'header', 'header': 'X-Powered-By', 'regex': r'PHP/'},
        {'type': 'html', 'regex': r'\.php(\?|$)'}
    ],
    'ASP.NET': [
        {'type': 'header', 'header': 'X-AspNet-Version', 'regex': r'.+'},
        {'type': 'header', 'header': 'X-Powered-By', 'regex': r'ASP\.NET'},
        {'type': 'html', 'regex': r'\.aspx?(\?|$)'}
    ],
    'Ruby on Rails': [
        {'type': 'header', 'header': 'X-Powered-By', 'regex': r'Rails'},
        {'type': 'header', 'header': 'X-Web-Console-Session-Id', 'regex': r'.+'}
    ],
    
    # JavaScript frameworks
    'Express.js': [
        {'type': 'header', 'header': 'X-Powered-By', 'regex': r'Express'}
    ],
    'Next.js': [
        {'type': 'html', 'regex': r'__NEXT_DATA__'},
        {'type': 'header', 'header': 'x-nextjs-page', 'regex': r'.+'}
    ],
    
    # Analytics and tracking
    'Google Analytics': [
        {'type': 'html', 'regex': r'google-analytics\.com/analytics\.js|ga\.js|gtag/js'},
        {'type': 'html', 'regex': r'GoogleAnalyticsObject|gtag\('}
    ],
    
    # Caching
    'Cloudflare': [
        {'type': 'header', 'header': 'CF-Ray', 'regex': r'.+'},
        {'type': 'header', 'header': 'Server', 'regex': r'cloudflare'}
    ],
    'Varnish': [
        {'type': 'header', 'header': 'X-Varnish', 'regex': r'.+'},
        {'type': 'header', 'header': 'Via', 'regex': r'varnish'}
    ]
}

def get_website_content(ip: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
    """
    Retrieve website content from a given IP and port.
    
    Args:
        ip: Target IP address
        port: Target port
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary with website content information
    """
    schema = 'https' if port == 443 or port == 8443 else 'http'
    url = f"{schema}://{ip}:{port}/"
    
    result = {
        'url': url,
        'status_code': None,
        'headers': {},
        'html': None,
        'error': None
    }
    
    try:
        # Disable SSL verification warnings
        requests.packages.urllib3.disable_warnings(
            requests.packages.urllib3.exceptions.InsecureRequestWarning
        )
        
        # Make the request with a user agent to avoid being blocked
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5'
        }
        
        response = requests.get(url, timeout=timeout, verify=False, headers=headers, allow_redirects=True)
        
        result['status_code'] = response.status_code
        result['headers'] = dict(response.headers)
        result['html'] = response.text
        result['url'] = response.url  # In case of redirects
        
    except requests.exceptions.SSLError:
        # Try the other schema if SSL error occurs
        alt_schema = 'http' if schema == 'https' else 'https'
        alt_url = f"{alt_schema}://{ip}:{port}/"
        
        try:
            response = requests.get(alt_url, timeout=timeout, verify=False, headers=headers, allow_redirects=True)
            
            result['status_code'] = response.status_code
            result['headers'] = dict(response.headers)
            result['html'] = response.text
            result['url'] = response.url
            
        except Exception as e:
            result['error'] = f"Error accessing website: {str(e)}"
    
    except Exception as e:
        result['error'] = f"Error accessing website: {str(e)}"
    
    return result

def extract_title_description(html: str) -> Dict[str, str]:
    """
    Extract title and description from HTML content.
    
    Args:
        html: HTML content as a string
        
    Returns:
        Dictionary with title and description
    """
    result = {
        'title': '',
        'description': ''
    }
    
    try:
        soup = BeautifulSoup(html, 'html.parser')
        
        # Extract title
        title_tag = soup.title
        if title_tag and title_tag.string:
            result['title'] = title_tag.string.strip()
        
        # Extract description from meta tags
        desc_meta = soup.find('meta', attrs={'name': 'description'})
        if desc_meta and desc_meta.get('content'):
            result['description'] = desc_meta['content'].strip()
        
        # If no description meta tag, try Open Graph
        if not result['description']:
            og_desc = soup.find('meta', attrs={'property': 'og:description'})
            if og_desc and og_desc.get('content'):
                result['description'] = og_desc['content'].strip()
        
        # If still no description, try to construct one from first paragraph
        if not result['description']:
            first_p = soup.find('p')
            if first_p and first_p.text:
                # Limit description to reasonable length
                result['description'] = first_p.text.strip()#[:200]
                if len(first_p.text) > 200:
                    result['description'] #+= '...'
    
    except Exception as e:
        logger.error(f"Error extracting title/description: {e}")
    
    return result

def detect_technologies(html: str, headers: Dict[str, str]) -> List[str]:
    """
    Detect technologies used by a website based on HTML content and headers.
    
    Args:
        html: HTML content as a string
        headers: HTTP response headers
        
    Returns:
        List of detected technologies
    """
    detected = set()
    
    # Check each technology signature
    for tech, signatures in TECH_SIGNATURES.items():
        for sig in signatures:
            if sig['type'] == 'html' and html:
                if re.search(sig['regex'], html, re.IGNORECASE):
                    detected.add(tech)
                    break
            elif sig['type'] == 'header' and headers:
                header_value = headers.get(sig['header'])
                if header_value and re.search(sig['regex'], header_value, re.IGNORECASE):
                    detected.add(tech)
                    break
    
    return sorted(list(detected))

def analyze_website(ip: str, port: int, timeout: float = 5.0) -> Optional[Dict[str, Any]]:
    """
    Analyze a website on a given IP and port.
    
    Args:
        ip: Target IP address
        port: Target port
        timeout: Request timeout in seconds
        
    Returns:
        Dictionary with website analysis results or None if not a website
    """
    try:
        logger.info(f"Analyzing website at {ip}:{port}")
        
        # Get website content
        content = get_website_content(ip, port, timeout)
        
        # If there was an error or no HTML, return limited info
        if content['error'] or not content['html']:
            if content['status_code']:
                return {
                    'url': content['url'],
                    'status_code': content['status_code'],
                    'title': '',
                    'description': '',
                    'technologies': [],
                    'error': content['error']
                }
            return None
        
        # Extract title and description
        metadata = extract_title_description(content['html'])
        
        # Detect technologies
        technologies = detect_technologies(content['html'], content['headers'])
        
        result = {
            'url': content['url'],
            'status_code': content['status_code'],
            'title': metadata['title'],
            'description': metadata['description'],
            'technologies': technologies
        }
        
        return result
        
    except Exception as e:
        logger.error(f"Error analyzing website at {ip}:{port}: {e}")
        return None
