import argparse
import requests
import time
import re
import json
import logging
import sys
import signal
from datetime import datetime
from bs4 import BeautifulSoup, Comment
from urllib.parse import urlparse, urljoin
from urllib.robotparser import RobotFileParser
from collections import deque
import xml.etree.ElementTree as ET
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Making the console output look pretty with colors - because who likes boring black text?
class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors for console output"""
    
    # Adding some color to our lives - different colors for different log levels
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan - for when you want to see everything
        'INFO': '\033[32m',     # Green - good news, everything's working
        'WARNING': '\033[33m',  # Yellow - something's fishy but not broken
        'ERROR': '\033[31m',    # Red - oh no, something broke
        'CRITICAL': '\033[35m', # Magenta - everything is on fire
        'RESET': '\033[0m'      # Reset - back to boring black
    }
    
    def format(self, record):
        if hasattr(record, 'color'):
            record.levelname = f"{self.COLORS.get(record.levelname, '')}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)

# Setting up our logging system - this makes everything easier to debug when things go wrong
def setup_logging(log_file=None, verbose=False):
    """Setup enhanced logging with console and file output"""
    logger = logging.getLogger(__name__)
    # If verbose mode is on, show everything. If not, just show the important stuff
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # Clean slate - remove any existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Console handler with colors - this makes the terminal output pretty and readable
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_formatter = ColoredFormatter('%(asctime)s - %(levelname)s - %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler if specified - save logs to file for later review when you're debugging
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    return logger

logger = setup_logging()

# This is our main scanner class - it does all the heavy lifting for finding vulnerabilities
class PassiveWebReconScanner:
    """
    Passive Web Reconnaissance & Vulnerability Scanner
    Focuses on passive discovery and non-intrusive vulnerability detection
    """
    
    def __init__(self, target_url, max_depth=2, max_pages=1000, rate_limit=0.5, verify_ssl=True, 
                 timeout=30, max_retries=3, user_agent=None, respect_robots=True, scan_start_time=None):
        # Clean up and validate the URL we're going to scan
        self.target_url = self.validate_and_normalize_url(target_url)
        self.domain = urlparse(self.target_url).netloc
        
        # Basic scanning configuration - how deep and how many pages to look at
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.rate_limit = rate_limit
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.max_retries = max_retries
        self.respect_robots = respect_robots
        self.scan_start_time = scan_start_time or datetime.now()
        
        # Rate limiting stuff - we don't want to overwhelm the target server
        self.last_request_time = 0
        self.request_count = 0
        self.rate_limit_violations = 0
        
        # Where we store all the stuff we find during scanning
        self.visited = set()                    # Pages we've already looked at
        self.discovered_pages = set()           # New pages we found
        self.discovered_directories = set()     # Directories we discovered
        self.discovered_files = set()           # Files we found
        self.forms = []                         # Forms we analyzed
        self.hidden_tokens = []                 # Secrets and tokens we found
        
        # Where we store all the security issues we discover
        self.security_headers = {}              # Missing or weak security headers
        self.insecure_cookies = []              # Cookies with security problems
        self.vulnerable_forms = []              # Forms with vulnerabilities
        self.software_stack = {}                # What technology the site uses
        self.vulnerability_summary = {          # Count of issues by severity
            'critical': 0,                      # Fire everything - immediate fix needed
            'high': 0,                          # Fix this soon
            'medium': 0,                        # Fix when you can
            'low': 0,                           # Nice to have
            'info': 0                           # Just FYI
        }
        
        # Keeping track of how well our scan is performing
        self.scan_stats = {
            'total_requests': 0,                # How many requests we made
            'successful_requests': 0,           # How many worked
            'failed_requests': 0,               # How many failed
            'rate_limit_delays': 0,             # How often we had to slow down
            'robots_txt_skipped': 0,            # How many pages robots.txt told us to skip
            'scan_duration': 0                  # How long the whole scan took
        }
        
        # Headers that make us look like a real browser - helps avoid detection
        self.headers = {
            'User-Agent': user_agent or 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
        
        # Patterns to look for when hunting for secrets and tokens in the code
        self.token_patterns = {
            'Generic Token': r'token["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{16,})["\']',
            'CSRF Token': r'csrf[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9+/=]{16,})["\']',
            'API Key': r'api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{20,})["\']',
            'JWT Token': r'(eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*)',
            'Session ID': r'session[_-]?id["\']?\s*[:=]\s*["\']([a-zA-Z0-9]{16,})["\']',
            'Auth Token': r'auth[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9+/=]{16,})["\']',
            'Bearer Token': r'Bearer\s+([a-zA-Z0-9\-._~+/=]+)',
            'Access Token': r'access[_-]?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9+/=]{16,})["\']'
        }
        
        # These are the security headers we check for - they're like the security guards of a website
        self.critical_security_headers = {
            'Content-Security-Policy': {
                'description': 'Helps prevent XSS attacks',
                'severity': 'high',
                'missing_risk': 'Missing CSP allows unrestricted script execution',
                'owasp_category': 'A7: Identification and Authentication Failures',
                'remediation': 'Implement strict CSP policy with script-src restrictions'
            },
            'Strict-Transport-Security': {
                'description': 'Forces HTTPS connections',
                'severity': 'high',
                'missing_risk': 'Missing HSTS allows protocol downgrade attacks',
                'owasp_category': 'A2: Cryptographic Failures',
                'remediation': 'Set HSTS header with max-age >= 31536000'
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking attacks',
                'severity': 'medium',
                'missing_risk': 'Missing X-Frame-Options allows clickjacking',
                'owasp_category': 'A5: Security Misconfiguration',
                'remediation': 'Set X-Frame-Options to DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME type sniffing',
                'severity': 'medium',
                'missing_risk': 'Missing X-Content-Type-Options allows MIME sniffing attacks',
                'owasp_category': 'A5: Security Misconfiguration',
                'remediation': 'Set X-Content-Type-Options to nosniff'
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information',
                'severity': 'low',
                'missing_risk': 'Missing Referrer-Policy may leak sensitive URLs',
                'owasp_category': 'A1: Broken Access Control',
                'remediation': 'Set Referrer-Policy to strict-origin-when-cross-origin'
            },
            'Permissions-Policy': {
                'description': 'Controls browser feature access',
                'severity': 'low',
                'missing_risk': 'Missing Permissions-Policy allows unrestricted feature access',
                'owasp_category': 'A5: Security Misconfiguration',
                'remediation': 'Implement Permissions-Policy to restrict browser features'
            }
        }

        # These are the XSS payloads we look for - classic stuff that hackers use
        self.xss_test_patterns = [
            '<script>alert(1)</script>',        # Basic script injection
            '"><script>alert(1)</script>',      # Breaking out of attributes
            "';alert(1);//",                     # JavaScript injection
            'javascript:alert(1)',              # Protocol handler injection
            '<img src=x onerror=alert(1)>',     # Event handler injection
            '<svg onload=alert(1)>'             # SVG injection
        ]
        
        # SQL error patterns - when a website spills its database guts
        self.sql_error_patterns = [
            r'SQL syntax.*MySQL',               # MySQL being chatty about errors
            r'Warning.*mysql_.*',               # MySQL warnings
            r'valid MySQL result',              # MySQL result messages
            r'MySqlClient\.',                   # MySQL client errors
            r'PostgreSQL.*ERROR',               # PostgreSQL errors
            r'Warning.*pg_.*',                  # PostgreSQL warnings
            r'valid PostgreSQL result',         # PostgreSQL result messages
            r'Npgsql\.',                        # Npgsql errors
            r'Driver.*SQL.*Server',             # SQL Server driver errors
            r'OLE DB.*SQL Server',              # SQL Server OLE DB errors
            r'SQLServer.*JDBC',                 # SQL Server JDBC errors
            r'SqlException',                    # Generic SQL exceptions
            r'ORA-[0-9][0-9][0-9][0-9]',      # Oracle error codes
            r'Oracle.*Driver',                  # Oracle driver errors
            r'quoted string not properly terminated',  # SQL syntax errors
            r'SQLite.*error',                   # SQLite errors
            r'sqlite3.OperationalError'         # SQLite operational errors
        ]
        
        # OWASP Top 10 - the most common web vulnerabilities that keep security people up at night
        self.owasp_categories = {
            'A1': 'Broken Access Control',              # Who can see what
            'A2': 'Cryptographic Failures',             # Encryption gone wrong
            'A3': 'Injection',                          # SQL, XSS, command injection
            'A4': 'Insecure Design',                    # Bad architecture decisions
            'A5': 'Security Misconfiguration',          # Default settings, missing headers
            'A6': 'Vulnerable and Outdated Components', # Old libraries with known bugs
            'A7': 'Identification and Authentication Failures',  # Login problems
            'A8': 'Software and Data Integrity Failures',       # Tampering with code/data
            'A9': 'Security Logging and Monitoring Failures',   # Can't see what's happening
            'A10': 'Server-Side Request Forgery (SSRF)'         # Making the server visit bad URLs
        }
        
        # Setup enhanced HTTP session with retry logic
        self.session = self._setup_session()

    def _setup_session(self):
        """Setup enhanced HTTP session with retry logic and connection pooling"""
        # Create a session object that will handle all our HTTP requests
        session = requests.Session()
        
        # Configure retry strategy - if a request fails, try again with exponential backoff
        retry_strategy = Retry(
            total=self.max_retries,                    # How many times to retry
            status_forcelist=[429, 500, 502, 503, 504],  # HTTP status codes that mean "try again"
            allowed_methods=["HEAD", "GET", "OPTIONS"],   # Only retry safe methods (no POST/PUT/DELETE)
            backoff_factor=1                            # Wait longer between each retry
        )
        
        # Configure adapter with retry strategy and mount it for both HTTP and HTTPS
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)   # Use our retry logic for HTTP
        session.mount("https://", adapter)  # Use our retry logic for HTTPS
        
        # Set our default headers (User-Agent, etc.) for all requests
        session.headers.update(self.headers)
        
        return session
    
    def _enforce_rate_limit(self):
        """Enhanced rate limiting with adaptive delays"""
        # Figure out how much time has passed since our last request
        current_time = time.time()
        time_since_last = current_time - self.last_request_time
        
        # If we're going too fast, slow down and wait
        if time_since_last < self.rate_limit:
            sleep_time = self.rate_limit - time_since_last
            logger.debug(f"Rate limiting: sleeping for {sleep_time:.2f}s")
            time.sleep(sleep_time)  # Take a nap
            self.scan_stats['rate_limit_delays'] += 1  # Keep track of how often we had to slow down
        
        # Update our timestamps for next time
        self.last_request_time = time.time()
        self.request_count += 1
    
    def _make_request(self, url, method='GET', **kwargs):
        """Enhanced request method with error handling and rate limiting"""
        # Make sure we're not going too fast (be nice to the server)
        self._enforce_rate_limit()
        
        # Remove timeout from kwargs if it exists to avoid conflicts with our default timeout
        if 'timeout' in kwargs:
            del kwargs['timeout']
        
        try:
            # Actually make the HTTP request
            response = self.session.request(
                method, 
                url, 
                timeout=self.timeout,
                verify=self.verify_ssl,
                **kwargs
            )
            self.scan_stats['successful_requests'] += 1  # Yay, it worked!
            return response
            
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout for {url}")  # Server took too long to respond
            self.scan_stats['failed_requests'] += 1
            return None
        except requests.exceptions.ConnectionError:
            logger.warning(f"Connection error for {url}")  # Can't reach the server
            self.scan_stats['failed_requests'] += 1
            return None
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request error for {url}: {e}")  # Something else went wrong
            self.scan_stats['failed_requests'] += 1
            return None
        finally:
            # Always count the request, whether it succeeded or failed
            self.scan_stats['total_requests'] += 1

    def validate_and_normalize_url(self, url):
        """Validate and normalize the target URL"""
        # If someone just types 'example.com', add https:// to make it a proper URL
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Parse the URL to make sure it's actually valid
        parsed = urlparse(url)
        if not parsed.netloc:  # netloc is the domain part (example.com)
            raise ValueError("Invalid URL format")
        
        # Return a clean, normalized URL
        return f"{parsed.scheme}://{parsed.netloc}"

    def get_user_consent(self):
        """Get explicit user consent for passive scanning"""
        # Show a big warning banner to make sure people understand what they're doing
        print("=" * 70)
        print("PASSIVE WEB RECONNAISSANCE SCANNER")
        print("=" * 70)
        print(f"Target: {self.target_url}")
        print("\nThis tool performs PASSIVE reconnaissance by:")
        print("- Crawling publicly accessible web pages")
        print("- Analyzing publicly available content")
        print("- Following links and parsing HTML/JavaScript")
        print("- Discovering forms and hidden fields")
        print("=" * 70)
        
        # Ask for permission - we don't want to scan sites without authorization
        consent = input("\nDo you have permission to scan this target? (yes/no): ").strip().lower()
        if consent not in ['yes', 'y']:
            print("Scanning cancelled.")
            exit(0)  # Bail out if they don't have permission

    def parse_robots_txt(self):
        """Enhanced robots.txt parsing with compliance checking"""
        # Check if the user wants us to respect robots.txt (they can disable this)
        if not self.respect_robots:
            logger.info("Robots.txt compliance disabled by user")
            return None
            
        # Create a parser to understand robots.txt files
        robots_parser = RobotFileParser()
        robots_url = urljoin(self.target_url, '/robots.txt')  # robots.txt is always at the root
        
        try:
            robots_parser.set_url(robots_url)
            robots_parser.read()
            
            # Try to fetch the robots.txt file to see what's in it
            robots_response = self._make_request(robots_url, timeout=5)
            if robots_response and robots_response.status_code == 200:
                self.discovered_files.add(robots_url)  # Found a robots.txt file
                logger.info(f"Found robots.txt: {robots_url}")
                
                # Parse each line of the robots.txt file
                for line in robots_response.text.split('\n'):
                    line = line.strip()
                    if line.startswith('Disallow:'):
                        # This tells us what paths the site doesn't want us to crawl
                        path = line.split(':', 1)[1].strip()
                        if path and path != '/':
                            full_path = urljoin(self.target_url, path.rstrip('*'))
                            self.discovered_directories.add(full_path)  # But we can still note them
                            logger.debug(f"Discovered directory from robots.txt: {full_path}")
                    
                    elif line.startswith('Crawl-delay:'):
                        # This tells us how fast we can crawl
                        try:
                            crawl_delay = float(line.split(':', 1)[1].strip())
                            if crawl_delay > self.rate_limit:
                                logger.info(f"Adjusting rate limit to respect robots.txt: {crawl_delay}s")
                                self.rate_limit = max(crawl_delay, self.rate_limit)  # Be respectful
                        except ValueError:
                            pass  # Ignore invalid crawl-delay values
                            
        except Exception as e:
            logger.warning(f"Could not parse robots.txt: {e}")
            robots_parser = None
            
        return robots_parser

    def parse_sitemap(self):
        """Enhanced sitemap parsing with better error handling"""
        sitemap_urls = ['/sitemap.xml', '/sitemap_index.xml', '/sitemap.xml.gz']
        
        for sitemap_path in sitemap_urls:
            sitemap_url = urljoin(self.target_url, sitemap_path)
            try:
                response = self._make_request(sitemap_url, timeout=5)
                if response and response.status_code == 200:
                    self.discovered_files.add(sitemap_url)
                    logger.info(f"Found sitemap: {sitemap_url}")
                    
                    # Parse XML sitemap
                    if 'xml' in response.headers.get('Content-Type', '').lower():
                        try:
                            root = ET.fromstring(response.content)
                            # Handle different sitemap namespaces
                            namespaces = {
                                'sitemap': 'http://www.sitemaps.org/schemas/sitemap/0.9'
                            }
                            
                            # Find all URLs in sitemap
                            for url_elem in root.findall('.//sitemap:url/sitemap:loc', namespaces):
                                if url_elem.text:
                                    self.discovered_pages.add(url_elem.text)
                                    logger.debug(f"Discovered page from sitemap: {url_elem.text}")
                                    
                            # Handle sitemap index files
                            for sitemap_elem in root.findall('.//sitemap:sitemap/sitemap:loc', namespaces):
                                if sitemap_elem.text:
                                    self.discovered_pages.add(sitemap_elem.text)
                                    logger.debug(f"Discovered sitemap index: {sitemap_elem.text}")
                                    
                        except ET.ParseError as e:
                            logger.warning(f"Could not parse XML sitemap {sitemap_url}: {e}")
                            
            except Exception as e:
                logger.debug(f"Could not fetch sitemap {sitemap_url}: {e}")
                continue

    def analyze_security_headers(self, response, url):
        """Analyze HTTP response headers for security misconfigurations"""
        headers = response.headers
        page_security = {
            'url': url,
            'missing_headers': [],
            'weak_headers': [],
            'good_headers': []
        }
        
        # Check for missing critical security headers
        for header_name, header_info in self.critical_security_headers.items():
            if header_name not in headers:
                page_security['missing_headers'].append({
                    'header': header_name,
                    'description': header_info['description'],
                    'severity': header_info['severity'],
                    'risk': header_info['missing_risk']
                })
                self.vulnerability_summary[header_info['severity']] += 1
            else:
                header_value = headers[header_name]
                page_security['good_headers'].append({
                    'header': header_name,
                    'value': header_value
                })
                
                # Analyze header values for weak configurations
                if header_name == 'Content-Security-Policy':
                    if 'unsafe-inline' in header_value or 'unsafe-eval' in header_value:
                        page_security['weak_headers'].append({
                            'header': header_name,
                            'issue': 'Contains unsafe-inline or unsafe-eval',
                            'severity': 'medium',
                            'value': header_value
                        })
                        self.vulnerability_summary['medium'] += 1
                
                elif header_name == 'Strict-Transport-Security':
                    # Check HSTS max-age
                    if 'max-age=' in header_value:
                        max_age_match = re.search(r'max-age=(\d+)', header_value)
                        if max_age_match:
                            max_age = int(max_age_match.group(1))
                            if max_age < 31536000:  # Less than 1 year
                                page_security['weak_headers'].append({
                                    'header': header_name,
                                    'issue': 'max-age less than 1 year (recommended)',
                                    'severity': 'low',
                                    'value': header_value
                                })
                                self.vulnerability_summary['low'] += 1
                
                elif header_name == 'X-Frame-Options':
                    if header_value.upper() not in ['DENY', 'SAMEORIGIN']:
                        page_security['weak_headers'].append({
                            'header': header_name,
                            'issue': 'Should be DENY or SAMEORIGIN',
                            'severity': 'medium',
                            'value': header_value
                        })
                        self.vulnerability_summary['medium'] += 1
        
        # Store security headers analysis
        self.security_headers[url] = page_security

    def analyze_cookies(self, response, url):
        """Analyze cookies for security flags"""
        if 'Set-Cookie' in response.headers:
            cookies = response.headers.get_all('Set-Cookie') if hasattr(response.headers, 'get_all') else [response.headers['Set-Cookie']]
            
            for cookie_header in cookies:
                cookie_analysis = {
                    'url': url,
                    'cookie_string': cookie_header,
                    'vulnerabilities': []
                }
                
                # Extract cookie name
                cookie_name = cookie_header.split('=')[0].strip()
                cookie_analysis['name'] = cookie_name
                
                # Check for missing security flags
                if 'HttpOnly' not in cookie_header:
                    cookie_analysis['vulnerabilities'].append({
                        'issue': 'Missing HttpOnly flag',
                        'risk': 'Cookie accessible via JavaScript (XSS risk)',
                        'severity': 'medium'
                    })
                    self.vulnerability_summary['medium'] += 1
                
                if 'Secure' not in cookie_header and self.target_url.startswith('https'):
                    cookie_analysis['vulnerabilities'].append({
                        'issue': 'Missing Secure flag on HTTPS site',
                        'risk': 'Cookie transmitted over HTTP (interception risk)',
                        'severity': 'medium'
                    })
                    self.vulnerability_summary['medium'] += 1
                
                if 'SameSite' not in cookie_header:
                    cookie_analysis['vulnerabilities'].append({
                        'issue': 'Missing SameSite attribute',
                        'risk': 'Potential CSRF vulnerability',
                        'severity': 'low'
                    })
                    self.vulnerability_summary['low'] += 1
                
                # Check for session cookies without expiration
                if any(session_indicator in cookie_name.lower() for session_indicator in ['session', 'sess', 'auth', 'login']):
                    if 'Expires=' not in cookie_header and 'Max-Age=' not in cookie_header:
                        cookie_analysis['vulnerabilities'].append({
                            'issue': 'Session cookie without expiration',
                            'risk': 'Session may persist longer than intended',
                            'severity': 'low'
                        })
                        self.vulnerability_summary['low'] += 1
                
                if cookie_analysis['vulnerabilities']:
                    self.insecure_cookies.append(cookie_analysis)

    def analyze_software_stack(self, response, url):
        """Identify software stack from response headers"""
        headers = response.headers
        stack_info = {}
        
        # Server identification
        if 'Server' in headers:
            server = headers['Server']
            stack_info['server'] = server
            
            # Parse server details
            if 'Apache' in server:
                stack_info['web_server'] = 'Apache'
                version_match = re.search(r'Apache/([0-9.]+)', server)
                if version_match:
                    stack_info['web_server_version'] = version_match.group(1)
            
            elif 'nginx' in server:
                stack_info['web_server'] = 'nginx'
                version_match = re.search(r'nginx/([0-9.]+)', server)
                if version_match:
                    stack_info['web_server_version'] = version_match.group(1)
            
            elif 'Microsoft-IIS' in server:
                stack_info['web_server'] = 'IIS'
                version_match = re.search(r'Microsoft-IIS/([0-9.]+)', server)
                if version_match:
                    stack_info['web_server_version'] = version_match.group(1)
        
        # Technology identification from various headers
        tech_headers = {
            'X-Powered-By': 'powered_by',
            'X-AspNet-Version': 'aspnet_version',
            'X-Generator': 'generator',
            'X-Drupal-Cache': 'cms',
            'X-Pingback': 'cms_feature'
        }
        
        for header, tech_type in tech_headers.items():
            if header in headers:
                stack_info[tech_type] = headers[header]
        
        # PHP detection
        if 'X-Powered-By' in headers and 'PHP' in headers['X-Powered-By']:
            php_match = re.search(r'PHP/([0-9.]+)', headers['X-Powered-By'])
            if php_match:
                stack_info['php_version'] = php_match.group(1)
        
        # Framework detection from headers
        framework_headers = {
            'X-Rails-Cache': 'Ruby on Rails',
            'X-Django-Version': 'Django',
            'X-Laravel-Session': 'Laravel',
            'X-Symfony-Cache': 'Symfony'
        }
        
        for header, framework in framework_headers.items():
            if header in headers:
                stack_info['framework'] = framework
        
        if stack_info:
            self.software_stack[url] = stack_info

    def check_form_vulnerabilities(self, form_data, soup, url):
        """Check forms for potential vulnerabilities"""
        # Ensure form_data has all required keys with defaults
        vulnerable_form = {
            'url': url,
            'form_action': form_data.get('action', ''),
            'form_method': form_data.get('method', 'GET'),
            'vulnerabilities': []
        }
        
        # Check for missing CSRF protection
        if form_data.get('method', 'GET').upper() in ['POST', 'PUT', 'DELETE']:
            if not form_data.get('csrf_tokens', []):
                vulnerable_form['vulnerabilities'].append({
                    'type': 'Missing CSRF Protection',
                    'severity': 'high',
                    'description': 'Form lacks CSRF token protection',
                    'risk': 'Vulnerable to Cross-Site Request Forgery attacks'
                })
                self.vulnerability_summary['high'] += 1
        
        # Check for potential XSS in form context
        form_html = str(soup.find('form'))  # Get the actual form HTML
        for input_data in form_data['inputs']:
            input_name = input_data['name']
            input_value = input_data.get('value', '')
            
            # Check if input value contains unescaped HTML/JavaScript
            if input_value and any(xss_char in input_value for xss_char in ['<', '>', '"', "'"]):
                if not self.is_properly_escaped(input_value):
                    vulnerable_form['vulnerabilities'].append({
                        'type': 'Potential Reflected XSS',
                        'severity': 'high',
                        'description': f'Input field "{input_name}" may be vulnerable to XSS',
                        'risk': 'Unescaped user input could lead to script injection',
                        'field': input_name
                    })
                    self.vulnerability_summary['high'] += 1
            
            # Check for SQL injection indicators in form context
            if any(sql_word in input_name.lower() for sql_word in ['id', 'user', 'search', 'query', 'filter']):
                vulnerable_form['vulnerabilities'].append({
                    'type': 'Potential SQL Injection Point',
                    'severity': 'high',
                    'description': f'Input field "{input_name}" may be vulnerable to SQL injection',
                    'risk': 'Database queries might not be properly sanitized',
                    'field': input_name,
                    'recommendation': 'Test with SQL injection payloads'
                })
                self.vulnerability_summary['high'] += 1
        
        # Check for file upload vulnerabilities
        if form_data.get('file_uploads', []):
            vulnerable_form['vulnerabilities'].append({
                'type': 'File Upload Functionality',
                'severity': 'medium',
                'description': 'Form contains file upload fields',
                'risk': 'Potential for malicious file uploads if not properly validated',
                'fields': form_data.get('file_uploads', []),
                'recommendation': 'Verify file type validation and upload restrictions'
            })
            self.vulnerability_summary['medium'] += 1
        
        # Check for password fields without HTTPS
        if form_data.get('sensitive_fields', []) and not url.startswith('https://'):
            vulnerable_form['vulnerabilities'].append({
                'type': 'Sensitive Data Over HTTP',
                'severity': 'critical',
                'description': 'Password/sensitive fields transmitted over HTTP',
                'risk': 'Credentials can be intercepted in transit',
                'fields': form_data.get('sensitive_fields', [])
            })
            self.vulnerability_summary['critical'] += 1
        
        if vulnerable_form['vulnerabilities']:
            self.vulnerable_forms.append(vulnerable_form)

    def is_properly_escaped(self, value):
        """Check if a value is properly HTML escaped"""
        dangerous_chars = {
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#x27;',
            '&': '&amp;'
        }
        
        for char, escaped in dangerous_chars.items():
            if char in value and escaped not in value:
                return False
        return True

    def test_error_based_sql_detection(self, url):
        """Test for SQL injection by analyzing error responses (non-intrusive)"""
        # Only test if URL has parameters
        if '?' not in url:
            return
        
        try:
            # Test with a simple quote to see if it generates SQL errors
            test_url = url + "'"
            response = requests.get(
                test_url,
                headers=self.headers,
                timeout=5,
                verify=self.verify_ssl
            )
            
            # Check for SQL error patterns in response
            for pattern in self.sql_error_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    self.vulnerable_forms.append({
                        'url': url,
                        'vulnerabilities': [{
                            'type': 'SQL Injection Error Pattern Detected',
                            'severity': 'critical',
                            'description': f'SQL error pattern found: {pattern}',
                            'risk': 'Application may be vulnerable to SQL injection',
                            'test_payload': "Single quote test",
                            'recommendation': 'Implement proper input sanitization and parameterized queries'
                        }]
                    })
                    self.vulnerability_summary['critical'] += 1
                    break
                    
        except requests.RequestException:
            pass  # Ignore request errors for this test

    def detect_tokens_in_content(self, content, url, context):
        """Detect hidden tokens and secrets in content using regex patterns"""
        for token_type, pattern in self.token_patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                token_value = match.group(1) if match.groups() else match.group(0)
                
                # Skip very short tokens (likely false positives)
                if len(token_value) < 10:
                    continue
                
                # Truncate long tokens for display
                display_value = token_value[:30] + '...' if len(token_value) > 30 else token_value
                
                self.hidden_tokens.append({
                    'url': url,
                    'type': token_type,
                    'context': context,
                    'value': display_value,
                    'length': len(token_value),
                    'pattern_matched': pattern
                })
                
    def analyze_forms(self, soup, url):
        """Comprehensive form analysis to detect hidden fields and vulnerabilities"""
        for form_idx, form in enumerate(soup.find_all('form')):
            form_data = {
                'url': url,
                'form_index': form_idx,
                'method': form.get('method', 'GET').upper(),
                'action': urljoin(url, form.get('action', '')),
                'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                'inputs': [],
                'hidden_fields': [],
                'csrf_tokens': [],
                'file_uploads': [],
                'sensitive_fields': []
            }
            
            # Analyze all form elements
            for element in form.find_all(['input', 'select', 'textarea', 'button']):
                element_data = {
                    'tag': element.name,
                    'name': element.get('name', ''),
                    'type': element.get('type', 'text').lower(),
                    'value': element.get('value', ''),
                    'id': element.get('id', ''),
                    'class': element.get('class', []),
                    'required': element.has_attr('required'),
                    'placeholder': element.get('placeholder', '')
                }
                
                form_data['inputs'].append(element_data)
                
                # Categorize special field types
                if element_data['type'] == 'hidden':
                    hidden_field = {
                        'name': element_data['name'],
                        'value': element_data['value']
                    }
                    form_data['hidden_fields'].append(hidden_field)
                    
                    # Check for CSRF tokens in hidden fields
                    name_lower = element_data['name'].lower()
                    if any(csrf_term in name_lower for csrf_term in ['csrf', 'token', 'authenticity', '_token']):
                        form_data['csrf_tokens'].append(hidden_field)
                        
                elif element_data['type'] == 'file':
                    form_data['file_uploads'].append(element_data['name'])
                    
                elif any(sensitive in element_data['name'].lower() 
                        for sensitive in ['password', 'pass', 'pwd', 'secret', 'key', 'auth']):
                    form_data['sensitive_fields'].append(element_data['name'])
            
            # Only add forms that have inputs
            if form_data['inputs']:
                self.forms.append(form_data)
                
                # Check for vulnerabilities in this form
                self.check_form_vulnerabilities(form_data, soup, url)

    def analyze_javascript(self, soup, url):
        """Analyze JavaScript for hidden tokens and endpoints"""
        # Analyze inline JavaScript
        for script in soup.find_all('script'):
            if script.string and script.string.strip():
                self.detect_tokens_in_content(script.string, url, "Inline JavaScript")
                
                # Look for potential API endpoints in JavaScript
                api_patterns = [
                    r'["\'](/api/[^"\']*)["\']',
                    r'["\']([^"\']*\.json)["\']',
                    r'fetch\s*\(\s*["\']([^"\']+)["\']',
                    r'ajax\s*\(\s*["\']([^"\']+)["\']'
                ]
                
                for pattern in api_patterns:
                    matches = re.finditer(pattern, script.string, re.IGNORECASE)
                    for match in matches:
                        endpoint = match.group(1)
                        full_endpoint = urljoin(url, endpoint)
                        if urlparse(full_endpoint).netloc == self.domain:
                            self.discovered_pages.add(full_endpoint)
        
        # Analyze external JavaScript files
        for script in soup.find_all('script', src=True):
            js_url = urljoin(url, script['src'])
            if urlparse(js_url).netloc == self.domain:
                try:
                    js_response = self._make_request(js_url, timeout=10)
                    if js_response and js_response.status_code == 200:
                        self.discovered_files.add(js_url)
                        self.detect_tokens_in_content(
                            js_response.text,
                            js_url, 
                            "External JavaScript"
                        )
                except Exception as e:
                    logger.warning(f"Could not fetch JavaScript file {js_url}: {e}")
                    
    def analyze_html_content(self, soup, url):
        """Analyze HTML content for hidden tokens and metadata"""
        # Check HTML comments for sensitive information
        comments = soup.find_all(string=lambda text: isinstance(text, Comment))
        for comment in comments:
            self.detect_tokens_in_content(str(comment), url, "HTML Comment")
        
        # Check meta tags
        for meta in soup.find_all('meta'):
            content = meta.get('content', '')
            name = meta.get('name', '')
            if content and any(keyword in name.lower() for keyword in ['csrf', 'token', 'auth']):
                self.detect_tokens_in_content(content, url, "Meta Tag")
        
        # Check for hidden divs or spans that might contain tokens
        for element in soup.find_all(['div', 'span'], style=re.compile(r'display\s*:\s*none', re.I)):
            if element.string:
                self.detect_tokens_in_content(element.string, url, "Hidden Element")

    def passive_crawl(self):
        """Perform passive crawling of the website"""
        robots_parser = self.parse_robots_txt()
        self.parse_sitemap()
        
        queue = deque([(self.target_url, 0)])
        
        while queue and len(self.visited) < self.max_pages:
            current_url, depth = queue.popleft()
            
            if current_url in self.visited or depth > self.max_depth:
                continue
                
            # Check robots.txt compliance
            if robots_parser and not robots_parser.can_fetch('*', current_url):
                logger.info(f"Skipping {current_url} due to robots.txt restrictions")
                continue
                
            self.visited.add(current_url)
            self.discovered_pages.add(current_url)
            
            logger.info(f"Crawling: {current_url} (depth: {depth})")
            
            try:
                response = self._make_request(
                    current_url,
                    allow_redirects=True
                )
                
                if response.status_code != 200:
                    logger.warning(f"HTTP {response.status_code} for {current_url}")
                    continue
                
                # Perform vulnerability analysis on response
                self.analyze_security_headers(response, current_url)
                self.analyze_cookies(response, current_url)
                self.analyze_software_stack(response, current_url)
                
                # Test for SQL injection on parameterized URLs
                if '?' in current_url:
                    self.test_error_based_sql_detection(current_url)
                
                content_type = response.headers.get('Content-Type', '').lower()
                
                # Handle different content types
                if 'text/html' in content_type:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    
                    # Perform comprehensive analysis
                    self.analyze_forms(soup, current_url)
                    self.analyze_javascript(soup, current_url)
                    self.analyze_html_content(soup, current_url)
                    
                    # Extract links for continued crawling
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        full_url = urljoin(current_url, href)
                        
                        # Only crawl same-domain links
                        if urlparse(full_url).netloc == self.domain:
                            # Remove fragments and normalize
                            clean_url = urlparse(full_url)._replace(fragment='').geturl()
                            
                            if clean_url not in self.visited:
                                # Detect if it's a directory or file
                                if clean_url.endswith('/') or '.' not in clean_url.split('/')[-1]:
                                    self.discovered_directories.add(clean_url)
                                else:
                                    self.discovered_files.add(clean_url)
                                
                                queue.append((clean_url, depth + 1))
                
                elif any(file_type in content_type for file_type in ['javascript', 'json', 'xml', 'css']):
                    # Analyze non-HTML content for tokens
                    self.discovered_files.add(current_url)
                    self.detect_tokens_in_content(response.text, current_url, f"File ({content_type})") 
                
            except requests.RequestException as e:
                logger.error(f"Error crawling {current_url}: {e}")
                continue
            
            time.sleep(self.rate_limit)

    def discover_common_files(self):
        """Passively discover common files by checking references"""
        common_files = [
            'robots.txt', 'sitemap.xml', 'favicon.ico', 'humans.txt',
            'security.txt', '.well-known/security.txt', 'ads.txt',
            'crossdomain.xml', 'clientaccesspolicy.xml'
        ]
        
        for file_path in common_files:
            full_url = urljoin(self.target_url, file_path)
            try:
                response = self._make_request(full_url, method='HEAD', timeout=5)
                if response and response.status_code == 200:
                    self.discovered_files.add(full_url)
                    logger.info(f"Found common file: {full_url}")
            except Exception as e:
                logger.debug(f"Could not check common file {full_url}: {e}")
                continue
            
            # Use enhanced rate limiting
            self._enforce_rate_limit()

    def generate_report(self):
        """Generate comprehensive reconnaissance report"""
        # Calculate scan duration
        scan_duration = (datetime.now() - self.scan_start_time).total_seconds()
        self.scan_stats['scan_duration'] = scan_duration
        
        report_data = {
            'target': self.target_url,
            'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'scan_duration_seconds': round(scan_duration, 2),
            'summary': {
                'pages_discovered': len(self.discovered_pages),
                'directories_found': len(self.discovered_directories),
                'files_found': len(self.discovered_files),
                'forms_analyzed': len(self.forms),
                'hidden_tokens_found': len(self.hidden_tokens),
                'security_issues': sum(self.vulnerability_summary.values()),
                'critical_issues': self.vulnerability_summary['critical'],
                'high_issues': self.vulnerability_summary['high'],
                'medium_issues': self.vulnerability_summary['medium'],
                'low_issues': self.vulnerability_summary['low']
            },
            'scan_statistics': self.scan_stats,
            'findings': {
                'discovered_pages': sorted(list(self.discovered_pages)),
                'discovered_directories': sorted(list(self.discovered_directories)),
                'discovered_files': sorted(list(self.discovered_files)),
                'forms': self.forms,
                'hidden_tokens': self.hidden_tokens
            },
            'vulnerabilities': {
                'security_headers': self.security_headers,
                'insecure_cookies': self.insecure_cookies,
                'vulnerable_forms': self.vulnerable_forms,
                'software_stack': self.software_stack,
                'summary': self.vulnerability_summary,
                'detailed_findings': {
                    'security_header_vulnerabilities': [],
                    'cookie_vulnerabilities': [],
                    'form_vulnerabilities': [],
                    'sql_injection_findings': [],
                    'xss_findings': [],
                    'information_disclosure': []
                }
            }
        }
        
        # Populate detailed vulnerability findings for better reporting
        for url, header_analysis in self.security_headers.items():
            if header_analysis['missing_headers'] or header_analysis['weak_headers']:
                for header in header_analysis.get('missing_headers', []):
                    report_data['vulnerabilities']['detailed_findings']['security_header_vulnerabilities'].append({
                        'vulnerability_name': f"Missing {header['header']}",
                        'location': url,
                        'risk_level': header['severity'],
                        'description': header['description'],
                        'risk': header['risk']
                    })
                
                for header in header_analysis.get('weak_headers', []):
                    report_data['vulnerabilities']['detailed_findings']['security_header_vulnerabilities'].append({
                        'vulnerability_name': f"Weak {header['header']}",
                        'location': url,
                        'risk_level': header['severity'],
                        'description': header['issue'],
                        'risk': 'Security header configured with weak settings'
                    })
        
        for cookie in self.insecure_cookies:
            for vuln in cookie['vulnerabilities']:
                report_data['vulnerabilities']['detailed_findings']['cookie_vulnerabilities'].append({
                    'vulnerability_name': vuln['issue'],
                    'location': cookie['url'],
                    'risk_level': vuln['severity'],
                    'description': f"Cookie: {cookie['name']}",
                    'risk': vuln['risk']
                })
        
        for form in self.vulnerable_forms:
            for vuln in form['vulnerabilities']:
                report_data['vulnerabilities']['detailed_findings']['form_vulnerabilities'].append({
                    'vulnerability_name': vuln['type'],
                    'location': form['url'],
                    'risk_level': vuln['severity'],
                    'description': vuln['description'],
                    'risk': vuln['risk'],
                    'affected_field': vuln.get('field', 'N/A'),
                    'recommendation': vuln.get('recommendation', 'N/A')
                })
        # Save JSON report
        with open('vulnerability_scan_report.json', 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        # Generate and save markdown report
        md_report = self.generate_markdown_report(report_data)
        with open('vulnerability_scan_report.md', 'w', encoding='utf-8') as f:
            f.write(md_report)
        
        logger.info("Reports saved: vulnerability_scan_report.json, vulnerability_scan_report.md")
        return report_data

    def generate_markdown_report(self, data):
        """Generate detailed markdown report"""
        md = f"""# 🛡️ Passive Web Reconnaissance & Vulnerability Assessment Report

## 📋 Scan Information
| Field | Value |
|-------|-------|
| **Target URL** | `{data['target']}` |
| **Scan Date** | {data['scan_timestamp']} |
| **Scan Duration** | {data['scan_statistics']['scan_duration']:.2f} seconds |
| **Total Requests** | {data['scan_statistics']['total_requests']} |
| **Successful Requests** | {data['scan_statistics']['successful_requests']} |
| **Failed Requests** | {data['scan_statistics']['failed_requests']} |
| **Rate Limit Delays** | {data['scan_statistics']['rate_limit_delays']} |

## 📊 Executive Summary
| Metric | Count |
|--------|-------|
| **Pages Discovered** | {data['summary']['pages_discovered']} |
| **Directories Found** | {data['summary']['directories_found']} |
| **Files Found** | {data['summary']['files_found']} |
| **Forms Analyzed** | {data['summary']['forms_analyzed']} |
| **Hidden Tokens Found** | {data['summary']['hidden_tokens_found']} |
| **Total Security Issues** | {data['summary']['security_issues']} |

## Discovered Pages ({len(data['findings']['discovered_pages'])})
"""
        for page in data['findings']['discovered_pages']:
            md += f"- {page}\n"

        md += f"\n## Discovered Directories ({len(data['findings']['discovered_directories'])})\n"
        for directory in data['findings']['discovered_directories']:
            md += f"- {directory}\n"

        md += f"\n## Discovered Files ({len(data['findings']['discovered_files'])})\n"
        for file_path in data['findings']['discovered_files']:
            md += f"- {file_path}\n"

        md += f"\n## Form Analysis ({len(data['findings']['forms'])} forms)\n"
        for i, form in enumerate(data['findings']['forms'], 1):
            md += f"### Form #{i} - {form['url']}\n"
            md += f"- **Method:** {form['method']}\n"
            md += f"- **Action:** {form['action']}\n"
            md += f"- **Encoding:** {form['enctype']}\n"
            md += f"- **Total Inputs:** {len(form['inputs'])}\n"
            
            if form['hidden_fields']:
                md += f"- **Hidden Fields ({len(form['hidden_fields'])}):**\n"
                for hidden in form['hidden_fields']:
                    md += f"  - {hidden['name']}: {hidden['value'][:50]}{'...' if len(hidden['value']) > 50 else ''}\n"
            
            if form['csrf_tokens']:
                md += f"- **CSRF Tokens:** {len(form['csrf_tokens'])} found\n"
            
            if form['file_uploads']:
                md += f"- **File Upload Fields:** {', '.join(form['file_uploads'])}\n"
            
            if form['sensitive_fields']:
                md += f"- **Sensitive Fields:** {', '.join(form['sensitive_fields'])}\n"
            
            md += "\n"

        md += f"\n## Hidden Tokens & Secrets ({len(data['findings']['hidden_tokens'])} found)\n"
        for token in data['findings']['hidden_tokens']:
            md += f"- **{token['type']}** in {token['context']} at {token['url']}\n"
            md += f"  - Value: `{token['value']}`\n"
            md += f"  - Length: {token['length']} characters\n\n"

        # Add comprehensive vulnerability findings section
        md += f"\n## Vulnerability Findings\n"
        
        # Security Headers Vulnerabilities
        if data['vulnerabilities']['security_headers']:
            md += f"\n### Security Headers Analysis\n"
            for url, header_analysis in data['vulnerabilities']['security_headers'].items():
                if header_analysis['missing_headers'] or header_analysis['weak_headers']:
                    md += f"\n**URL:** {url}\n"
                    
                    if header_analysis['missing_headers']:
                        md += f"- **Missing Security Headers:**\n"
                        for header in header_analysis['missing_headers']:
                            md += f"  - {header['header']} ({header['severity'].upper()}) - {header['risk']}\n"
                    
                    if header_analysis['weak_headers']:
                        md += f"- **Weak Security Headers:**\n"
                        for header in header_analysis['weak_headers']:
                            md += f"  - {header['header']} ({header['severity'].upper()}) - {header['issue']}\n"
        
        # Insecure Cookies
        if data['vulnerabilities']['insecure_cookies']:
            md += f"\n### Insecure Cookies\n"
            for cookie in data['vulnerabilities']['insecure_cookies']:
                md += f"\n**URL:** {cookie['url']}\n"
                md += f"**Cookie:** {cookie['name']}\n"
                for vuln in cookie['vulnerabilities']:
                    md += f"- **{vuln['issue']}** ({vuln['severity'].upper()}) - {vuln['risk']}\n"
        
        # Vulnerable Forms
        if data['vulnerabilities']['vulnerable_forms']:
            md += f"\n### Vulnerable Forms\n"
            for form in data['vulnerabilities']['vulnerable_forms']:
                md += f"\n**URL:** {form['url']}\n"
                md += f"**Form Action:** {form['form_action']}\n"
                md += f"**Method:** {form['form_method']}\n"
                for vuln in form['vulnerabilities']:
                    md += f"- **{vuln['type']}** ({vuln['severity'].upper()}) - {vuln['description']}\n"
                    md += f"  - **Risk:** {vuln['risk']}\n"
                    if 'field' in vuln:
                        md += f"  - **Affected Field:** {vuln['field']}\n"
                    if 'recommendation' in vuln:
                        md += f"  - **Recommendation:** {vuln['recommendation']}\n"
        
        # Software Stack Information
        if data['vulnerabilities']['software_stack']:
            md += f"\n### Software Stack Discovery\n"
            for url, stack_info in data['vulnerabilities']['software_stack'].items():
                md += f"\n**URL:** {url}\n"
                for key, value in stack_info.items():
                    md += f"- **{key.replace('_', ' ').title()}:** {value}\n"
        
        # Vulnerability Summary
        md += f"\n## Vulnerability Summary\n"
        md += f"- **🔴 Critical:** {data['vulnerabilities']['summary']['critical']}\n"
        md += f"- **🟠 High:** {data['vulnerabilities']['summary']['high']}\n"
        md += f"- **🟡 Medium:** {data['vulnerabilities']['summary']['medium']}\n"
        md += f"- **🔵 Low:** {data['vulnerabilities']['summary']['low']}\n"
        md += f"- **📊 Total Issues:** {sum(data['vulnerabilities']['summary'].values())}\n"

        # Add a consolidated vulnerability findings table
        md += f"\n## Consolidated Vulnerability Findings\n"
        md += f"| Vulnerability Name | Location | Risk Level | Description | Risk |\n"
        md += f"|-------------------|----------|------------|-------------|------|\n"
        
        # Security Header Vulnerabilities
        if data['vulnerabilities']['security_headers']:
            for url, header_analysis in data['vulnerabilities']['security_headers'].items():
                if header_analysis['missing_headers']:
                    for header in header_analysis['missing_headers']:
                        md += f"| Missing {header['header']} | {url} | {header['severity'].upper()} | {header['description']} | {header['risk']} |\n"
                
                if header_analysis['weak_headers']:
                    for header in header_analysis['weak_headers']:
                        md += f"| Weak {header['header']} | {url} | {header['severity'].upper()} | {header['issue']} | Security header configured with weak settings |\n"
        
        # Cookie Vulnerabilities
        if data['vulnerabilities']['insecure_cookies']:
            for cookie in data['vulnerabilities']['insecure_cookies']:
                for vuln in cookie['vulnerabilities']:
                    md += f"| {vuln['issue']} | {cookie['url']} | {vuln['severity'].upper()} | Cookie: {cookie['name']} | {vuln['risk']} |\n"
        
        # Form Vulnerabilities
        if data['vulnerabilities']['vulnerable_forms']:
            for form in data['vulnerabilities']['vulnerable_forms']:
                for vuln in form['vulnerabilities']:
                    description = vuln['description']
                    if 'field' in vuln:
                        description += f" (Field: {vuln['field']})"
                    md += f"| {vuln['type']} | {form['url']} | {vuln['severity'].upper()} | {description} | {vuln['risk']} |\n"

        return md

    def run_passive_scan(self):
        """Execute complete passive reconnaissance scan"""
        # First, make sure the user has permission to scan this target
        self.get_user_consent()
        
        logger.info(f"Starting passive reconnaissance of {self.target_url}")
        print(f"\nScanning {self.target_url}...")
        
        # Phase 1: Look for common files that websites often have (robots.txt, sitemap.xml, etc.)
        print("Phase 1: Discovering common files...")
        self.discover_common_files()
        
        # Phase 2: This is the main scanning phase - crawl the site and analyze everything
        print("Phase 2: Passive crawling and vulnerability analysis...")
        self.passive_crawl()
        
        # Phase 3: Generate reports with all our findings
        print("Phase 3: Generating reports...")
        try:
            report = self.generate_report()
        except Exception as e:
            logger.error(f"Error generating report: {e}")
            # If detailed report generation fails, create a basic one so we don't crash
            report = {
                'target': self.target_url,
                'scan_timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'error': str(e),
                'summary': {
                    'pages_discovered': len(self.discovered_pages),
                    'directories_found': len(self.discovered_directories),
                    'files_found': len(self.discovered_files),
                    'forms_analyzed': len(self.forms),
                    'hidden_tokens_found': len(self.hidden_tokens),
                    'security_issues': sum(self.vulnerability_summary.values())
                }
            }
        
        # Calculate how long the whole scan took
        scan_duration = (datetime.now() - self.scan_start_time).total_seconds()
        self.scan_stats['scan_duration'] = scan_duration
        
        # Display enhanced summary
        print("\n" + "=" * 100)
        print("🎯 WEB RECONNAISSANCE & VULNERABILITY ASSESSMENT COMPLETE")
        print("=" * 100)
        
        print(f"\n📊 DISCOVERY RESULTS:")
        print(f"  ✓ Pages discovered: {len(self.discovered_pages)}")
        print(f"  ✓ Directories found: {len(self.discovered_directories)}")
        print(f"  ✓ Files found: {len(self.discovered_files)}")
        print(f"  ✓ Forms analyzed: {len(self.forms)}")
        print(f"  ✓ Hidden tokens found: {len(self.hidden_tokens)}")
        
        print(f"\n🛡️ SECURITY ASSESSMENT:")
        print(f"  🔴 Critical issues: {self.vulnerability_summary['critical']}")
        print(f"  🟠 High issues: {self.vulnerability_summary['high']}")
        print(f"  🟡 Medium issues: {self.vulnerability_summary['medium']}")
        print(f"  🔵 Low issues: {self.vulnerability_summary['low']}")
        print(f"  📊 Total issues: {sum(self.vulnerability_summary.values())}")
        
        print(f"\n⚡ SCAN PERFORMANCE:")
        print(f"  ⏱️  Scan duration: {scan_duration:.2f} seconds")
        print(f"  📡 Total requests: {self.scan_stats['total_requests']}")
        print(f"  ✅ Successful: {self.scan_stats['successful_requests']}")
        print(f"  ❌ Failed: {self.scan_stats['failed_requests']}")
        print(f"  🐌 Rate limit delays: {self.scan_stats['rate_limit_delays']}")
        
        # Security recommendations
        if self.vulnerability_summary['critical'] > 0:
            print(f"\n🚨 CRITICAL ALERT: {self.vulnerability_summary['critical']} critical security issues found!")
            print("   ⚠️  IMMEDIATE REMEDIATION REQUIRED!")
        elif self.vulnerability_summary['high'] > 0:
            print(f"\n⚠️  HIGH PRIORITY: {self.vulnerability_summary['high']} high-priority security issues found!")
            print("   🔍 Review and address promptly.")
        elif self.vulnerability_summary['medium'] > 0:
            print(f"\n🟡 MEDIUM PRIORITY: {self.vulnerability_summary['medium']} medium-priority issues found.")
            print("   📋 Plan remediation within 30 days.")
        else:
            print(f"\n✅ GOOD NEWS: No high or critical security issues found!")
            print("   🎉 Your application appears to follow security best practices.")
        
        if self.hidden_tokens:
            print(f"\n🔐 SECRETS DISCOVERED: {len(self.hidden_tokens)} potential tokens/secrets found!")
            print("   🔍 Review for sensitive information exposure.")
        
        print(f"\n📋 REPORTS GENERATED:")
        print(f"  📄 JSON Report: vulnerability_scan_report.json")
        print(f"  📝 Markdown Report: vulnerability_scan_report.md")
        
        print(f"\n🎯 NEXT STEPS:")
        print(f"  1. Review the detailed vulnerability findings")
        print(f"  2. Prioritize remediation based on risk levels")
        print(f"  3. Implement security fixes for identified issues")
        print(f"  4. Consider running follow-up scans after remediation")
        
        print("\n" + "=" * 100)
        
        return report

def main():
    # Set up the command line argument parser - this handles all the options users can pass
    parser = argparse.ArgumentParser(
        description="🛡️ Professional Web Reconnaissance & Vulnerability Scanner",
        epilog="Example: python scanner.py --url https://example.com --max-depth 3 --rate-limit 1.0 --verbose",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # The only argument you absolutely need - what website to scan
    parser.add_argument('--url', required=True, 
                       help="Target URL/domain to scan (e.g., https://example.com)")
    
    # How to control the scanning behavior
    parser.add_argument('--max-depth', type=int, default=2, 
                       help="Maximum crawl depth (default: 2)")
    parser.add_argument('--max-pages', type=int, default=1000, 
                       help="Maximum pages to crawl (default: 1000)")
    parser.add_argument('--rate-limit', type=float, default=0.5, 
                       help="Delay between requests in seconds (default: 0.5)")
    parser.add_argument('--timeout', type=int, default=30, 
                       help="Request timeout in seconds (default: 30)")
    parser.add_argument('--max-retries', type=int, default=3, 
                       help="Maximum retry attempts for failed requests (default: 3)")
    
    # Security and compliance options - be nice to the target server
    parser.add_argument('--no-verify', action='store_true', 
                       help="Disable SSL certificate verification")
    parser.add_argument('--no-robots', action='store_true', 
                       help="Disable robots.txt compliance")
    parser.add_argument('--user-agent', 
                       help="Custom User-Agent string")
    
    # Output and logging options - control what you see and save
    parser.add_argument('--verbose', '-v', action='store_true', 
                       help="Enable verbose logging")
    parser.add_argument('--log-file', 
                       help="Save detailed logs to file")
    parser.add_argument('--output-dir', 
                       help="Directory to save reports (default: current directory)")
    
    # Advanced options - for when you want to go fast (but be careful!)
    parser.add_argument('--aggressive', action='store_true', 
                       help="Enable aggressive scanning (faster, less respectful)")
    
    # Parse all the arguments the user provided
    args = parser.parse_args()
    
    # Set up our logging system based on user preferences
    logger = setup_logging(args.log_file, args.verbose)
    
    # If aggressive mode is on, reduce rate limiting (but be careful with this!)
    if args.aggressive:
        args.rate_limit = max(0.1, args.rate_limit * 0.5)
        logger.info("Aggressive mode enabled - reduced rate limiting")
    
    try:
        # Create our scanner object with all the user's settings
        scanner = PassiveWebReconScanner(
            target_url=args.url,
            max_depth=args.max_depth,
            max_pages=args.max_pages,
            rate_limit=args.rate_limit,
            verify_ssl=not args.no_verify,
            timeout=args.timeout,
            max_retries=args.max_retries,
            user_agent=args.user_agent,
            respect_robots=not args.no_robots
        )
        
        # Let's go! Start the vulnerability assessment
        logger.info("🚀 Starting enhanced vulnerability assessment...")
        scanner.run_passive_scan()
        
    except ValueError as e:
        # User provided invalid input (like a malformed URL)
        logger.error(f"❌ Invalid input: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        # User pressed Ctrl+C to stop the scan
        logger.info("\n⏹️  Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        # Something unexpected went wrong
        logger.error(f"💥 Unexpected error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()  # Show the full error details
        sys.exit(1)

if __name__ == "__main__":
    main()