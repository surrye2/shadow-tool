# modules/new_core/decoder_utils.py

import base64
import urllib.parse
import re
import binascii
import html
from termcolor import cprint
from datetime import datetime

class DecoderUtils:
    """Advanced decoder with multi-layer decoding and vulnerability detection"""
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.decoding_history = []
        self.findings = []
    
    def try_decode(self, data, depth=0, max_depth=5):
        """
        Attempts to decode data using multiple encoding methods.
        Supports recursive decoding (double encoding, triple encoding, etc.)
        
        Args:
            data: Input string to decode
            depth: Current decoding depth (internal use)
            max_depth: Maximum decoding depth to prevent infinite loops
        
        Returns:
            tuple: (decoded_string, method_used, depth)
        """
        if not data or len(data) < 3 or depth >= max_depth:
            return None, None, depth
        
        original_data = data
        
        # 1. URL Decoding (single and double)
        try:
            decoded_url = urllib.parse.unquote(data)
            if decoded_url != data:
                # Check for double encoding
                decoded_double = urllib.parse.unquote(decoded_url)
                if decoded_double != decoded_url:
                    self.decoding_history.append(('Double URL', decoded_double))
                    return decoded_double, 'Double URL', depth + 1
                else:
                    self.decoding_history.append(('URL', decoded_url))
                    return decoded_url, 'URL', depth + 1
        except:
            pass
        
        # 2. Base64 Decoding (multiple variations)
        try:
            # Standard Base64
            if re.fullmatch(r'[A-Za-z0-9+/=]+', data) and len(data) % 4 == 0:
                decoded_b64 = base64.b64decode(data).decode('utf-8', errors='ignore')
                if len(decoded_b64) > 3 and decoded_b64 != data:
                    self.decoding_history.append(('Base64', decoded_b64))
                    return decoded_b64, 'Base64', depth + 1
            
            # Base64 with URL-safe characters
            if re.fullmatch(r'[A-Za-z0-9_-]+', data):
                padded = data + '=' * (4 - len(data) % 4) if len(data) % 4 else data
                decoded_b64url = base64.urlsafe_b64decode(padded).decode('utf-8', errors='ignore')
                if len(decoded_b64url) > 3 and decoded_b64url != data:
                    self.decoding_history.append(('Base64URL', decoded_b64url))
                    return decoded_b64url, 'Base64URL', depth + 1
        except:
            pass
        
        # 3. Hex Decoding
        try:
            if re.fullmatch(r'[0-9a-fA-F]{2,}', data) and len(data) % 2 == 0:
                decoded_hex = bytes.fromhex(data).decode('utf-8', errors='ignore')
                if len(decoded_hex) > 3 and decoded_hex != data:
                    self.decoding_history.append(('Hex', decoded_hex))
                    return decoded_hex, 'Hex', depth + 1
        except:
            pass
        
        # 4. HTML Entity Decoding
        try:
            decoded_html = html.unescape(data)
            if decoded_html != data and len(decoded_html) > 3:
                self.decoding_history.append(('HTML Entity', decoded_html))
                return decoded_html, 'HTML Entity', depth + 1
        except:
            pass
        
        # 5. Unicode Decoding
        try:
            # Detect Unicode escape sequences like \uXXXX
            if r'\u' in data:
                decoded_unicode = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), data)
                if decoded_unicode != data:
                    self.decoding_history.append(('Unicode', decoded_unicode))
                    return decoded_unicode, 'Unicode', depth + 1
            
            # Detect %uXXXX format
            if r'%u' in data:
                decoded_unicode = re.sub(r'%u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), data)
                if decoded_unicode != data:
                    self.decoding_history.append(('Unicode (URL)', decoded_unicode))
                    return decoded_unicode, 'Unicode (URL)', depth + 1
        except:
            pass
        
        # 6. ROT13 Decoding
        try:
            import codecs
            decoded_rot13 = codecs.decode(data, 'rot_13')
            if decoded_rot13 != data and len(decoded_rot13) > 3:
                self.decoding_history.append(('ROT13', decoded_rot13))
                return decoded_rot13, 'ROT13', depth + 1
        except:
            pass
        
        # 7. Gzip/Deflate (if data is compressed)
        try:
            import zlib
            import gzip
            from io import BytesIO
            
            # Try zlib decompress
            decoded_zlib = zlib.decompress(data.encode(), 16+zlib.MAX_WBITS)
            if decoded_zlib:
                self.decoding_history.append(('Gzip', decoded_zlib.decode()))
                return decoded_zlib.decode(), 'Gzip', depth + 1
        except:
            pass
        
        return None, None, depth
    
    def detect_vulnerabilities(self, decoded_text):
        """Advanced vulnerability detection with pattern matching"""
        findings = []
        decoded_lower = decoded_text.lower()
        
        # SQL Injection patterns
        sqli_patterns = [
            (r'union\s+select', 'SQL Injection - UNION'),
            (r'OR\s+1\s*=\s*1', 'SQL Injection - Boolean'),
            (r'AND\s+1\s*=\s*1', 'SQL Injection - Boolean'),
            (r';\s*(DROP|DELETE|INSERT|UPDATE)', 'SQL Injection - Manipulation'),
            (r'(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\s+', 'SQL Keyword'),
            (r'--\s*$', 'SQL Comment Injection'),
            (r'/\*.*?\*/', 'SQL Comment Block'),
            (r'(mysql|sqlite|postgresql)_error', 'SQL Error Message'),
            (r'you have an error in your sql syntax', 'SQL Syntax Error'),
            (r'warning.*mysql', 'MySQL Warning'),
        ]
        
        # XSS patterns
        xss_patterns = [
            (r'<script[^>]*>.*?</script>', 'XSS - Script Tag'),
            (r'on\w+\s*=\s*["\'][^"\']*["\']', 'XSS - Event Handler'),
            (r'javascript\s*:', 'XSS - JavaScript Protocol'),
            (r'<iframe[^>]*>', 'XSS - IFrame'),
            (r'<object[^>]*>', 'XSS - Object Tag'),
            (r'<embed[^>]*>', 'XSS - Embed Tag'),
            (r'<svg[^>]*on\w+', 'XSS - SVG Vector'),
            (r'<math[^>]*on\w+', 'XSS - MathML'),
            (r'<img[^>]*on\w+', 'XSS - Image Event'),
            (r'<body[^>]*on\w+', 'XSS - Body Event'),
            (r'document\.cookie', 'XSS - Cookie Stealing'),
            (r'alert\s*\(', 'XSS - Alert'),
            (r'prompt\s*\(', 'XSS - Prompt'),
            (r'confirm\s*\(', 'XSS - Confirm'),
            (r'eval\s*\(', 'XSS - Eval'),
        ]
        
        # Command Injection patterns
        cmd_patterns = [
            (r';[\s]*(ls|dir|id|whoami|cat|type|echo)', 'Command Injection'),
            (r'`[^`]+`', 'Command Injection - Backticks'),
            (r'\$\([^)]+\)', 'Command Injection - Dollar'),
            (r'\|[\s]*(ls|dir|id|whoami)', 'Command Injection - Pipe'),
            (r'&&[\s]*(ls|dir|id|whoami)', 'Command Injection - AND'),
            (r'\|\|[\s]*(ls|dir|id|whoami)', 'Command Injection - OR'),
        ]
        
        # Path Traversal patterns
        path_patterns = [
            (r'\.\./\.\./\.\./', 'Path Traversal - Linux'),
            (r'\.\.\\\.\.\\\.\.\\', 'Path Traversal - Windows'),
            (r'%2e%2e%2f', 'Path Traversal - URL Encoded'),
            (r'\.\.%5c\.\.%5c', 'Path Traversal - Windows URL'),
            (r'/etc/passwd', 'Path Traversal - Passwd File'),
            (r'c:\\windows\\win\.ini', 'Path Traversal - Windows INI'),
        ]
        
        # LFI/RFI patterns
        lfi_patterns = [
            (r'php://filter', 'LFI - PHP Filter'),
            (r'php://input', 'LFI - PHP Input'),
            (r'data://', 'RFI - Data Wrapper'),
            (r'http://', 'RFI - HTTP'),
            (r'https://', 'RFI - HTTPS'),
            (r'ftp://', 'RFI - FTP'),
            (r'file://', 'LFI - File Protocol'),
            (r'expect://', 'RFI - Expect'),
        ]
        
        # Combined patterns with severity levels
        all_patterns = [
            (*p, 'SQLi') for p in sqli_patterns
        ] + [
            (*p, 'XSS') for p in xss_patterns
        ] + [
            (*p, 'CMDi') for p in cmd_patterns
        ] + [
            (*p, 'Path Traversal') for p in path_patterns
        ] + [
            (*p, 'LFI/RFI') for p in lfi_patterns
        ]
        
        # Check each pattern
        for pattern, name, vuln_type in all_patterns:
            matches = re.findall(pattern, decoded_text, re.IGNORECASE)
            if matches:
                # Determine severity
                if 'SQLi' in vuln_type:
                    severity = 'CRITICAL'
                elif 'XSS' in vuln_type:
                    severity = 'HIGH'
                elif 'CMDi' in vuln_type:
                    severity = 'CRITICAL'
                elif 'Path Traversal' in vuln_type:
                    severity = 'HIGH'
                elif 'LFI/RFI' in vuln_type:
                    severity = 'CRITICAL'
                else:
                    severity = 'MEDIUM'
                
                findings.append({
                    'type': vuln_type,
                    'name': name,
                    'pattern': pattern,
                    'match': str(matches[0])[:100],
                    'severity': severity,
                    'confidence': '90%'
                })
        
        return findings
    
    def deep_inspect(self, session_manager, url, data_to_check, verbose=False):
        """
        Main function: Extracts encoded data, decodes it recursively,
        detects vulnerabilities, and returns findings.
        
        Returns:
            list: Findings from decoded data
        """
        self.decoding_history = []
        self.findings = []
        
        if not data_to_check or len(data_to_check) < 3:
            return []
        
        if verbose:
            cprint(f"[*] Deep decoding: Analyzing encoded data...", "blue")
        
        # Recursive decoding
        decoded_data, method, depth = self.try_decode(data_to_check)
        
        if decoded_data and method:
            if verbose:
                cprint(f"[*] Detected {method} encoding (depth {depth})", "cyan")
                cprint(f"[*] Decoded: {decoded_data[:200]}...", "white")
            
            # Detect vulnerabilities
            findings = self.detect_vulnerabilities(decoded_data)
            
            if findings:
                for finding in findings:
                    cprint(f"\n[!] VULNERABILITY DETECTED!", "red", attrs=['bold'])
                    cprint(f"    Type: {finding['type']}", "red")
                    cprint(f"    Name: {finding['name']}", "yellow")
                    cprint(f"    Severity: {finding['severity']}", "red" if finding['severity'] == 'CRITICAL' else "yellow")
                    cprint(f"    Confidence: {finding['confidence']}", "green")
                    cprint(f"    Decoded: {decoded_data[:200]}", "white")
                    
                    self.findings.append(finding)
                
                return findings
            else:
                if verbose:
                    cprint("[i] Decoded data appears clean", "green")
                return []
        
        return []
    
    def reset(self):
        """Reset decoder state"""
        self.decoding_history = []
        self.findings = []


# Legacy function for backward compatibility
def try_decode(data):
    """Legacy function - tries single-layer decoding"""
    decoder = DecoderUtils()
    decoded, method, _ = decoder.try_decode(data)
    if decoded:
        return decoded, method
    return None, None

def deep_inspect_and_clean(session_manager, url, data_to_check, verbose=False):
    """
    Legacy function for backward compatibility
    """
    decoder = DecoderUtils(verbose=verbose)
    findings = decoder.deep_inspect(session_manager, url, data_to_check, verbose)
    return len(findings) > 0


if __name__ == "__main__":
    # Test the decoder
    decoder = DecoderUtils(verbose=True)
    
    test_payloads = [
        '%3Cscript%3Ealert(1)%3C%2Fscript%3E',
        'c2VsZWN0ICogZnJvbSB1c2Vycw==',
        '..%2f..%2f..%2fetc%2fpasswd',
        '%2527%2520OR%25201%253D1%2520--',
        '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e',
        '; id',
    ]
    
    for payload in test_payloads:
        print(f"\n{'='*60}")
        print(f"Testing: {payload}")
        print('='*60)
        decoder.deep_inspect(None, 'test.com', payload, verbose=True)
        decoder.reset()
