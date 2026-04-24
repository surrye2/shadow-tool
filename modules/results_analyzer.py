#!/usr/bin/env python3
"""
Results Analyzer - Extract sensitive data from all scan result files
Advanced version with JSON parsing, Base64 decoding, JWT verification, and severity classification
"""

import re
import os
import json
import base64
from termcolor import cprint
from datetime import datetime

SAVE_FILE = "extracted_data.txt"
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB max

# المجالات التي سيتم تجاهلها
IGNORED_DOMAINS = ['example.com', 'test.com', 'google.com', 'gmail.com', 'yahoo.com', 'outlook.com']

def is_valid_value(value):
    """Filter out false positives"""
    blacklist = {"test", "null", "none", "123456", "password", "admin", "root", "user", "", "example", "demo"}
    if len(value) < 6:
        return False
    if value.lower() in blacklist:
        return False
    # Check entropy (basic)
    unique_chars = len(set(value))
    if unique_chars < 5 and len(value) < 20:
        return False
    return True

def decode_base64_if_needed(value):
    """Decode base64 encoded values"""
    try:
        if re.match(r'^[A-Za-z0-9+/=]{20,}$', value):
            decoded = base64.b64decode(value).decode('utf-8', errors='ignore')
            if len(decoded) > 5 and decoded != value:
                return decoded, True
    except:
        pass
    return value, False

def verify_jwt_structure(token):
    """Verify if token is a real JWT or just random text"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return False
        
        header_b64 = parts[0]
        # Add padding for decoding
        padding = 4 - (len(header_b64) % 4)
        if padding != 4:
            header_b64 += '=' * padding
        
        header_json = base64.urlsafe_b64decode(header_b64).decode('utf-8')
        return '"alg"' in header_json.lower() and '"typ"' in header_json.lower()
    except:
        return False

def extract_from_json(data, current_path=""):
    """Recursively extract sensitive data from JSON"""
    findings = []
    
    if isinstance(data, dict):
        for key, value in data.items():
            new_path = f"{current_path}.{key}" if current_path else key
            findings.extend(extract_from_json(value, new_path))
    elif isinstance(data, list):
        for i, item in enumerate(data):
            new_path = f"{current_path}[{i}]"
            findings.extend(extract_from_json(item, new_path))
    elif isinstance(data, str):
        # Check if the string looks like a token
        if len(data) > 8 and is_valid_value(data):
            # Check for JWT first
            if verify_jwt_structure(data):
                findings.append(('JWT_TOKEN', data[:50] + '...', current_path, 98))
            elif re.match(r'^[A-Za-z0-9+/=]{32,}$', data):
                decoded, is_b64 = decode_base64_if_needed(data)
                if is_b64:
                    findings.append(('BASE64_DATA', decoded[:50] + '...', current_path, 70))
                else:
                    findings.append(('TOKEN', data[:50] + '...', current_path, 60))
            elif re.match(r'^[A-Fa-f0-9]{32,}$', data):
                findings.append(('HEX_TOKEN', data[:50] + '...', current_path, 75))
            elif any(keyword in current_path.lower() for keyword in ['password', 'secret', 'key', 'token']):
                findings.append(('SENSITIVE_VALUE', data[:50] + '...', current_path, 85))
    
    return findings

def extract_data(text, filename=""):
    """Extract emails, passwords, tokens from text with enhanced detection"""
    
    findings = []
    
    # Try to parse as JSON
    try:
        if filename.endswith('.json') or (text.strip().startswith('{') and text.strip().endswith('}')):
            json_data = json.loads(text)
            findings = extract_from_json(json_data)
    except:
        pass
    
    # Extract emails with domain filtering
    emails = set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text))
    # Filter out ignored domains
    emails = {e for e in emails if not any(dom in e for dom in IGNORED_DOMAINS)}
    # Filter out image extensions
    emails = {e for e in emails if not e.endswith('.png') and not e.endswith('.jpg') and not e.endswith('.gif')}
    
    # Extract passwords, tokens, keys (enhanced patterns)
    password_patterns = re.findall(
        r'(?i)(password|pass|pwd|token|key|apikey|api_key|apiToken|apiKey|secret|access_token)[\'"]?\s*[:=]\s*[\'"]([^\'"\s]{6,})[\'"]',
        text
    )
    passwords = []
    for k, v in password_patterns:
        if is_valid_value(v):
            # Check if it's a JWT
            if verify_jwt_structure(v):
                passwords.append(('JWT_TOKEN (verified)', v[:50] + '...', 98))
            else:
                passwords.append((k.upper(), v[:50] + '...', 70))
    
    # Extract JWT tokens with verification
    jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
    jwt_tokens = set(re.findall(jwt_pattern, text))
    for token in jwt_tokens:
        if verify_jwt_structure(token):
            passwords.append(('JWT_TOKEN (verified)', token[:50] + '...', 98))
        else:
            passwords.append(('JWT_TOKEN (suspicious)', token[:50] + '...', 60))
    
    # Extract API keys with validation
    api_patterns = [
        (r'AKIA[0-9A-Z]{16}', 'AWS_KEY', 95),
        (r'AIza[0-9A-Za-z\-_]{35}', 'GOOGLE_API', 95),
        (r'gh[ops]_[0-9a-zA-Z]{36}', 'GITHUB_TOKEN', 95),
        (r'sk_live_[0-9a-zA-Z]{24}', 'STRIPE_KEY', 98),
        (r'sk_test_[0-9a-zA-Z]{24}', 'STRIPE_TEST_KEY', 90),
        (r'xox[baprs]-[0-9a-zA-Z]{10,}', 'SLACK_TOKEN', 95),
        (r'RGAPI-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', 'RIOT_API', 90),
    ]
    
    for pattern, name, confidence in api_patterns:
        matches = re.findall(pattern, text)
        for match in matches:
            passwords.append((name, match, confidence))
    
    # Search for other keywords
    keywords = ["username", "email", "password", "token", "key", "auth", "credentials", 
                "session", "api_key", "apikey", "apiToken", "apiKey", "secret", "bearer"]
    found = {}
    
    for word in keywords:
        pattern = re.compile(rf'{word}[\'"]?\s*[:=]\s*[\'"]([^\'"\s]{{6,}})[\'"]', re.IGNORECASE)
        matches = pattern.findall(text)
        for match in matches:
            if is_valid_value(match):
                if word not in found:
                    found[word] = []
                # Check if it's a JWT
                if verify_jwt_structure(match):
                    found[word].append(('JWT_TOKEN (verified)', match[:50] + '...', 98))
                else:
                    found[word].append((match[:50] + '...', 70))
    
    return emails, passwords, found, jwt_tokens, findings

def find_all_result_files():
    """Search for all result files in all directories"""
    result_files = []
    
    # Directories to search
    search_dirs = [
        ".",                    # Current directory
        "scan_results",         # Scan results directory
        "modules",              # Modules directory
        "new_core",             # New core directory
        "logs",                 # Logs directory
        "reports",              # Reports directory
        "../scan_results",      # Parent directory
    ]
    
    # File extensions to look for
    extensions = ['.json', '.txt', '.log', '.csv', '.xml', '.html']
    
    # Keywords in filenames to look for
    keywords = ['scan', 'result', 'analysis', 'report', 'jwt', 'cookie', 'header', 'security']
    
    for search_dir in search_dirs:
        if not os.path.exists(search_dir):
            continue
        
        for root, dirs, files in os.walk(search_dir):
            for file in files:
                # Skip large files
                file_path = os.path.join(root, file)
                try:
                    if os.path.getsize(file_path) > MAX_FILE_SIZE:
                        continue
                except:
                    pass
                
                # Check by extension
                if any(file.endswith(ext) for ext in extensions):
                    result_files.append(file_path)
                    continue
                
                # Check by keyword in filename
                if any(keyword in file.lower() for keyword in keywords):
                    if file.endswith('.json') or file.endswith('.txt'):
                        result_files.append(file_path)
    
    # Remove duplicates
    result_files = list(set(result_files))
    
    # Sort by modification time (newest first)
    result_files.sort(key=lambda x: os.path.getmtime(x) if os.path.exists(x) else 0, reverse=True)
    
    return result_files

def print_results(text, save_to_file=False, verbose=False, filename=""):
    """Display and save extracted results"""
    emails, passwords, found, jwt_tokens, json_findings = extract_data(text, filename)
    
    lines = []
    
    # Add filename header
    lines.append(f"\n{'='*60}")
    lines.append(f"File: {filename}")
    lines.append(f"{'='*60}")
    
    # Emails
    lines.append("\n[+] Emails Found:")
    if emails:
        for email in list(emails)[:20]:
            lines.append(f" - {email}")
            if verbose:
                cprint(f" - {email}", "green")
        if len(emails) > 20:
            lines.append(f" ... and {len(emails) - 20} more")
            if verbose:
                cprint(f" ... and {len(emails) - 20} more", "yellow")
    else:
        lines.append(" No emails found.")
        if verbose:
            cprint(" No emails found.", "yellow")
    
    # Passwords/Tokens with confidence
    lines.append("\n[+] Passwords/Tokens/API Keys Found:")
    if passwords:
        for item in passwords[:20]:
            if len(item) == 3:
                name, val, confidence = item
                lines.append(f" - {name}: {val} (confidence: {confidence}%)")
                if verbose:
                    cprint(f" - {name}: {val} (confidence: {confidence}%)", "red")
            else:
                name, val = item
                lines.append(f" - {name}: {val}")
                if verbose:
                    cprint(f" - {name}: {val}", "red")
        if len(passwords) > 20:
            lines.append(f" ... and {len(passwords) - 20} more")
    else:
        lines.append(" No passwords, tokens or API keys found.")
        if verbose:
            cprint(" No passwords, tokens or API keys found.", "yellow")
    
    # JSON findings
    if json_findings:
        lines.append("\n[+] JSON Sensitive Data Found:")
        for name, val, path, confidence in json_findings[:10]:
            lines.append(f" - {name}: {val} (path: {path}, confidence: {confidence}%)")
            if verbose:
                cprint(f" - {name}: {val} (path: {path})", "magenta")
        if len(json_findings) > 10:
            lines.append(f" ... and {len(json_findings) - 10} more")
    
    # Other keywords
    lines.append("\n[+] Other Sensitive Keywords Found:")
    if found:
        for key, vals in list(found.items())[:10]:
            lines.append(f" - {key}:")
            for val in vals[:5]:
                if len(val) == 3:
                    name, v, conf = val
                    lines.append(f"    * {name}: {v} (confidence: {conf}%)")
                    if verbose:
                        cprint(f"    * {name}: {v}", "magenta")
                else:
                    v, conf = val
                    lines.append(f"    * {v} (confidence: {conf}%)")
                    if verbose:
                        cprint(f"    * {v}", "magenta")
            if len(vals) > 5:
                lines.append(f"    ... and {len(vals) - 5} more")
    else:
        lines.append(" No other sensitive keywords found.")
        if verbose:
            cprint(" No other sensitive keywords found.", "yellow")
    
    if save_to_file:
        with open(SAVE_FILE, "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

def scan(url, verbose=False):
    """Main scan function - reads all result files"""
    
    # Find all result files
    result_files = find_all_result_files()
    
    # Remove old extracted file
    if os.path.exists(SAVE_FILE):
        os.remove(SAVE_FILE)
    
    if not result_files:
        cprint("[!] No result files found in any directory.", "red")
        cprint("[*] Run a scan first to generate result files.", "yellow")
        return
    
    cprint(f"\n[*] Found {len(result_files)} result files to analyze", "blue")
    
    if verbose:
        cprint(f"[*] Files to analyze:", "cyan")
        for f in result_files[:10]:
            cprint(f"    - {f}", "cyan")
        if len(result_files) > 10:
            cprint(f"    ... and {len(result_files) - 10} more", "cyan")
    
    analyzed_count = 0
    for file in result_files:
        try:
            with open(file, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                print_results(content, save_to_file=True, verbose=verbose, filename=file)
                analyzed_count += 1
                if verbose:
                    cprint(f"[~] Analyzed: {os.path.basename(file)}", "blue")
        except Exception as e:
            if verbose:
                cprint(f"[!] Failed to read {file}: {e}", "red")
    
    cprint(f"\n[✓] Analysis completed: {analyzed_count} files processed", "green")
    cprint(f"[✓] Extracted data saved to: {SAVE_FILE}", "cyan")
    
    # Show summary
    if os.path.exists(SAVE_FILE):
        with open(SAVE_FILE, "r", encoding="utf-8") as f:
            content = f.read()
            email_count = content.count("@")
            token_count = content.count("JWT_TOKEN") + content.count("API")
            cprint(f"\n[ Summary: {email_count} emails, {token_count} tokens found", "yellow")

def scan_results(url, verbose=False):
    """Alias for scan()"""
    scan(url, verbose)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        scan(sys.argv[1], verbose=True)
    else:
        print("Usage: python results_analyzer.py <url>")
