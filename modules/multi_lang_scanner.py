#!/usr/bin/env python3
# modules/multi_lang_scanner.py - النسخة الكاملة مع مخرجات مختصرة

import re
import requests
import json
from termcolor import cprint
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

class MultiLanguageScanner:
    def __init__(self, timeout=10, verbose=False):
        self.timeout = timeout
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'Mozilla/5.0'})
        self.findings = []
        
        # ========== الأنماط الكاملة (مثل الكود الأصلي) ==========
        self.vuln_patterns = {
            'PHP': {
                'Critical': [
                    (r'eval\s*\(\s*\$_(GET|POST|REQUEST)\[', 'Remote Code Execution via eval()'),
                    (r'system\s*\(\s*\$_(GET|POST|REQUEST)\[', 'OS Command Injection via system()'),
                    (r'exec\s*\(\s*\$_(GET|POST|REQUEST)\[', 'OS Command Injection via exec()'),
                    (r'passthru\s*\(\s*\$_(GET|POST|REQUEST)\[', 'OS Command Injection via passthru()'),
                    (r'shell_exec\s*\(\s*\$_(GET|POST|REQUEST)\[', 'OS Command Injection via shell_exec()'),
                    (r'popen\s*\(\s*\$_(GET|POST|REQUEST)\[', 'OS Command Injection via popen()'),
                    (r'\$\$', 'Variable Variable (Potential RCE)'),
                    (r'create_function\s*\(\s*[\'"][^\'"]*[\'"]\s*,\s*\$_(GET|POST|REQUEST)', 'Dynamic Function Creation')
                ],
                'High': [
                    (r'include\s*\(\s*\$_(GET|POST|REQUEST)', 'Remote File Inclusion (RFI)'),
                    (r'require\s*\(\s*\$_(GET|POST|REQUEST)', 'Remote File Inclusion (RFI)'),
                    (r'file_get_contents\s*\(\s*\$_(GET|POST|REQUEST)', 'Local File Inclusion (LFI)'),
                    (r'fopen\s*\(\s*\$_(GET|POST|REQUEST)', 'Arbitrary File Access'),
                    (r'curl_exec\s*\(\s*\$[a-z_]+\)', 'SSRF via cURL'),
                    (r'new\s+SimpleXMLElement\s*\(\s*\$_(GET|POST|REQUEST)', 'XXE Injection')
                ],
                'Medium': [
                    (r'mysql_query\s*\(\s*\$_(GET|POST|REQUEST)', 'SQL Injection'),
                    (r'mysqli_query\s*\(\s*\$_(GET|POST|REQUEST)', 'SQL Injection'),
                    (r'pg_query\s*\(\s*\$_(GET|POST|REQUEST)', 'SQL Injection'),
                    (r'unserialize\s*\(\s*\$_(GET|POST|REQUEST)', 'Insecure Deserialization')
                ]
            },
            'JavaScript': {
                'Critical': [
                    (r'eval\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)', 'Dynamic Code Execution via eval()'),
                    (r'document\.write\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)', 'DOM-based XSS'),
                    (r'innerHTML\s*=\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'DOM-based XSS'),
                    (r'new\s+Function\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)', 'Dynamic Function Creation')
                ],
                'High': [
                    (r'setTimeout\s*\(\s*[\'"].*?[\'"]\s*,', 'Code Execution via setTimeout'),
                    (r'setInterval\s*\(\s*[\'"].*?[\'"]\s*,', 'Code Execution via setInterval'),
                    (r'fetch\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'Potential SSRF'),
                    (r'WebSocket\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'Insecure WebSocket')
                ],
                'Medium': [
                    (r'localStorage\.setItem\s*\(\s*[\'"].*?[\'"]\s*,\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'Sensitive Data in LocalStorage'),
                    (r'sessionStorage\.setItem\s*\(\s*[\'"].*?[\'"]\s*,\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'Sensitive Data in SessionStorage')
                ]
            },
            'Java': {
                'Critical': [
                    (r'Runtime\.getRuntime\(\)\.exec\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'Command Injection'),
                    (r'ProcessBuilder\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'Command Injection'),
                    (r'Class\.forName\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'Dynamic Class Loading (RCE)')
                ],
                'High': [
                    (r'ObjectInputStream\s*\(', 'Insecure Deserialization'),
                    (r'readObject\s*\(\)', 'Insecure Deserialization'),
                    (r'DriverManager\.getConnection\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'SQL Injection'),
                    (r'Statement\.executeQuery\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'SQL Injection')
                ]
            },
            'Python': {
                'Critical': [
                    (r'eval\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'Remote Code Execution'),
                    (r'exec\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'Remote Code Execution'),
                    (r'__import__\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'Dynamic Import (RCE)'),
                    (r'os\.system\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'Command Injection'),
                    (r'subprocess\.(call|Popen|run)\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'Command Injection')
                ],
                'High': [
                    (r'pickle\.loads\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'Insecure Deserialization'),
                    (r'yaml\.load\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'YAML Deserialization (RCE)'),
                    (r'xml\.etree\.ElementTree\.parse\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'XXE Injection')
                ]
            },
            'Bash': {
                'Critical': [
                    (r'`\s*\$[a-zA-Z_$][a-zA-Z0-9_$]*\s*`', 'Command Substitution Injection'),
                    (r'\$\(\s*\$[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)', 'Command Substitution Injection'),
                    (r'eval\s+[\'"]?\$[a-zA-Z_$][a-zA-Z0-9_$]*', 'Code Injection via eval')
                ],
                'High': [
                    (r'curl\s+\$[a-zA-Z_$][a-zA-Z0-9_$]*', 'SSRF via curl'),
                    (r'wget\s+\$[a-zA-Z_$][a-zA-Z0-9_$]*', 'SSRF via wget')
                ]
            },
            'Ruby': {
                'Critical': [
                    (r'eval\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'Remote Code Execution'),
                    (r'system\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'Command Injection'),
                    (r'exec\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'Command Injection'),
                    (r'`\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*`', 'Command Injection')
                ],
                'High': [
                    (r'YAML\.load\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'YAML Deserialization (RCE)'),
                    (r'Marshal\.load\s*\(\s*[a-zA-Z_$][a-zA-Z0-9_$]*', 'Insecure Deserialization')
                ]
            }
        }
        
        self.safe_patterns = [r'\.min\.js$', r'\.bundle\.js$', r'jquery', r'bootstrap', r'vue', r'react', r'angular']

    # ========== باقي الدوال (نفس الأصل ولكن مع إخفاء المخرجات) ==========
    def scan(self, url, verbose=False):
        self.verbose = verbose
        cprint("\n" + "="*70, "cyan")
        cprint("🌐 MULTI-LANGUAGE SCANNER", "cyan")
        cprint("="*70, "cyan")

        results = {'vulnerable': False, 'findings': [], 'summary': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0}, 'files_scanned': []}
        
        try:
            if self.verbose:
                cprint("[*] Scanning main page...", "blue")
            r = self.session.get(url, timeout=self.timeout)
            main_findings = self._analyze_code(r.text, 'HTML', url)
            results['findings'].extend(main_findings)
            results['files_scanned'].append({'url': url, 'type': 'HTML'})

            js_files = self._extract_js_files(r.text, url)
            if js_files and self.verbose:
                cprint(f"[*] Scanning {len(js_files)} JS files...", "blue")
            with ThreadPoolExecutor(max_workers=5) as ex:
                futures = {ex.submit(self._scan_js_file, js_url): js_url for js_url in js_files[:30]}
                for f in as_completed(futures):
                    findings = f.result()
                    if findings:
                        results['findings'].extend(findings)
                        results['files_scanned'].append({'url': futures[f], 'type': 'JavaScript'})

            php_files = self._discover_php_files(url)
            if php_files and self.verbose:
                cprint(f"[*] Checking {len(php_files)} PHP files...", "blue")
            for php_url in php_files[:20]:
                findings = self._scan_php_file(php_url)
                if findings:
                    results['findings'].extend(findings)
                    results['files_scanned'].append({'url': php_url, 'type': 'PHP'})

            for f in results['findings']:
                sev = f['severity'].lower()
                results['summary']['total'] += 1
                if sev == 'critical':
                    results['summary']['critical'] += 1
                elif sev == 'high':
                    results['summary']['high'] += 1
                elif sev == 'medium':
                    results['summary']['medium'] += 1

            results['vulnerable'] = results['summary']['total'] > 0
            self._display_results(results)
            self._save_report(results)
            return results
        except Exception as e:
            cprint(f"[!] Scanner error: {e}", "red")
            return results

    def _extract_js_files(self, html, base_url):
        js_files = set()
        patterns = [r'<script[^>]+src=["\']([^"\']+\.js)["\']', r'import\(["\']([^"\']+\.js)["\']\)']
        for p in patterns:
            for m in re.findall(p, html, re.IGNORECASE):
                js_files.add(urljoin(base_url, m))
        for common in ['/app.js', '/main.js', '/bundle.js']:
            js_files.add(urljoin(base_url, common))
        return list(js_files)

    def _scan_js_file(self, url):
        try:
            r = self.session.get(url, timeout=self.timeout)
            if len(r.text) > 5_000_000:
                return []
            for safe in self.safe_patterns:
                if re.search(safe, url, re.IGNORECASE):
                    return []
            return self._analyze_code(r.text, 'JavaScript', url)
        except:
            return []

    def _discover_php_files(self, base_url):
        common = ['index.php', 'config.php', 'db.php', 'functions.php', 'login.php', 'admin.php', 'api.php']
        return [urljoin(base_url, f) for f in common]

    def _scan_php_file(self, url):
        try:
            r = self.session.get(url, timeout=self.timeout)
            if r.status_code == 200:
                return self._analyze_code(r.text, 'PHP', url)
        except:
            pass
        return []

    def _analyze_code(self, code, language, source_url):
        findings = []
        cleaned = self._remove_comments(code, language)
        for lang, sev_dict in self.vuln_patterns.items():
            if lang != language and language not in ['HTML', 'Unknown']:
                continue
            for severity, patterns in sev_dict.items():
                for pattern, desc in patterns:
                    if re.search(pattern, cleaned, re.IGNORECASE):
                        findings.append({
                            'language': lang,
                            'severity': severity.upper(),
                            'type': desc,
                            'source': source_url,
                            'confidence': '95%'
                        })
        return findings

    def _remove_comments(self, code, lang):
        if lang in ['JavaScript', 'Java', 'PHP']:
            code = re.sub(r'//.*?$', '', code, flags=re.MULTILINE)
            code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
        elif lang == 'Python':
            code = re.sub(r'#.*?$', '', code, flags=re.MULTILINE)
        return code

    def _display_results(self, results):
        if not results['vulnerable']:
            cprint("\n[✓] No security issues detected", "green")
            return

        cprint("\n" + "="*70, "red")
        cprint("⚠️  SECURITY ISSUES DETECTED", "red")
        cprint("="*70, "red")

        s = results['summary']
        cprint(f"📊 CRITICAL: {s['critical']} | HIGH: {s['high']} | MEDIUM: {s['medium']} | TOTAL: {s['total']}", "yellow")

        for finding in results['findings'][:12]:
            sev = finding['severity']
            color = "red" if sev == "CRITICAL" else "light_red" if sev == "HIGH" else "yellow"
            cprint(f"\n📍 [{sev}] {finding['type']}", color)
            cprint(f"   Language: {finding['language']} | Source: {finding['source'].split('/')[-1]}", "white")
            cprint(f"   Confidence: {finding['confidence']}", "green")

        if len(results['findings']) > 12:
            cprint(f"\n... and {len(results['findings'])-12} more", "yellow")
        cprint("\n" + "="*70 + "\n", "red")

    def _save_report(self, results):
        filename = f"multilang_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        cprint(f"[✓] Report saved: {filename}", "green")

def scan(url, verbose=False):
    scanner = MultiLanguageScanner(verbose=verbose)
    return scanner.scan(url, verbose)

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        scan(sys.argv[1], verbose=True)
    else:
        print("Usage: python multi_lang_scanner.py <url>")