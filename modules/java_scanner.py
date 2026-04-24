#!/usr/bin/env python3
# modules/java_scanner.py - AlZill V6 Pro
# Java Security Scanner with advanced pattern matching, comment detection, dependency analysis

import os
import re
import json
import subprocess
import tempfile
from termcolor import cprint
from pathlib import Path
from typing import List, Dict, Optional, Tuple

# ============================================================
# CONFIGURATION
# ============================================================
INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class JavaSecurityScanner:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.vulnerabilities = []
        self.critical_count = 0
        self.high_count = 0
        self.medium_count = 0
        self.low_count = 0
        
        # ============================================================
        # ADVANCED VULNERABILITY PATTERNS (مع تجنب التعليقات)
        # ============================================================
        self.vuln_patterns = {
            # Command Injection (Critical)
            r'Runtime\.getRuntime\(\)\.exec\s*\([^;]*\+': {
                'severity': 'CRITICAL',
                'type': 'Command Injection',
                'cwe': 'CWE-78',
                'description': 'OS command injection via concatenation',
                'fix': 'Use ProcessBuilder with sanitized input'
            },
            r'ProcessBuilder\s*\(\s*[^)]*\+': {
                'severity': 'CRITICAL',
                'type': 'Command Injection',
                'cwe': 'CWE-78',
                'description': 'Command injection in ProcessBuilder',
                'fix': 'Use array arguments instead of string concatenation'
            },
            r'\.exec\s*\(\s*request\.getParameter': {
                'severity': 'CRITICAL',
                'type': 'Command Injection',
                'cwe': 'CWE-78',
                'description': 'Direct user input in exec()',
                'fix': 'Validate and sanitize all user inputs'
            },
            
            # SQL Injection (Critical)
            r'Statement\s+.*?=.*?createStatement\s*\(\s*\)': {
                'severity': 'CRITICAL',
                'type': 'SQL Injection',
                'cwe': 'CWE-89',
                'description': 'Statement object (should use PreparedStatement)',
                'fix': 'Replace Statement with PreparedStatement'
            },
            r'["\']SELECT.*?\+.*?["\']': {
                'severity': 'CRITICAL',
                'type': 'SQL Injection',
                'cwe': 'CWE-89',
                'description': 'String concatenation in SQL query',
                'fix': 'Use parameterized queries (PreparedStatement)'
            },
            r'executeQuery\s*\(\s*["\'][^"\']*\+': {
                'severity': 'CRITICAL',
                'type': 'SQL Injection',
                'cwe': 'CWE-89',
                'description': 'Dynamic SQL query construction',
                'fix': 'Use PreparedStatement with ? placeholders'
            },
            
            # XXE (XML External Entity) - High
            r'DocumentBuilderFactory\s*\(\)': {
                'severity': 'HIGH',
                'type': 'XXE Injection',
                'cwe': 'CWE-611',
                'description': 'XXE vulnerability in XML parser',
                'fix': 'Set setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)'
            },
            r'SAXParserFactory\s*\(\)': {
                'severity': 'HIGH',
                'type': 'XXE Injection',
                'cwe': 'CWE-611',
                'description': 'XXE vulnerability in SAX parser',
                'fix': 'Disable external entities'
            },
            
            # Deserialization (Critical)
            r'ObjectInputStream\s*\(.*?request': {
                'severity': 'CRITICAL',
                'type': 'Insecure Deserialization',
                'cwe': 'CWE-502',
                'description': 'Deserialization of untrusted data',
                'fix': 'Use whitelist filtering or avoid deserialization'
            },
            r'readObject\s*\(\s*\)': {
                'severity': 'HIGH',
                'type': 'Insecure Deserialization',
                'cwe': 'CWE-502',
                'description': 'Unsafe deserialization',
                'fix': 'Validate input or use JSON instead'
            },
            
            # Path Traversal (High)
            r'new\s+File\s*\(\s*request\.getParameter': {
                'severity': 'HIGH',
                'type': 'Path Traversal',
                'cwe': 'CWE-22',
                'description': 'User-controlled file path',
                'fix': 'Sanitize input and use whitelist'
            },
            r'\\.\\./.*?request\.getParameter': {
                'severity': 'HIGH',
                'type': 'Path Traversal',
                'cwe': 'CWE-22',
                'description': 'Directory traversal pattern',
                'fix': 'Normalize path and check boundaries'
            },
            
            # XSS (Medium-High)
            r'response\.getWriter\(\)\.print\s*\(\s*request\.getParameter': {
                'severity': 'HIGH',
                'type': 'Reflected XSS',
                'cwe': 'CWE-79',
                'description': 'Unescaped user input in response',
                'fix': 'Use escapeHtml() or Content-Security-Policy'
            },
            r'out\.println\s*\(\s*request\.getParameter': {
                'severity': 'HIGH',
                'type': 'Reflected XSS',
                'cwe': 'CWE-79',
                'description': 'Direct output of user input',
                'fix': 'Sanitize with OWASP Java Encoder'
            },
            
            # LDAP Injection (High)
            r'DirContext\.search\s*\(\s*["\'][^"\']*\+': {
                'severity': 'HIGH',
                'type': 'LDAP Injection',
                'cwe': 'CWE-90',
                'description': 'LDAP query concatenation',
                'fix': 'Use whitelist and escape special characters'
            },
            
            # Hardcoded Credentials (Medium-High)
            r'String\s+password\s*=\s*["\'][^"\']*["\']': {
                'severity': 'MEDIUM',
                'type': 'Hardcoded Password',
                'cwe': 'CWE-259',
                'description': 'Password hardcoded in source code',
                'fix': 'Use environment variables or secrets manager'
            },
            r'api[_-]?key\s*=\s*["\'][a-zA-Z0-9]{16,}': {
                'severity': 'MEDIUM',
                'type': 'Hardcoded API Key',
                'cwe': 'CWE-798',
                'description': 'API key exposed in code',
                'fix': 'Store in environment variables'
            },
            
            # Insecure Cryptography (High)
            r'MD5\s*\(\s*[^)]*\)': {
                'severity': 'HIGH',
                'type': 'Weak Hash Algorithm',
                'cwe': 'CWE-327',
                'description': 'MD5 is cryptographically broken',
                'fix': 'Use SHA-256 or bcrypt'
            },
            r'SHA-?\d{1}\s*\(\s*[^)]*\)': {
                'severity': 'MEDIUM',
                'type': 'Weak Hash Algorithm',
                'cwe': 'CWE-327',
                'description': 'SHA-1 is deprecated for security',
                'fix': 'Use SHA-256 or stronger'
            },
            r'Cipher\.getInstance\s*\(\s*["\']DES': {
                'severity': 'HIGH',
                'type': 'Weak Encryption',
                'cwe': 'CWE-326',
                'description': 'DES encryption is insecure',
                'fix': 'Use AES-256 instead'
            },
            
            # Log Forging (Medium)
            r'log\.(info|debug|warn)\s*\(\s*request\.getParameter': {
                'severity': 'MEDIUM',
                'type': 'Log Forging',
                'cwe': 'CWE-117',
                'description': 'User input in log messages',
                'fix': 'Sanitize newline characters'
            },
            
            # Information Disclosure (Low-Medium)
            r'printStackTrace\s*\(\s*\)': {
                'severity': 'MEDIUM',
                'type': 'Information Disclosure',
                'cwe': 'CWE-209',
                'description': 'Stack trace exposed to user',
                'fix': 'Log errors internally, show generic message'
            },
            r'e\.printStackTrace\s*\(\s*\)': {
                'severity': 'MEDIUM',
                'type': 'Information Disclosure',
                'cwe': 'CWE-209',
                'description': 'Exception stack trace exposure',
                'fix': 'Remove or log to secure file'
            },
            
            # Race Conditions (Medium)
            r'synchronized\s*\(\s*this\s*\)': {
                'severity': 'MEDIUM',
                'type': 'Race Condition Risk',
                'cwe': 'CWE-362',
                'description': 'Monitor lock on this object',
                'fix': 'Use dedicated lock objects'
            }
        }
        
        # ============================================================
        # DANGEROUS APIS
        # ============================================================
        self.dangerous_apis = {
            'java.lang.Runtime': 'Command execution possible',
            'java.lang.ProcessBuilder': 'Process spawning',
            'java.sql.Statement': 'SQL injection risk',
            'javax.crypto.Cipher': 'Encryption implementation',
            'java.io.ObjectInputStream': 'Deserialization risk',
            'java.net.URL': 'SSRF potential',
            'javax.naming.directory.DirContext': 'LDAP injection risk'
        }
        
        # ============================================================
        # VULNERABLE DEPENDENCIES (مع Fastjson و Struts2)
        # ============================================================
        self.vulnerable_dependencies = {
            # Log4j (Log4Shell)
            'log4j-core': {
                'versions': ['2.0', '2.1', '2.2', '2.3', '2.4', '2.5', '2.6', '2.7', '2.8', '2.9', '2.10', '2.11', '2.12', '2.13', '2.14', '2.15', '2.16'],
                'cve': 'CVE-2021-44228',
                'severity': 'CRITICAL',
                'description': 'Log4Shell - Remote Code Execution',
                'fix': 'Upgrade to log4j-core 2.17.0 or higher'
            },
            # Fastjson (JSON deserialization RCE)
            'fastjson': {
                'versions': ['1.2.24', '1.2.25', '1.2.41', '1.2.42', '1.2.43', '1.2.45', '1.2.47', '1.2.48', '1.2.49', '1.2.54', '1.2.56', '1.2.58', '1.2.59', '1.2.60', '1.2.61', '1.2.62', '1.2.66', '1.2.67', '1.2.68', '1.2.69', '1.2.70', '1.2.71', '1.2.72', '1.2.73', '1.2.74', '1.2.75', '1.2.76', '1.2.77', '1.2.78', '1.2.79', '1.2.80'],
                'cve': 'CVE-2022-25845, CVE-2022-25846, CVE-2023-35116',
                'severity': 'CRITICAL',
                'description': 'Fastjson deserialization RCE',
                'fix': 'Upgrade to fastjson 1.2.83 or higher, or migrate to Jackson'
            },
            # Struts2 (RCE)
            'struts2-core': {
                'versions': ['2.0', '2.1', '2.2', '2.3', '2.5', '6.0'],
                'cve': 'CVE-2017-5638, CVE-2018-11776, CVE-2021-31805',
                'severity': 'CRITICAL',
                'description': 'Struts2 RCE vulnerabilities',
                'fix': 'Upgrade to Struts2 2.5.30 or 6.1.2 or higher'
            },
            # Spring Framework
            'spring-core': {
                'versions': ['5.3.0', '5.3.1', '5.3.2', '5.3.3', '5.3.4', '5.3.5', '5.3.6', '5.3.7', '5.3.8', '5.3.9', '5.3.10', '5.3.11', '5.3.12', '5.3.13', '5.3.14', '5.3.15', '5.3.16', '5.3.17', '5.3.18', '5.3.19', '5.3.20'],
                'cve': 'CVE-2022-22965 (Spring4Shell)',
                'severity': 'CRITICAL',
                'description': 'Spring4Shell RCE',
                'fix': 'Upgrade to Spring Framework 5.3.21 or higher'
            },
            # Jackson Databind
            'jackson-databind': {
                'versions': ['2.9.0', '2.9.1', '2.9.2', '2.9.3', '2.9.4', '2.9.5', '2.9.6', '2.9.7', '2.9.8', '2.9.9', '2.9.10', '2.10.0', '2.10.1', '2.10.2', '2.10.3', '2.10.4', '2.10.5', '2.11.0', '2.11.1', '2.11.2', '2.11.3', '2.11.4', '2.12.0', '2.12.1', '2.12.2', '2.12.3', '2.12.4', '2.12.5', '2.12.6', '2.13.0', '2.13.1', '2.13.2'],
                'cve': 'Multiple CVEs',
                'severity': 'HIGH',
                'description': 'Jackson deserialization vulnerabilities',
                'fix': 'Upgrade to latest version (2.13.4 or higher)'
            }
        }

    # ============================================================
    # COMMENT DETECTION FUNCTIONS
    # ============================================================
    
    def is_in_comment(self, line: str, is_multiline_comment: bool) -> Tuple[bool, bool]:
        """
        التحقق مما إذا كان السطر داخل تعليق
        يعيد (is_comment, new_multiline_state)
        """
        # التعليقات أحادية السطر
        if '//' in line and not is_multiline_comment:
            # التحقق من أن // ليس داخل سلسلة نصية
            if not self._is_in_string(line, '//'):
                return True, False
        
        # التعليقات متعددة الأسطر
        if '/*' in line and not is_multiline_comment:
            if not self._is_in_string(line, '/*'):
                is_multiline_comment = True
        
        if '*/' in line and is_multiline_comment:
            if not self._is_in_string(line, '*/'):
                is_multiline_comment = False
        
        return is_multiline_comment, is_multiline_comment
    
    def _is_in_string(self, line: str, substring: str) -> bool:
        """
        التحقق مما إذا كان النص المطلوب داخل سلسلة نصية (String literal)
        """
        # بسيط: التحقق من وجود علامات اقتباس غير مغلقة قبل النص
        quote_count = 0
        in_double_quote = False
        in_single_quote = False
        
        idx = line.find(substring)
        if idx == -1:
            return False
        
        for i, char in enumerate(line[:idx]):
            if char == '"' and not in_single_quote:
                in_double_quote = not in_double_quote
            elif char == "'" and not in_double_quote:
                in_single_quote = not in_single_quote
        
        return in_double_quote or in_single_quote
    
    def is_line_commented(self, line: str) -> bool:
        """التحقق مما إذا كان السطر كله تعليق"""
        stripped = line.strip()
        return stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*')
    
    # ============================================================
    # MAIN SCANNING FUNCTIONS
    # ============================================================
    
    def scan_java_file(self, filepath: str) -> List[Dict]:
        """مسح ملف Java واحد مع تجنب التعليقات"""
        results = []
        is_multiline_comment = False
        
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for line_num, line in enumerate(lines, 1):
                # تحديث حالة التعليق متعدد الأسطر
                is_comment, is_multiline_comment = self.is_in_comment(line, is_multiline_comment)
                
                # تخطي التعليقات
                if is_comment or self.is_line_commented(line):
                    continue
                
                # فحص الأنماط الضارة
                for pattern, info in self.vuln_patterns.items():
                    if re.search(pattern, line, re.IGNORECASE):
                        results.append({
                            'file': filepath,
                            'line': line_num,
                            'code': line.strip(),
                            'severity': info['severity'],
                            'type': info['type'],
                            'cwe': info['cwe'],
                            'description': info['description'],
                            'fix': info['fix']
                        })
                        
                        # تحديث الإحصائيات
                        if info['severity'] == 'CRITICAL':
                            self.critical_count += 1
                        elif info['severity'] == 'HIGH':
                            self.high_count += 1
                        elif info['severity'] == 'MEDIUM':
                            self.medium_count += 1
                        else:
                            self.low_count += 1
            
            # فحص الاستيرادات الخطرة
            is_multiline_comment = False
            for line_num, line in enumerate(lines, 1):
                is_comment, is_multiline_comment = self.is_in_comment(line, is_multiline_comment)
                
                if is_comment or self.is_line_commented(line):
                    continue
                
                for api, reason in self.dangerous_apis.items():
                    if f'import {api}' in line:
                        results.append({
                            'file': filepath,
                            'line': line_num,
                            'code': line.strip(),
                            'severity': 'INFO',
                            'type': 'Dangerous Import',
                            'cwe': 'N/A',
                            'description': f'Potentially dangerous API: {api}',
                            'fix': f'Review usage of {api}: {reason}'
                        })
        
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Error scanning {filepath}: {e}", ERROR)
        
        return results
    
    def scan_directory(self, directory: str, recursive: bool = True) -> List[Dict]:
        """مسح مجلد كامل من ملفات Java"""
        cprint("\n" + "="*70, INFO)
        cprint("JAVA SECURITY SCANNER - AlZill V6 Pro", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, INFO)
        cprint("[*] Features: Comment detection | Dependency analysis | Fastjson/Struts2 detection", "yellow")
        
        all_results = []
        java_files = []
        
        # جمع كل ملفات Java
        if recursive:
            for root, _, files in os.walk(directory):
                for file in files:
                    if file.endswith('.java'):
                        java_files.append(os.path.join(root, file))
        else:
            for file in os.listdir(directory):
                if file.endswith('.java'):
                    java_files.append(os.path.join(directory, file))
        
        if self.verbose:
            cprint(f"[*] Found {len(java_files)} Java file(s) to scan", INFO)
        
        # فحص كل ملف
        for java_file in java_files:
            if self.verbose:
                cprint(f"\n[*] Scanning: {java_file}", INFO)
            
            results = self.scan_java_file(java_file)
            all_results.extend(results)
        
        # عرض النتائج
        self.display_results(all_results)
        
        # تحليل إضافي
        self.analyze_dependencies(directory)
        
        return all_results
    
    def display_results(self, results: List[Dict]):
        """عرض النتائج بشكل منظم"""
        if not results:
            cprint("\n[✓] No critical vulnerabilities found!", SUCCESS)
            cprint("   The code appears to be relatively secure", INFO)
            return
        
        # إحصائيات
        cprint(f"\n📊 VULNERABILITY STATISTICS:", WARNING)
        cprint(f"   CRITICAL: {self.critical_count}", ERROR)
        cprint(f"   HIGH: {self.high_count}", "light_red")
        cprint(f"   MEDIUM: {self.medium_count}", WARNING)
        cprint(f"   LOW/INFO: {self.low_count}", INFO)
        cprint(f"   Total findings: {len(results)}", "white")
        
        # تفاصيل الثغرات حسب الخطورة
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'INFO']:
            severity_results = [r for r in results if r['severity'] == severity]
            if severity_results:
                color = ERROR if severity == 'CRITICAL' else "light_red" if severity == 'HIGH' else WARNING
                cprint(f"\n{'='*70}", INFO)
                cprint(f"{severity} SEVERITY VULNERABILITIES:", color, attrs=['bold'])
                cprint(f"{'='*70}", INFO)
                
                for result in severity_results[:10]:
                    cprint(f"\n📁 File: {result['file']}", "white")
                    cprint(f"   📍 Line {result['line']}: {result['code'][:100]}", WARNING)
                    cprint(f"   🔴 Type: {result['type']}", color)
                    cprint(f"   📝 Description: {result['description']}", "white")
                    cprint(f"   🔧 Fix: {result['fix']}", SUCCESS)
                    cprint(f"   🆔 CWE: {result['cwe']}", INFO)
        
        if len(results) > 10:
            cprint(f"\n... and {len(results) - 10} more findings", WARNING)
    
    def analyze_dependencies(self, directory: str):
        """تحليل ملفات pom.xml و build.gradle للبحث عن ثغرات في المكتبات (مع Fastjson و Struts2)"""
        cprint("\n" + "="*70, INFO)
        cprint("📦 DEPENDENCY ANALYSIS", HIGHLIGHT, attrs=['bold'])
        cprint("="*70, INFO)
        
        found_deps = False
        
        # البحث عن pom.xml (Maven)
        for root, _, files in os.walk(directory):
            if 'pom.xml' in files:
                found_deps = True
                pom_path = os.path.join(root, 'pom.xml')
                cprint(f"\n[+] Found Maven project: {pom_path}", SUCCESS)
                self.analyze_maven_dependencies_advanced(pom_path)
            
            if 'build.gradle' in files:
                found_deps = True
                gradle_path = os.path.join(root, 'build.gradle')
                cprint(f"\n[+] Found Gradle project: {gradle_path}", SUCCESS)
                self.analyze_gradle_dependencies_advanced(gradle_path)
        
        if not found_deps:
            cprint("[!] No dependency files found (pom.xml or build.gradle)", WARNING)
            cprint("    Manual dependency review recommended", INFO)
    
    def analyze_maven_dependencies_advanced(self, pom_path: str):
        """تحليل متقدم لثغرات مكتبات Maven (مع Fastjson و Struts2)"""
        try:
            with open(pom_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # البحث عن كل dependency
            dep_pattern = r'<dependency>.*?<groupId>(.*?)</groupId>.*?<artifactId>(.*?)</artifactId>.*?<version>(.*?)</version>.*?</dependency>'
            dependencies = re.findall(dep_pattern, content, re.DOTALL)
            
            found_vulns = False
            
            for group_id, artifact_id, version in dependencies:
                artifact_id_lower = artifact_id.lower()
                version_clean = version.strip()
                
                # فحص المكتبات الضعيفة
                for dep_name, info in self.vulnerable_dependencies.items():
                    if dep_name in artifact_id_lower:
                        for vuln_version in info['versions']:
                            if version_clean.startswith(vuln_version):
                                severity_color = ERROR if info['severity'] == 'CRITICAL' else WARNING
                                cprint(f"   ⚠️ {severity_color} {artifact_id}:{version_clean}", severity_color)
                                cprint(f"       CVE: {info['cve']}", INFO)
                                cprint(f"       Description: {info['description']}", WARNING)
                                cprint(f"       Fix: {info['fix']}", SUCCESS)
                                found_vulns = True
                                break
            
            if not found_vulns:
                cprint("   ✅ No vulnerable dependencies found", SUCCESS)
                
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Error analyzing {pom_path}: {e}", ERROR)
    
    def analyze_gradle_dependencies_advanced(self, gradle_path: str):
        """تحليل متقدم لثغرات مكتبات Gradle (مع Fastjson و Struts2)"""
        try:
            with open(gradle_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            found_vulns = False
            
            # أنماط مختلفة لـ Gradle dependencies
            patterns = [
                r"implementation\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
                r"compile\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]",
                r"api\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]"
            ]
            
            for pattern in patterns:
                matches = re.findall(pattern, content)
                for group_id, artifact_id, version in matches:
                    artifact_id_lower = artifact_id.lower()
                    version_clean = version.strip()
                    
                    for dep_name, info in self.vulnerable_dependencies.items():
                        if dep_name in artifact_id_lower:
                            for vuln_version in info['versions']:
                                if version_clean.startswith(vuln_version):
                                    severity_color = ERROR if info['severity'] == 'CRITICAL' else WARNING
                                    cprint(f"   ⚠️ {severity_color} {artifact_id}:{version_clean}", severity_color)
                                    cprint(f"       CVE: {info['cve']}", INFO)
                                    cprint(f"       Description: {info['description']}", WARNING)
                                    cprint(f"       Fix: {info['fix']}", SUCCESS)
                                    found_vulns = True
                                    break
            
            if not found_vulns:
                cprint("   ✅ No vulnerable dependencies found", SUCCESS)
                
        except Exception as e:
            if self.verbose:
                cprint(f"[!] Error analyzing {gradle_path}: {e}", ERROR)
    
    def generate_report(self, results: List[Dict], output_file: str = 'java_scan_report.json'):
        """توليد تقرير مفصل"""
        report = {
            'summary': {
                'total_vulnerabilities': len(results),
                'critical': self.critical_count,
                'high': self.high_count,
                'medium': self.medium_count,
                'low': self.low_count
            },
            'vulnerabilities': results,
            'recommendations': self.generate_recommendations(results)
        }
        
        # حفظ كـ JSON
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False)
        
        cprint(f"\n[+] Report saved to {output_file}", SUCCESS)
    
    def generate_recommendations(self, results: List[Dict]) -> List[str]:
        """توليد توصيات بناءً على الثغرات المكتشفة"""
        recommendations = set()
        
        for result in results:
            if 'Command Injection' in result['type']:
                recommendations.add("🔧 Use ProcessBuilder with array arguments instead of string concatenation")
                recommendations.add("🔧 Implement input validation whitelist for all user inputs")
            
            if 'SQL Injection' in result['type']:
                recommendations.add("🔧 Replace all Statement objects with PreparedStatement")
                recommendations.add("🔧 Use parameterized queries with '?' placeholders")
            
            if 'XSS' in result['type']:
                recommendations.add("🔧 Use OWASP Java Encoder to escape output")
                recommendations.add("🔧 Implement Content-Security-Policy header")
            
            if 'Hardcoded' in result['type']:
                recommendations.add("🔧 Move credentials to environment variables or secrets manager")
                recommendations.add("🔧 Use tools like HashiCorp Vault for secret management")
            
            if 'XXE' in result['type']:
                recommendations.add("🔧 Disable external entities in XML parsers")
            
            if 'Deserialization' in result['type']:
                recommendations.add("🔧 Avoid deserialization of untrusted data")
                recommendations.add("🔧 Use JSON instead of Java serialization")
        
        return list(recommendations)


# ============================================================
# LEGACY FUNCTIONS
# ============================================================

def scan_directory(directory: str, generate_report: bool = False) -> List[Dict]:
    """واجهة متوافقة مع الكود القديم"""
    scanner = JavaSecurityScanner(verbose=True)
    results = scanner.scan_directory(directory)
    
    if generate_report:
        scanner.generate_report(results)
    
    return results


def scan_java_file(filepath: str) -> List[Dict]:
    """فحص ملف Java واحد"""
    scanner = JavaSecurityScanner(verbose=False)
    return scanner.scan_java_file(filepath)


def scan_java_code(content: str, filename: str = "inline.java", verbose: bool = False) -> List[Dict]:
    """
    مسح محتوى Java مباشرة (بدون ملف على القرص)
    هذه الدالة مطلوبة من الكود الرئيسي azil.py
    
    Args:
        content: محتوى الكود (نص)
        filename: اسم الملف للعرض (اختياري)
        verbose: عرض تفاصيل إضافية
    
    Returns:
        list: قائمة بالثغرات المكتشفة
    """
    scanner = JavaSecurityScanner(verbose=verbose)
    
    # حفظ المحتوى مؤقتاً في ملف وهمي للفحص
    with tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False, encoding='utf-8') as f:
        f.write(content)
        temp_file = f.name
    
    try:
        # فحص الملف المؤقت
        results = scanner.scan_java_file(temp_file)
        
        # تعديل مسار الملف للعرض
        for result in results:
            result['file'] = filename
        
        # عرض النتائج إذا كان verbose
        if verbose and results:
            cprint(f"\n[!] Java Security Issues in {filename}:", WARNING)
            for r in results[:5]:
                cprint(f"    -> {r['severity']}: {r['type']} at line {r['line']}", ERROR)
        
        return results
        
    finally:
        # حذف الملف المؤقت
        try:
            os.unlink(temp_file)
        except:
            pass


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        target = sys.argv[1]
        scan_directory(target, generate_report=True)
    else:
        print("Usage: python java_scanner.py <directory>")