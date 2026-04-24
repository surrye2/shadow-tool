#!/usr/bin/env python3
"""
Hash Analyzer - Detect password hashes in text
Does NOT crack them (avoids CPU overload). Provides warning and suggests external tools.
Compatible with AlZill.
"""

import re
from termcolor import cprint

class HashAnalyzer:
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.findings = []

        # أنماط لأنواع الهاشات الشائعة
        self.hash_patterns = {
            "MD5": r'\b[a-f0-9]{32}\b',
            "SHA-1": r'\b[a-f0-9]{40}\b',
            "SHA-256": r'\b[a-f0-9]{64}\b',
            "SHA-512": r'\b[a-f0-9]{128}\b',
            "bcrypt": r'\$2[aby]\$[0-9]{2}\$[./A-Za-z0-9]{53}',
            "argon2": r'\$argon2(id|d|i)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+',
            "NTLM": r'\b[a-f0-9]{32}\b',  # NTLM also 32 chars, but context needed
            "MySQL": r'\*[A-F0-9]{40}\b',
            "PostgreSQL": r'md5[a-f0-9]{32}',
        }

    def scan(self, content, source="inline", verbose=False):
        """الوظيفة الرئيسية – تكتشف الهاشات فقط، لا تكسرها"""
        self.verbose = verbose
        cprint("\n[HASH ANALYZER] Scanning for password hashes", "cyan")

        findings = []
        for hash_type, pattern in self.hash_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                # تجاهل التكرارات
                if match not in [f['hash'] for f in findings]:
                    findings.append({
                        'type': hash_type,
                        'hash': match,
                        'source': source
                    })
                    if self.verbose:
                        cprint(f"    [!] Detected {hash_type}: {match[:20]}...", "yellow")

        self.findings = findings
        self._display_results()
        return len(findings) > 0

    def _display_results(self):
        if not self.findings:
            cprint("[✓] No password hashes detected", "green")
            return

        cprint(f"\n[!] Found {len(self.findings)} password hash(es):", "red")
        for f in self.findings[:10]:
            cprint(f"    - {f['type']}: {f['hash'][:30]}...", "yellow")
        if len(self.findings) > 10:
            cprint(f"    ... and {len(self.findings)-10} more", "yellow")

        # تحذير: لا تحاول تكسير الهاشات هنا
        cprint("\n⚠️  WARNING: Cracking hashes requires significant CPU power.", "red")
        cprint("   Use dedicated tools like hashcat or John the Ripper on a powerful machine.", "yellow")
        cprint("   AlZill will NOT attempt to crack them to avoid system overload.\n", "yellow")


# دالة متوافقة مع AlZill (تستقبل URL وتجلب المحتوى)
def scan(url, verbose=False):
    """AlZill-compatible entry point"""
    import requests
    try:
        response = requests.get(url, timeout=10, verify=False)
        content = response.text
        analyzer = HashAnalyzer(verbose=verbose)
        return analyzer.scan(content, source=url, verbose=verbose)
    except Exception as e:
        cprint(f"[HASH ANALYZER] Error fetching {url}: {e}", "red")
        return False


# للاختبار المستقل
if __name__ == "__main__":
    test_content = """
    password_hash = "$2a$12$abcdefghijklmnopqrstuvwxyzABCDEF"
    md5_hash = "5d41402abc4b2a76b9719d911017c592"
    """
    analyzer = HashAnalyzer(verbose=True)
    analyzer.scan(test_content)
