#!/usr/bin/env python3
"""
AlZill JSON Injector Module - V6 Pro
Purpose: Inject obfuscated payloads into JSON structures, arrays, and nested API endpoints.
Features: Deep copy protection | Array support | JSON WAF bypass | String preservation
"""

import json
import copy
import random
import string
from modules.obfuscator import AlZillObfuscator
from typing import Union, List, Dict, Any, Optional, Tuple

INFO = "cyan"
SUCCESS = "green"
WARNING = "yellow"
ERROR = "red"
HIGHLIGHT = "magenta"


class JSONInjector:
    """
    Advanced JSON Injector with:
    - Deep copy protection (لا تعديل على النسخة الأصلية)
    - Array/List support
    - JSON WAF bypass techniques
    - Duplicate key injection (JSON Parameter Pollution)
    - Automatic string preservation (يحافظ على نوع الإدخال)
    """

    def __init__(self, *args, **kwargs):
        """Initialize AlZill JSON engine"""
        self.verbose = kwargs.get('verbose', False)
        
        # WAF bypass techniques
        self.waf_bypass_techniques = [
            'standard',           # Standard injection
            'unicode_escape',     # Unicode escaped
            'comment_injection',  # JSON with comments (if parser supports)
            'duplicate_keys',     # Duplicate key pollution
            'array_wrap',         # Wrapped in array
            'nested_wrap',        # Deep nested
        ]

    # ============================================================
    # DEEP COPY PROTECTION (منع تعديل النسخة الأصلية)
    # ============================================================
    
    @staticmethod
    def _deep_copy(data: Any) -> Any:
        """
        إنشاء نسخة عميقة من البيانات لمنع تعديل الأصل
        هذه أهم نقطة في الموديول
        """
        try:
            return copy.deepcopy(data)
        except Exception:
            # Fallback: استخدام JSON serialization
            try:
                return json.loads(json.dumps(data))
            except:
                return data

    # ============================================================
    # TYPE PRESERVATION (الحفاظ على نوع الإدخال)
    # ============================================================
    
    @staticmethod
    def _was_string_input(original_data: Any) -> bool:
        """التحقق مما إذا كان الإدخال الأصلي نصاً"""
        return isinstance(original_data, str)

    @staticmethod
    def _to_json_string(data: Any, pretty: bool = False) -> str:
        """تحويل البيانات إلى JSON string"""
        if pretty:
            return json.dumps(data, indent=2, ensure_ascii=False)
        return json.dumps(data, ensure_ascii=False)

    @staticmethod
    def _preserve_type(original_data: Any, result: Any) -> Union[str, Any]:
        """
        إعادة النتيجة بنفس نوع الإدخال الأصلي
        إذا كان الإدخال نصاً، نعيد JSON string
        """
        if JSONInjector._was_string_input(original_data):
            return JSONInjector._to_json_string(result)
        return result

    # ============================================================
    # ARRAY/LIST SUPPORT (دعم المصفوفات)
    # ============================================================
    
    @staticmethod
    def _find_in_array(arr: List, param_name: str) -> Optional[int]:
        """
        البحث عن عنصر في المصفوفة
        """
        for idx, item in enumerate(arr):
            if isinstance(item, dict) and param_name in item:
                return idx
            elif isinstance(item, str) and item == param_name:
                return idx
        return None

    @staticmethod
    def _inject_into_array(arr: List, param_name: str, payload: Any) -> List:
        """
        حقن البايلود في المصفوفة
        """
        result = copy.deepcopy(arr)
        
        # محاولة العثور على العنصر واستبداله
        idx = JSONInjector._find_in_array(result, param_name)
        if idx is not None:
            if isinstance(result[idx], dict):
                result[idx][param_name] = payload
            else:
                result[idx] = payload
        else:
            # إضافة عنصر جديد
            result.append({param_name: payload})
        
        return result

    # ============================================================
    # WAF BYPASS TECHNIQUES
    # ============================================================
    
    @staticmethod
    def _unicode_escape_payload(payload: str) -> str:
        """
        تحويل البايلود إلى Unicode escaped format
        """
        return ''.join(f'\\u{ord(c):04x}' for c in payload)

    @staticmethod
    def _comment_injection(data: Dict, param_name: str, payload: Any) -> str:
        """
        إضافة تعليقات JSON (إذا كان المحلل يدعمها)
        بعض WAFs لا تتحقق من التعليقات
        """
        # تحويل إلى JSON string
        json_str = json.dumps(data)
        # إضافة تعليق قبل الباراميتر
        json_str = json_str.replace(f'"{param_name}"', f'/* WAF_BYPASS */ "{param_name}"')
        return json_str

    @staticmethod
    def _duplicate_keys(data: Dict, param_name: str, payload: Any) -> str:
        """
        تقنية Duplicate Keys (JSON Parameter Pollution)
        بعض المحللات تأخذ آخر قيمة، مما قد يتجاوز الفلترة
        """
        json_str = json.dumps(data)
        # إضافة مفتاح مكرر
        duplicate = f', "{param_name}": {json.dumps(payload)}'
        # إدراج المفتاح المكرر قبل نهاية القاموس
        insert_pos = json_str.rfind('}')
        if insert_pos > 0:
            json_str = json_str[:insert_pos] + duplicate + json_str[insert_pos:]
        return json_str

    @staticmethod
    def _array_wrap(data: Dict, param_name: str, payload: Any) -> List:
        """
        لف البايلود في مصفوفة لتجاوز الفلاتر
        """
        result = copy.deepcopy(data)
        result[param_name] = [payload, "normal_value"]
        return result

    # ============================================================
    # MAIN INJECTION FUNCTIONS
    # ============================================================
    
    @staticmethod
    def inject(original_data: Union[Dict, List, str], 
               param_name: str, 
               payload: str, 
               obfuscate: bool = True,
               use_deep_copy: bool = True,
               preserve_type: bool = True) -> Union[Dict, List, str]:
        """
        Inject payload into JSON data with optional obfuscation.
        
        Args:
            original_data: dict, list, or string (original JSON)
            param_name: parameter name to inject
            payload: raw payload
            obfuscate: Boolean to apply AlZill stealth layers
            use_deep_copy: Boolean to use deep copy (default True)
            preserve_type: Boolean to preserve input type (default True)
        
        Returns:
            Modified copy of original data (original unchanged)
            Returns JSON string if input was string, otherwise dict/list
        """
        # IMPORTANT: Create deep copy to avoid modifying original
        if use_deep_copy:
            data = JSONInjector._deep_copy(original_data)
        else:
            data = original_data
        
        # Track if input was string for type preservation
        was_string = JSONInjector._was_string_input(original_data) if preserve_type else False
        
        # Parse string JSON if needed
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                data = {}
        
        # Apply obfuscation if enabled
        final_payload = AlZillObfuscator.super_obfuscate(payload) if obfuscate else payload
        
        # Handle different data types
        if isinstance(data, dict):
            # Dictionary injection
            data[param_name] = final_payload
            result = data
        
        elif isinstance(data, list):
            # Array injection
            result = JSONInjector._inject_into_array(data, param_name, final_payload)
        
        else:
            # Default case
            result = {param_name: final_payload}
        
        # Preserve original type if requested
        if was_string:
            return JSONInjector._to_json_string(result)
        
        return result

    @staticmethod
    def inject_nested(original_data: Union[Dict, List, str], 
                      path: List[str], 
                      payload: str, 
                      obfuscate: bool = True,
                      use_deep_copy: bool = True,
                      preserve_type: bool = True) -> Union[Dict, List, str]:
        """
        Inject payload into deep nested JSON structures.
        Example: {"user": {"meta": {"field": "value"}}}
        
        Args:
            original_data: Original JSON data
            path: List of keys to traverse (e.g., ['user', 'meta', 'field'])
            payload: Payload to inject
            obfuscate: Apply obfuscation
            use_deep_copy: Use deep copy to protect original
            preserve_type: Preserve input type
        
        Returns:
            Modified copy of original data
        """
        # Track if input was string for type preservation
        was_string = JSONInjector._was_string_input(original_data) if preserve_type else False
        
        # Create deep copy to avoid modifying original
        if use_deep_copy:
            data = JSONInjector._deep_copy(original_data)
        else:
            data = original_data
        
        # Parse string JSON if needed
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except json.JSONDecodeError:
                data = {}
        
        final_payload = AlZillObfuscator.super_obfuscate(payload) if obfuscate else payload
        
        # Handle nested dictionary
        if isinstance(data, dict):
            current = data
            for key in path[:-1]:
                if key not in current or not isinstance(current[key], dict):
                    current[key] = {}
                current = current[key]
            current[path[-1]] = final_payload
            result = data
        
        # Handle nested list
        elif isinstance(data, list):
            result = copy.deepcopy(data)
            for idx, item in enumerate(result):
                if isinstance(item, dict):
                    result[idx] = JSONInjector.inject_nested(item, path, final_payload, obfuscate, False, False)
        
        else:
            result = data
        
        # Preserve original type if requested
        if was_string:
            return JSONInjector._to_json_string(result)
        
        return result

    @staticmethod
    def inject_multi(original_data: Union[Dict, List, str],
                     injections: List[Dict],
                     obfuscate: bool = True,
                     use_deep_copy: bool = True,
                     preserve_type: bool = True) -> Union[Dict, List, str]:
        """
        Inject multiple payloads at once
        
        Args:
            original_data: Original JSON data
            injections: List of injection configs
                Example: [{'param': 'cmd', 'payload': 'whoami'}, {'param': 'id', 'payload': 'id'}]
            obfuscate: Apply obfuscation
            use_deep_copy: Use deep copy
            preserve_type: Preserve input type
        
        Returns:
            Modified copy with all injections
        """
        # Track if input was string for type preservation
        was_string = JSONInjector._was_string_input(original_data) if preserve_type else False
        
        result = JSONInjector._deep_copy(original_data) if use_deep_copy else original_data
        
        # Parse string JSON if needed
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except json.JSONDecodeError:
                result = {}
        
        for injection in injections:
            param = injection.get('param')
            payload = injection.get('payload')
            path = injection.get('path', None)
            
            if path:
                result = JSONInjector.inject_nested(result, path, payload, obfuscate, False, False)
            else:
                result = JSONInjector.inject(result, param, payload, obfuscate, False, False)
        
        # Preserve original type if requested
        if was_string:
            return JSONInjector._to_json_string(result)
        
        return result

    # ============================================================
    # STEALTH JSON VARIANTS
    # ============================================================
    
    @staticmethod
    def get_stealth_json_variants(param_name: str, 
                                  payload: str,
                                  include_waf_bypass: bool = True) -> List[Union[Dict, List, str]]:
        """
        Generate multiple stealthy JSON variations for API testing.
        
        Args:
            param_name: Target parameter name
            payload: Payload to inject
            include_waf_bypass: Include WAF bypass techniques
        
        Returns:
            List of JSON variants
        """
        variants = []
        
        # Obfuscated payload
        obfuscated_payload = AlZillObfuscator.super_obfuscate(payload)
        
        # 1. Standard Obfuscated JSON
        variants.append({param_name: obfuscated_payload})
        
        # 2. Unicode Escaped Variant
        unicode_payload = JSONInjector._unicode_escape_payload(payload)
        variants.append({param_name: unicode_payload})
        
        # 3. Double Wrapped Patterns
        variants.append({'request': {param_name: obfuscated_payload}})
        variants.append({'api_data': {'input': {param_name: obfuscated_payload}}})
        variants.append({'data': {'attributes': {param_name: obfuscated_payload}}})
        
        # 4. JSON Array Injection
        variants.append({param_name: [obfuscated_payload, "normal_value"]})
        variants.append({param_name: ["normal_value", obfuscated_payload]})
        
        # 5. Nested Array Injection
        variants.append({param_name: [{"value": obfuscated_payload}]})
        
        # 6. WAF Bypass Techniques (اختياري)
        if include_waf_bypass:
            # Duplicate Keys (JSON Parameter Pollution)
            base_data = {"normal": "value"}
            duplicate_json = JSONInjector._duplicate_keys(base_data, param_name, obfuscated_payload)
            variants.append(duplicate_json)
            
            # Array Wrap
            variants.append(JSONInjector._array_wrap({}, param_name, obfuscated_payload))
            
            # Deep nested
            variants.append({'level1': {'level2': {'level3': {param_name: obfuscated_payload}}}})
        
        return variants

    @staticmethod
    def get_random_variant(param_name: str, payload: str) -> Union[Dict, List, str]:
        """
        Get random stealth variant for fuzzing
        """
        variants = JSONInjector.get_stealth_json_variants(param_name, payload, include_waf_bypass=True)
        return random.choice(variants)

    # ============================================================
    # VALIDATION FUNCTIONS
    # ============================================================
    
    @staticmethod
    def is_valid_json(data: str) -> bool:
        """
        Check if string is valid JSON
        """
        try:
            json.loads(data)
            return True
        except json.JSONDecodeError:
            return False

    @staticmethod
    def validate_injection(original: Union[Dict, List, str], 
                          injected: Union[Dict, List, str]) -> bool:
        """
        Validate that injection was successful
        """
        # Convert to strings for comparison
        original_str = json.dumps(original, sort_keys=True) if not isinstance(original, str) else original
        injected_str = json.dumps(injected, sort_keys=True) if not isinstance(injected, str) else injected
        
        return original_str != injected_str

    # ============================================================
    # JSON PATH EXTRACTION (الكنز الحقيقي - للـ Fuzzer)
    # ============================================================
    
    @staticmethod
    def get_json_paths(data: Union[Dict, List], parent: str = '') -> List[str]:
        """
        Extract all JSON paths for analysis.
        هذه الدالة "كنز" حقيقي يمكن استخدامها في موديول الـ Fuzzer
        
        Args:
            data: JSON data (dict or list)
            parent: Parent path (for recursion)
        
        Returns:
            List of JSON paths like:
            - 'user.name'
            - 'items[0]'
            - 'nested.field[1].value'
        """
        paths = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                # Build current path
                if parent:
                    current_path = f"{parent}.{key}"
                else:
                    current_path = key
                
                paths.append(current_path)
                
                # Recursively extract nested paths
                if isinstance(value, (dict, list)):
                    paths.extend(JSONInjector.get_json_paths(value, current_path))
        
        elif isinstance(data, list):
            for idx, item in enumerate(data):
                # Build current path with array index
                current_path = f"{parent}[{idx}]" if parent else f"[{idx}]"
                
                # Recursively extract nested paths
                if isinstance(item, (dict, list)):
                    paths.extend(JSONInjector.get_json_paths(item, current_path))
        
        return paths

    @staticmethod
    def get_injection_points(data: Union[Dict, List]) -> List[Dict]:
        """
        استخراج نقاط الحقن المحتملة مع معلومات إضافية للـ Fuzzer
        هذه الدالة تحدد كل مكان يمكن حقن البايلود فيه
        
        Returns:
            List of injection points with metadata:
            - path: JSON path
            - type: نوع القيمة (string, number, boolean, etc.)
            - current_value: القيمة الحالية
        """
        injection_points = []
        
        def traverse(obj, path=''):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    
                    # Record injection point
                    injection_points.append({
                        'path': current_path,
                        'type': type(value).__name__,
                        'current_value': str(value)[:50] if value is not None else None,
                        'is_nested': isinstance(value, (dict, list))
                    })
                    
                    # Traverse deeper
                    traverse(value, current_path)
            
            elif isinstance(obj, list):
                for idx, item in enumerate(obj):
                    current_path = f"{path}[{idx}]"
                    
                    # Record injection point
                    injection_points.append({
                        'path': current_path,
                        'type': type(item).__name__,
                        'current_value': str(item)[:50] if item is not None else None,
                        'is_nested': isinstance(item, (dict, list))
                    })
                    
                    # Traverse deeper
                    traverse(item, current_path)
        
        traverse(data)
        return injection_points

    # ============================================================
    # FUZZER-READY FUNCTIONS (للاستخدام المباشر في موديول الـ Fuzzer)
    # ============================================================
    
    @staticmethod
    def get_all_injection_variants(data: Union[Dict, List, str],
                                   payload: str,
                                   obfuscate: bool = True) -> List[Tuple[str, Any]]:
        """
        توليد جميع متغيرات الحقن الممكنة لنقطة واحدة
        يمكن استخدامها مباشرة في موديول الـ Fuzzer
        
        Returns:
            List of (path, injected_data) tuples
        """
        # Parse data if string
        if isinstance(data, str):
            try:
                data = json.loads(data)
            except:
                return []
        
        # Get all injection points
        injection_points = JSONInjector.get_injection_points(data)
        
        variants = []
        
        for point in injection_points:
            if not point['is_nested']:  # Only inject into leaf nodes
                path = point['path'].split('.')
                
                # Try different injection methods
                for variant_name, variant_data in JSONInjector._get_path_variants(data, path, payload, obfuscate):
                    variants.append((f"{point['path']} [{variant_name}]", variant_data))
        
        return variants

    @staticmethod
    def _get_path_variants(data: Any, path: List[str], payload: str, obfuscate: bool) -> List[Tuple[str, Any]]:
        """
        توليد متغيرات مختلفة لنفس المسار
        """
        variants = []
        
        # 1. Standard injection
        variants.append(('standard', JSONInjector.inject_nested(data, path, payload, obfuscate)))
        
        # 2. Array wrap injection
        array_path = path[:-1] + [f"{path[-1]}[]"]
        variants.append(('array_wrap', JSONInjector.inject_nested(data, array_path, payload, obfuscate)))
        
        # 3. Unicode escape injection
        variants.append(('unicode', JSONInjector.inject_nested(data, path, payload, obfuscate)))
        
        return variants

    # ============================================================
    # UTILITY FUNCTIONS
    # ============================================================
    
    @staticmethod
    def pretty_print(data: Any) -> str:
        """
        Pretty print JSON data
        """
        try:
            if isinstance(data, str):
                data = json.loads(data)
            return json.dumps(data, indent=2, ensure_ascii=False)
        except:
            return str(data)


# ============================================================
# DEMO / TEST
# ============================================================

if __name__ == "__main__":
    # Test data
    original_data = {
        "user": "admin",
        "password": "secret",
        "nested": {
            "field1": "value1",
            "field2": "value2"
        },
        "items": ["item1", "item2", "item3"]
    }
    
    print("="*60)
    print("JSON INJECTOR V6 Pro - Demo")
    print("="*60)
    
    # Test 1: Type preservation (String input)
    print("\n[1] Type Preservation (String Input):")
    json_string = '{"user": "admin", "password": "secret"}'
    print(f"Input type: {type(json_string)}")
    
    injected = JSONInjector.inject(json_string, "cmd", "whoami", preserve_type=True)
    print(f"Output type: {type(injected)}")
    print(f"Injected JSON: {injected[:80]}...")
    
    # Test 2: JSON Paths (الكنز الحقيقي)
    print("\n[2] JSON Paths Extraction (لـ Fuzzer):")
    paths = JSONInjector.get_json_paths(original_data)
    for path in paths:
        print(f"  {path}")
    
    # Test 3: Injection Points (لـ Fuzzer)
    print("\n[3] Injection Points (لـ Fuzzer):")
    points = JSONInjector.get_injection_points(original_data)
    for point in points[:5]:
        print(f"  Path: {point['path']} | Type: {point['type']} | Value: {point['current_value']}")
    
    # Test 4: All injection variants (Fuzzer-ready)
    print("\n[4] All Injection Variants (Fuzzer-Ready):")
    variants = JSONInjector.get_all_injection_variants(original_data, "test_payload")
    for i, (path, _) in enumerate(variants[:5]):
        print(f"  {i+1}. {path}")
    
    # Test 5: Nested injection with string preservation
    print("\n[5] Nested Injection with String Preservation:")
    nested_json = '{"level1": {"level2": {"target": "value"}}}'
    injected_nested = JSONInjector.inject_nested(nested_json, ['level1', 'level2', 'target'], "XSS_PAYLOAD", preserve_type=True)
    print(f"Original: {nested_json}")
    print(f"Injected: {injected_nested}")
    
    print("\n" + "="*60)
    print("[✓] JSON Injector V6 Pro Ready for Fuzzer Integration")
    print("="*60)