import os
import importlib
import inspect
import warnings
from bs4 import MarkupResemblesLocatorWarning

warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)

class AlZillEngine:
    def __init__(self, target_url):
        self.target_url = target_url if target_url.startswith(('http', 'https')) else f"https://{target_url}"
        self.modules_dir = "modules"
        # إزالة waf_detector من القائمة - سيتم تشغيله فقط من start_intelligent_scan
        self.enabled_modules = ['infra_scanner']  # فقط الموديولات الأخرى

    def start_scanning(self):
        if not os.path.exists(self.modules_dir):
            return

        print(f"[*] AlZillEngine: Starting scan (WAF detection handled externally)")
        
        for module_name in self.enabled_modules:
            try:
                module = importlib.import_module(f"modules.{module_name}")
                
                for name, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and obj.__module__ == module.__name__:
                        # التحقق من عدد الوسائط قبل الإنشاء
                        sig = inspect.signature(obj.__init__)
                        if len(sig.parameters) > 1:  # إذا كان يقبل وسائط (self + target)
                            instance = obj(self.target_url)
                        else:
                            instance = obj()
                        
                        if hasattr(instance, 'run'):
                            print(f"[*] Running module: {module_name}")
                            instance.run()
                            
            except Exception as e:
                print(f"[X] Engine Error loading [{module_name}]: {str(e)}")
