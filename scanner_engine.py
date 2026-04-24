import os
import importlib
import inspect
import warnings
from bs4 import MarkupResemblesLocatorWarning

# إخفاء التحذيرات المزعجة التي ظهرت في الفحص السابق
warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
warnings.filterwarnings("ignore", category=UserWarning, module='bs4')

class AlZillEngine:
    def __init__(self, target_url):
        # التأكد من أن الرابط يبدأ بـ http أو https
        if not target_url.startswith(('http://', 'https://')):
            self.target_url = f"https://{target_url}"
        else:
            self.target_url = target_url

        self.modules_dir = "modules"

    def start_scanning(self):
        # الحصول على قائمة الموديولات المتاحة
        if not os.path.exists(self.modules_dir):
            print(f"[X] Error: Directory '{self.modules_dir}' not found!")
            return

        module_files = [f[:-3] for f in os.listdir(self.modules_dir)
                        if f.endswith('.py') and f != '__init__.py']

        for module_name in module_files:
            try:
                # استيراد الموديول برمجياً
                module = importlib.import_module(f"modules.{module_name}")

                # البحث عن الكلاسات داخل الموديول
                for name, obj in inspect.getmembers(module):
                    if inspect.isclass(obj) and obj.__module__ == module.__name__:
                        # إنشاء نسخة وتمرير الرابط (target_url) لها
                        instance = obj(self.target_url)

                        # تشغيل الدالة الموحدة run
                        if hasattr(instance, 'run'):
                            instance.run()

            except Exception as e:
                print(f"[X] Engine Error loading [{module_name}]: {str(e)}")
