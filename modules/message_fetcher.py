import os
import re
import requests
import urllib3
from bs4 import BeautifulSoup
from termcolor import cprint

# تعطيل تحذيرات SSL لبيئات العمل المحلية
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# --- أنماط البيانات الحساسة (AlZill Sensitive Regex Patterns) ---
SENSITIVE_PATTERNS = {
    "Email Address": r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "Google API Key": r'AIza[0-9A-Za-z-_]{35}',
    "Firebase URL": r'https://.*\.firebaseio\.com',
    "GitHub Token": r'ghp_[0-9a-zA-Z]{36}',
    "AWS Access Key": r'AKIA[0-9A-Z]{16}',
    "IP Address": r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    "Private Key": r'-----BEGIN [A-Z ]+ PRIVATE KEY-----'
}

CHAT_CLASSES = [
    "message", "msg", "chat-message", "message-text", "chat",
    "text", "chat-msg", "conversation", "messages", "Messenger", "html"
]

def load_payloads(tag=None):
    payload_file = os.path.join(os.path.dirname(__file__), "payloads.txt")
    payloads = []
    if not os.path.exists(payload_file):
        cprint("[!] payloads.txt not found.", "red")
        return []
    try:
        with open(payload_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"): continue
                if tag and line.startswith(f"[{tag}]"):
                    payloads.append(line.split(f"[{tag}]")[-1].strip())
                elif not tag and not line.startswith("["):
                    payloads.append(line)
        return payloads
    except Exception as e:
        cprint(f"[!] Error: {e}", "red")
        return []

def fetch_messages(url, api_key=None):
    headers = {'User-Agent': 'AlZill-Scanner/1.1 (Sensitive Data Support)'}
    if api_key: headers['Authorization'] = f"Bearer {api_key}"

    try:
        response = requests.get(url, headers=headers, verify=False, timeout=15)
        response.raise_for_status()
        content = response.text
    except requests.RequestException as e:
        cprint(f"[!] Error fetching URL: {e}", "red")
        return []

    messages = set()
    
    # --- 1. البحث عن البيانات الحساسة باستخدام Regex ---
    cprint("\n[*] Scanning for Sensitive Leaks (Regex)...", "magenta", attrs=['bold'])
    leak_found = False
    for label, pattern in SENSITIVE_PATTERNS.items():
        matches = re.findall(pattern, content)
        if matches:
            leak_found = True
            for match in set(matches):
                cprint(f"[!] {label} Exposed: {match}", "red", attrs=['bold'])
    if not leak_found:
        cprint("[+] No sensitive patterns detected in source code.", "green")

    # --- 2. فحص النزاهة باستخدام وسوم FUZZ من الملف ---
    fuzz_payloads = load_payloads("FUZZ")
    for p in fuzz_payloads:
        if p in content:
            cprint(f"[!] Critical Path Exposure: {p}", "yellow", attrs=['bold'])

    # --- 3. استخراج النصوص العادية ---
    soup = BeautifulSoup(content, "html.parser")
    for class_name in CHAT_CLASSES:
        for tag in soup.find_all(class_=class_name):
            text = tag.get_text(strip=True)
            if text: messages.add(text)

    return list(messages)

def print_messages(url, save=False):
    msgs = fetch_messages(url)
    if msgs:
        cprint(f"\n[✓] Extracted {len(msgs)} text elements.", "cyan")
        if save:
            with open("leaks_log.txt", "a") as f:
                f.write(f"\n--- Target: {url} ---\n")
                for m in msgs: f.write(m + "\n")
            cprint("[✓] Data appended to leaks_log.txt", "blue")

if __name__ == "__main__":
    target = input("Enter target URL: ")
    print_messages(target, save=True)

