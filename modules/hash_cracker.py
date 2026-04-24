import bcrypt
import argon2
from termcolor import cprint

def detect_hash_type(hash_str):
    if hash_str.startswith("$2a$") or hash_str.startswith("$2b$"):
        return "bcrypt"
    elif hash_str.startswith("$argon2"):
        return "argon2"
    return None

def verify_bcrypt(hash_str, password):
    try:
        return bcrypt.checkpw(password.encode(), hash_str.encode())
    except Exception:
        return False

def verify_argon2(hash_str, password):
    try:
        ph = argon2.PasswordHasher()
        ph.verify(hash_str, password)
        return True
    except Exception:
        return False

def brute_force_hash(hash_str, wordlist_path):
    cprint(f"[*] Starting brute-force on hash: {hash_str}", "cyan")
    hash_type = detect_hash_type(hash_str)
    if not hash_type:
        cprint("[!] Unsupported hash type.", "red")
        return None

    try:
        with open(wordlist_path, "r") as f:
            for line in f:
                word = line.strip()
                if hash_type == "bcrypt" and verify_bcrypt(hash_str, word):
                    return word
                elif hash_type == "argon2" and verify_argon2(hash_str, word):
                    return word
    except FileNotFoundError:
        cprint(f"[!] Wordlist file not found: {wordlist_path}", "red")
    except Exception as e:
        cprint(f"[!] Error during brute-force: {e}", "red")

    return None
