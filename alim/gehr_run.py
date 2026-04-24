import sys
from termcolor import cprint
import cookie_analyzer
import data_decryptor

def main():
    if len(sys.argv) < 2:
        cprint("Usage: python3 gehr_run.py <target_url>", "yellow")
        sys.exit(1)

    target_url = sys.argv[1]
    cprint("=" * 60, "cyan")
    cprint("  GEHR Data Analyzer & Decryptor", "magenta", attrs=["bold"])
    cprint("=" * 60, "cyan")

    # Step 1 - Analyze cookies and extract sensitive data
    cprint("[1] Running cookie analyzer...", "blue")
    analysis_results = cookie_analyzer.run(target_url)

    if not analysis_results or "error" in analysis_results:
        cprint(f"[!] Analysis failed: {analysis_results.get('error', 'unknown error')}", "red")
        sys.exit(1)

    cprint("\n[2] Running data decryptor...", "blue")
    decrypted = data_decryptor.run(analysis_results)

    # Save results to files
    with open("results/gehr_analysis.json", "w", encoding="utf-8") as f:
        import json
        json.dump(analysis_results, f, indent=4, ensure_ascii=False)

    with open("results/gehr_decrypted.json", "w", encoding="utf-8") as f:
        import json
        json.dump(decrypted, f, indent=4, ensure_ascii=False)

    cprint("\n[✓] Analysis completed successfully.", "green")
    cprint("[+] Saved results to:", "cyan")
    cprint("    results/gehr_analysis.json", "white")
    cprint("    results/gehr_decrypted.json\n", "white")

if __name__ == "__main__":
    main()
