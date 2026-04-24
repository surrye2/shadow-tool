#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import dns.resolver
import dns.dnssec
import dns.name
import dns.query
import dns.message
import dns.rdatatype

from urllib.parse import urlparse


def analyze_dns(target_url):
    """Perform advanced DNS analysis and return readable text."""
    parsed = urlparse(target_url)
    domain = parsed.netloc or parsed.path
    if domain.startswith("www."):
        domain = domain[4:]

    output = []
    output.append(f"[*] Analyzing DNS records for: {domain}\n")

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4.0

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype)
            values = [str(rdata.to_text()) for rdata in answers]
            output.append(f"[+] {rtype} Records: {', '.join(values)}")
        except dns.resolver.NoAnswer:
            output.append(f"[-] {rtype}: No records found.")
        except dns.resolver.NXDOMAIN:
            output.append(f"[!] Domain does not exist: {domain}")
            break
        except Exception as e:
            output.append(f"[!] {rtype} lookup failed: {e}")

    # Check for SPF / DMARC presence
    try:
        txt_records = resolver.resolve(domain, "TXT")
        spf = [r.to_text() for r in txt_records if "v=spf" in r.to_text().lower()]
        dmarc = []
        try:
            dmarc_records = resolver.resolve(f"_dmarc.{domain}", "TXT")
            dmarc = [r.to_text() for r in dmarc_records]
        except Exception:
            pass
        if spf:
            output.append(f"[+] SPF Records: {', '.join(spf)}")
        else:
            output.append("[-] No SPF record detected.")
        if dmarc:
            output.append(f"[+] DMARC Records: {', '.join(dmarc)}")
        else:
            output.append("[-] No DMARC record detected.")
    except Exception:
        output.append("[-] No TXT/SPF/DMARC records found.")

    # DNSSEC Check
    try:
        dnskey = resolver.resolve(domain, "DNSKEY")
        if dnskey:
            output.append("[✓] DNSSEC: Enabled (DNSKEY records found)")
        else:
            output.append("[-] DNSSEC: Not configured.")
    except dns.resolver.NoAnswer:
        output.append("[-] DNSSEC: No DNSKEY record found.")
    except Exception as e:
        output.append(f"[-] DNSSEC check failed: {e}")

    return "\n".join(output)
