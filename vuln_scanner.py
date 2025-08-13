import requests
import os
from urllib.parse import urlparse
from scanners.nikto_scanner import scan_nikto
from scanners.nmap_scanner import scan_nmap

def ai_analysis(vulnerabilities, nikto_results=None, nmap_results=None):
    table_data = []

    nikto_count = len(nikto_results) if nikto_results else 0
    nikto_severity = 'Variable' if nikto_results else 'None'
    nikto_status = 'Vulnerable' if nikto_results else 'Secure'
    nikto_key_findings = '; '.join([f.get('description', 'N/A')[:50] + '...' for f in nikto_results[:3]]) if nikto_results else 'No issues found'

    table_data.append({
        'Scanner': 'Nikto',
        'Status': nikto_status,
        'Finding Count': nikto_count,
        'Severity': nikto_severity,
        'Key Findings': nikto_key_findings
    })

    nmap_count = len(nmap_results) if nmap_results else 0
    nmap_severity = 'Info' if nmap_results else 'None'
    nmap_status = 'Vulnerable' if nmap_results else 'Secure'
    nmap_key_findings = '; '.join([f.get('description', 'N/A')[:50] + '...' for f in nmap_results[:3]]) if nmap_results else 'No open ports found'

    table_data.append({
        'Scanner': 'Nmap',
        'Status': nmap_status,
        'Finding Count': nmap_count,
        'Severity': nmap_severity,
        'Key Findings': nmap_key_findings
    })

    return table_data

def main():
    print("AI-Powered Web Application Vulnerability Scanner")
    target_url = input("Enter the target URL: ").strip()
    vulnerabilities = []
    print("\nScanning with Nmap...")
    nmap_results = scan_nmap(target_url)
    if nmap_results:
        vulnerabilities.append('Nmap findings')
        print(f"[Nmap] Found {len(nmap_results)} open ports/services.")
    else:
        print("[Nmap] No open ports found.")
        nmap_results = []

    web_ports = [80, 443, 8080, 8443]
    web_targets = [
        (res["host"], res["port"])
        for res in nmap_results
        if res["service"] in ["http", "https"] or int(res["port"]) in web_ports
    ]

    nikto_results = []
    if web_targets:
        print("\nScanning with Nikto on detected web services...")
        for host, port in web_targets:
            url = f"http://{host}:{port}" if port != 443 else f"https://{host}"
            print(f"[Nikto] Scanning {url}...")
            res = scan_nikto(url)
            if res:
                nikto_results.extend(res)
    else:
        print("\nNo web services detected — skipping Nikto scan.")

    if nikto_results:
        vulnerabilities.append('Nikto findings')
        print(f"[Nikto] Found {len(nikto_results)} potential issues.")
    else:
        print("[Nikto] No major issues found.")

    print("\nRunning AI Analysis...")
    table_data = ai_analysis(vulnerabilities, nikto_results, nmap_results)
    if table_data and bool(os.getenv("STREAMLIT_RUNTIME")):
        print("[AI Analysis] Table data prepared for display")


if __name__ == "__main__":
    main()
