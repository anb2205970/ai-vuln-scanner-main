import subprocess
import xml.etree.ElementTree as ET
import os
from urllib.parse import urlparse

def scan_nmap(target_url):
    """Quick Nmap scan for common web ports and return findings."""
    parsed_url = urlparse(target_url)
    target = parsed_url.hostname
    if not target:
        print(f"[Nmap] Invalid URL: {target_url}. Could not extract hostname.")
        return []
    output_file = "nmap_output.xml"
    if os.path.exists(output_file):
        os.remove(output_file)

    try:
        subprocess.run([
            "nmap", "-p", "80,443,8080,8443",
            "--open", "-sV",
            "-oX", output_file, target
        ], check=True)
        if not os.path.exists(output_file):
            print("[Nmap] Output file not found.")
            return []
        tree = ET.parse(output_file)
        root = tree.getroot()
        findings = []
        for port in root.findall(".//port"):
            port_id = int(port.get("portid"))
            protocol = port.get("protocol")
            state = port.find("state").get("state")
            service = port.find("service").get("name") if port.find("service") is not None else "Unknown"

            if state == "open" and service in ["http", "https"]:
                findings.append({
                    "description": f"Open {service.upper()} service on port {port_id}/{protocol}",
                    "port": port_id,
                    "service": service,
                    "severity": "Info",
                    "host": target
                })
        return findings
    except subprocess.CalledProcessError as e:
        print(f"[Nmap] Error running Nmap: {e}")
        return []
