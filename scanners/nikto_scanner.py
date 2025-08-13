import subprocess
import xml.etree.ElementTree as ET
import os

def scan_nikto(host, port=80, tuning="12345789abc"):
    output_file = "nikto_output.xml"
    target_url = f"http://{host}:{port}"

    if not host or not isinstance(port, int) or port < 1 or port > 65535:
        print(f"[Nikto] Invalid host or port: {host}:{port}")
        return []

    if os.path.exists(output_file):
        try:
            os.remove(output_file)
        except OSError as e:
            print(f"[Nikto] Error removing old output file: {e}")
            return []

    try:
        cmd = ["nikto", "-h", target_url, "-Tuning", tuning, "-o", output_file, "-Format", "xml"]
        print(f"[Nikto] Running command: {' '.join(cmd)}")
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[Nikto] Stdout: {result.stdout}")
        print(f"[Nikto] Stderr: {result.stderr}")

        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            try:
                tree = ET.parse(output_file)
                root = tree.getroot()
                findings = []
                for item in root.findall(".//item"):
                    findings.append({
                        "host": host,
                        "port": port,
                        "description": item.findtext("description"),
                        "uri": item.findtext("uri"),
                        "severity": item.findtext("severity") or "Unknown"
                    })
                return findings
            except ET.ParseError as e:
                print(f"[Nikto] XML Parse Error: {e}")
                return []
        else:
            print(f"[Nikto] Error: Output file {output_file} is empty or does not exist.")
            return []
    except subprocess.CalledProcessError as e:
        print(f"[Nikto] Error running Nikto: {e}")
        return []
