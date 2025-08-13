import streamlit as st
from scanners.nmap_scanner import scan_nmap
from scanners.nikto_scanner import scan_nikto

st.set_page_config(page_title="Nmap + Nikto Web Scanner", page_icon="🔎", layout="wide")
st.title("🔎 Nmap → Nikto Web Scanner (No Visualization)")

url = st.text_input("Target URL", placeholder="https://example.com")

if st.button("Run Scan", type="primary"):
    if not url.startswith(("http://", "https://")):
        st.error("Please enter a valid URL starting with http:// or https://")
    else:
        st.subheader("Nmap Findings")
        st.write("Running Nmap…")
        nmap_findings = scan_nmap(url) or []

        if nmap_findings:
            nmap_rows = []
            for f in nmap_findings:
                nmap_rows.append({
                    "Host": f.get("host"),
                    "Port": f.get("port"),
                    "Service": f.get("service"),
                    "State": f.get("state"),
                    "Severity": f.get("severity"),
                    "Description": f.get("description"),
                })
            st.dataframe(nmap_rows, use_container_width=True)
        else:
            st.info("No Nmap results.")

        web_ports = {80, 443, 8080, 8443, 8000, 8888}
        web_targets = []
        for f in nmap_findings:
            try:
                host = f.get("host")
                port = int(f.get("port"))
                state = (f.get("state") or "open").lower()
                service = (f.get("service") or "").lower()
            except Exception:
                continue

            if state == "open" and (service in {"http", "https"} or port in web_ports):
                web_targets.append((host, port))

        web_targets = sorted(set(web_targets))

        st.subheader("Nikto Findings")
        nikto_findings = []
        if web_targets:
            st.write(f"Running Nikto against {len(web_targets)} detected web service(s)…")
            for host, port in web_targets:
                st.write(f"• {host}:{port}")
                issues = scan_nikto(host, port, tuning="12345789abc") or []
                for i in issues:
                    i.setdefault("host", host)
                    i.setdefault("port", port)
                nikto_findings.extend(issues)

            if nikto_findings:
                nikto_rows = []
                for i in nikto_findings:
                    nikto_rows.append({
                        "Host": i.get("host"),
                        "Port": i.get("port"),
                        "URI": i.get("uri"),
                        "Severity": i.get("severity"),
                        "Description": i.get("description"),
                    })
                st.dataframe(nikto_rows, use_container_width=True)
            else:
                st.success("No Nikto issues reported.")
        else:
            st.warning("No web services from Nmap to scan with Nikto.")

        with st.expander("Raw JSON"):
            st.json({
                "nmap": nmap_findings,
                "nikto": nikto_findings
            })
