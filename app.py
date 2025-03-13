from flask import Flask, render_template, request, jsonify
import nmap
import requests
import json
import os
import re
from functools import wraps
from dotenv import load_dotenv
import ipaddress
import time

app = Flask(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT = 50  # Max 50 CVEs per 30 seconds
NVD_SLEEP_TIME = 30  # Wait 30 seconds after hitting the limit
NVD_API_KEY = os.getenv("NVD_API_KEY")

def fetch_cve_details(cve_id):
    """
    Fetch CVE details (description and CVSS score) for a single CVE ID.
    :param cve_id: CVE ID to fetch details for.
    :return: Dictionary containing description and CVSS score.
    """
    url = f"{NVD_API_URL}?cveId={cve_id}"
    headers = {"apiKey": NVD_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an error for HTTP issues
        data = response.json()

        if "vulnerabilities" in data and data["vulnerabilities"]:
            cve = data["vulnerabilities"][0].get("cve", {})

            # Extract description
            description = cve.get("descriptions", [{}])[0].get("value", "No description available")

            # Extract CVSS score (try CVSSv3 first, then fallback to CVSSv2)
            cvss_metrics = cve.get("metrics", {})
            cvss_score = None

            if "cvssMetricV31" in cvss_metrics:
                cvss_score = cvss_metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in cvss_metrics:
                cvss_score = cvss_metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in cvss_metrics:
                cvss_score = cvss_metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            return {
                "description": description,
                "cvss_score": cvss_score if cvss_score is not None else "Unknown"
            }

    except requests.exceptions.RequestException as e:
        print(f"Error fetching CVE details for {cve_id}: {e}")

    return {"description": "Error fetching details", "cvss_score": "Unknown"}


def parse_vulners_output(output):
    """Parse and sanitize Vulners script output."""
    if not output:
        return []
    
    vulns = []
    for line in output:
        if line.startswith("CVE"):
            vulns.append(line)
            # print(line)
    return vulns

def validate_ip_addr(ip):
    """Validate the IP address"""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
def scan_vulnerabilities(ip):
    """Scan vulnerabilities for a given IP address"""
    try:
        validate_ip_addr(ip)
        print(f"Scanning IP: {ip}")  # Debugging

        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-sV --script vulners")

        vulnerabilities = []
        all_cves = []

        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    try:
                        port_data = nm[host][proto][port]
                        service = port_data.get("name", "unknown")
                        version = port_data.get("version", "unknown")
                        product = port_data.get("product", "unknown")

                        vuln_scripts = port_data.get("script", {})
                        vulners_output = vuln_scripts.get("vulners", "").split()

                        if vulners_output:
                            cve_ids = parse_vulners_output(vulners_output)
                            all_cves.extend(cve_ids)

                            for cve_id in cve_ids:
                                vulnerabilities.append({
                                    "port": port,
                                    "service": service,
                                    "product": product,
                                    "version": version,
                                    "vuln_id": cve_id,
                                    "Description": None, # Placeholder to be filled later
                                    "CVSS Score": None # Placeholder to be filled later
                                })

                    except Exception as e:
                        print(f"Error processing vulnerabilities on port {port}: {str(e)}")

        # **Process CVEs in batches of 50 to follow rate limits**
        for i in range(0, len(all_cves), NVD_RATE_LIMIT):
            batch = all_cves[i:i + NVD_RATE_LIMIT]

            for cve_id in batch:
                cve_details = fetch_cve_details(cve_id)

                # **Update vulnerabilities with CVE details**
                for vuln in vulnerabilities:
                    if vuln["vuln_id"] == cve_id:
                        vuln["Description"] = cve_details.get("description")  # ✅ Correctly updating details
                        vuln["CVSS Score"] = cve_details.get("cvss_score")  # ✅ Correctly updating details
                        print(cve_id)
                        print(cve_details)
                        print('\n')

            # **Wait 30 seconds if more than 50 CVEs**
            if i + NVD_RATE_LIMIT < len(all_cves):
                print(f"Rate limit reached. Sleeping for {NVD_SLEEP_TIME} seconds...")
                time.sleep(NVD_SLEEP_TIME)

    except Exception as e:
        print(f"Error scanning vulnerabilities for {ip}: {str(e)}")
    return vulnerabilities





@app.route("/", methods=["GET", "POST"])
def index():
    ip = None
    error = None
    results = None
    
    if request.method == "POST":
        try:
            ip = request.form.get("ip")
            if not ip:
                raise ValueError("Ip address is required")
            
            results = scan_vulnerabilities(ip)
        except ValueError as e:
            error = str(e)
        except Exception as e:
            app.logger.error(f"Error scanning vulnerabilities for {ip}: {str(e)}")
            error = "An error occurred while scanning vulnerabilities."
            
    return render_template("index.html", results=results, ip=ip, error=error)


if __name__ == "__main__":
    app.run(debug=True)
