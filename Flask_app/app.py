from flask import Flask, render_template, request, jsonify
import nmap
import requests
import json
import os
import re
from functools import wraps
from dotenv import load_dotenv
import ipaddress

# Load environment variables from.env file
# load_dotenv()

app = Flask(__name__)

# VULNERS_URL = "https://vulners.com/api/v3/search/id/"
# VULNERS_API_KEY = os.getenv("VULNERS_API_KEY")

# if not VULNERS_API_KEY:
#     print("VULNERS_API_KEY is not set or is empty!")
# else:
#     print("VULNERS_API_KEY is loaded successfully.")

def parse_vulners_output(output):
    """Parse and sanitize Vulners script output."""
    if not output:
        return []
    
    vulns = []
    for line in output.split("\n"):
        vuln_id = line.strip()
        if vuln_id and re.match(r'^[A-Za-z0-9-_]+$', vuln_id):
            vulns.append(vuln_id)
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
        print(f"Scan Results: {nm.all_hosts()}")  # Debugging

        vulnerabilities = []
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
                        vulners_output = vuln_scripts.get("vulners", "")
                        
                        if vulners_output:
                            vulns = parse_vulners_output(vulners_output)
                        for vuln_id in vulners_output.split("\n"):
                            if vuln_id.strip():
                                # vuln_details = fetch_vulnerability_details(vuln_id)
                                vulnerabilities.append({
                                    "port": port,
                                    "service": service,
                                    "product": product,
                                    "version": version,
                                    "vuln_id": vuln_id,
                                    "details": "None"
                                })
                          
                    except Exception as e:
                        print(f"Error fetching vulnerability details for {vuln_id} on port {port}: {str(e)}")
    except Exception as e:
        app.logger.error(f"Error scanning vulnerabilities for {ip}: {str(e)}")
        print("Error")
    return vulnerabilities



# def fetch_vulnerability_details(vuln_id):
#     """Fetch vulnerability details from Vulners API"""
#     if not VULNERS_API_KEY:
#         raise ValueError("Vulners API key is not configured.")
#     try:
#         response = requests.get(f"{VULNERS_URL}?id={vuln_id}&apiKey={VULNERS_API_KEY}")
#         data = response.json()
#         if "data" in data and data["data"]:
#             print(f"Request URL: {response.url}")  # Debugging
#             print(f"Response Code: {response.status_code}")  # Debugging
#             print(f"Response JSON: {response.text}")  # Debugging
#             return data["data"].get("description", "No description available.")
#     except Exception as e:
#         print(f"Error fetching details for {vuln_id}: {e}")
#         print(f"Error fetching details for {vuln_id}")
#         return "No details found."
        


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
