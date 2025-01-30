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
load_dotenv()

app = Flask(__name__)

VULNERS_URL = "https://vulners.com/api/v3/search/id/"
VULNERS_API_KEY = os.getenv("VULNERS_API_KEY")


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
        nm = nmap.PortScanner()
        nm.scan(ip, arguments="-sV --script vulners --max-rate 100")
        
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
                            for vuln in vulns:
                                vuln_details = fetch_vulnerability_details(vuln)
                                if vuln_details:
                                    vulnerabilities.append({
                                        "port": port,
                                        "service": service,
                                        "product": product,
                                        "version": version,
                                        "vuln_id": vuln,
                                        "details": vuln_details
                                    })
                    except Exception as e:
                        app.logger.error(f"Error processing port {port}: {str(e)}")
                        continue
                            
        return vulnerabilities
    except Exception as e:
        app.logger.error(f"Scan failed: {str(e)}")
        raise
    #                 for vuln_id in vulners_output.split("\n"):
    #                     if vuln_id.strip():
    #                         vuln_details = fetch_vulnerability_details(vuln_id)
    #                         vulnerabilities.append({
    #                             "port": port,
    #                             "service": service,
    #                             "product": product,
    #                             "version": version,
    #                             "vuln_id": vuln_id,
    #                             "details": vuln_details
    #                         })
    # return vulnerabilities


def fetch_vulnerability_details(vuln_id):
    """Fetch vulnerability details from Vulners API"""
    if not VULNERS_API_KEY:
        raise ValueError("Vulners API key is not configured.")
    try:
    #     response = requests.get(f"{VULNERS_URL}?id={vuln_id}&apiKey={VULNERS_API_KEY}")
    #     data = response.json()
    #     if "data" in data and data["data"]:
    #         return data["data"].get("description", "No description available.")
    # except Exception as e:
    #     print(f"Error fetching details for {vuln_id}: {e}")
    # return "No details found."
        headers = {
            'User-Agent': 'Security Scanner/1.0',
            'Accept': 'application/json'
        }
        
        params = {
            'id': vuln_id,
            'apiKey': VULNERS_API_KEY
        }
        
        response = requests.get(
            VULNERS_URL,
            params=params,
            headers=headers,
            timeout=10
        )
        
        response.raise_for_status()
        data = response.json()
        
        if "data" in data and data["data"]:
            return data["data"].get("description", "No description available.")
            
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Error fetching details for {vuln_id}: {str(e)}")
        
    except json.JSONDecodeError as e:
        app.logger.error(f"Error parsing response for {vuln_id}: {str(e)}")
        
    return None

@app.route("/", methods=["GET", "POST"])
def index():
    ip = None
    error = None
    results = None
    
    if request.method == "POST":
        try:
            ip = request.form.get("ip").strip()
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
