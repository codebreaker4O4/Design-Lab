import nmap
import ipaddress
import json
import re  

def parse_vulners_output(vulners_output):
    """
    Parse the vulners script output in CPE-based format.
    Returns a list of vulnerability dictionaries.
    """
    vulnerabilities = []
    
    # Try to parse as JSON first
    try:
        return json.loads(vulners_output)
    except json.JSONDecodeError:
        pass
    
    # Parse CPE-based format
    # Split by CPE entries
    cpe_entries = vulners_output.split("cpe:/")
    
    for entry in cpe_entries:
        if not entry.strip():
            continue
            
        # Parse individual vulnerabilities
        lines = entry.split('\n')
        cpe = f"cpe:/{lines[0].strip()}" if lines[0].strip() else "unknown"
        
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
                
            # Match the ID, CVSS score, and URL pattern
            pattern = r'\s*([\w-]+)\s+([\d.]+)\s+(https://[\S]+)(?:\s+\*EXPLOIT\*)?'
            match = re.match(pattern, line)
            
            if match:
                vuln_id = match.group(1)
                cvss_score = match.group(2)
                url = match.group(3)
                
                vulnerabilities.append({
                    'id': vuln_id,
                    'cvss': cvss_score,
                    'description': f"Associated with {cpe}. More info: {url}",
                    'cpe': cpe,
                    'url': url
                })
    
    return vulnerabilities

def scan_vulnerabilities(ip):
    nm = nmap.PortScanner()
    
    # Run a vulnerability scan
    print(f"Scanning {ip} for vulnerabilities...")
    result = nm.scan(ip, arguments="-sV --script vuln")

    # Parse results
    vulnerabilities = []
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = nm[host][proto].keys()
            for port in ports:
                port_data = nm[host][proto][port]
                service = port_data.get('name', 'unknown')
                version = port_data.get('version', 'unknown')
                state = port_data.get('state', 'unknown')
                product = port_data.get('product', 'unknown')
                # print(f"Port: {port}\t State: {state} \tService: {service} \tProduct: {product} \tVersion: {version}")
            # Check if the port has vulnerabilities
                vuln_scripts = port_data.get('script', {})
                vulners_output = vuln_scripts.get("vulners", "")
                
                # If there is vulners output, extract data
                if vulners_output:
                    print(f"Raw vulners output for port {port}:")
                    print("-" * 50)
                    print(vulners_output)
                    print("-" * 50)
                    # Debugging
                    
                    
                    parsed_vulns = parse_vulners_output(vulners_output)

                    if parsed_vulns:
                        for vuln in parsed_vulns:
                            vulnerabilities.append({
                                "port": port,
                                "service": service,
                                "state": state,
                                "product": product,
                                "version": version,
                                "vuln_id": vuln.get('id', 'N/A'),
                                "cvss_score": vuln.get('cvss', 'N/A'),
                                "description": vuln.get('description', 'No description'),
                                "cpe": vuln.get('cpe', 'N/A'),
                                "url": vuln.get('url', 'N/A')
                            })
                    else:
                        print(f"No vulnerabilities could be parsed for port {port}")

    return vulnerabilities
    
def print_vulnerabilities(vulnerabilities):
    if not vulnerabilities:
        print("\nNo vulnerabilities were found or could be parsed.")
        return
        
    print("\nVulnerabilities Report:")
    print("-" * 80)
    
    # Sort vulnerabilities by CVSS score (highest first)
    sorted_vulns = sorted(vulnerabilities, 
                         key=lambda x: float(x['cvss_score']) if isinstance(x['cvss_score'], (int, float, str)) else 0, 
                         reverse=True)
    
    def print_vulnerabilities(vulnerabilities):
        if not vulnerabilities:
            print("\nNo vulnerabilities were found or could be parsed.")
            return
            
        print("\nVulnerabilities Report:")
        print("-" * 80)
        
        # Sort vulnerabilities by CVSS score (highest first)
        sorted_vulns = sorted(vulnerabilities, 
                            key=lambda x: float(x['cvss_score']) if isinstance(x['cvss_score'], (int, float, str)) else 0, 
                            reverse=True)
        
        for vuln in sorted_vulns:
            print(f"""
            Port: {vuln['port']}
            Service: {vuln['service']} ({vuln['product']} {vuln['version']})
            State: {vuln['state']}
            CPE: {vuln['cpe']}
            Vulnerability ID: {vuln['vuln_id']}
            CVSS Score: {vuln['cvss_score']}
            URL: {vuln['url']}
            Description: {vuln['description']}
            """)
            print("-" * 80)


def main():
    target_ips = ["10.3.100.100", 
                #   "10.3.100.60"
                  ]
    for ip in target_ips:
        try:
            ip_address_obj = ipaddress.ip_address(ip)
            print(f"Scanning valid IP address: {ip}")
            vulnerabilities = scan_vulnerabilities(ip)
            print_vulnerabilities(vulnerabilities)
        except ValueError:
            print(f"Invalid IP address: {ip}")
    
if __name__ == "__main__":
    main()
