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
    
    # Split the output into CPE sections
    cpe_sections = vulners_output.strip().split("cpe:/")
    
    for section in cpe_sections:
        if not section.strip():
            continue
            
        # Parse CPE and vulnerabilities
        lines = section.strip().split('\n')
        if not lines:
            continue
            
        # Extract CPE
        cpe_line = lines[0].strip()
        if not cpe_line:
            continue
        cpe = f"cpe:/{cpe_line.rstrip(':')}"
        
        # Process each vulnerability entry
        for line in lines[1:]:
            # Remove leading whitespace and tabs
            line = line.strip()
            if not line:
                continue
                
            # Split the line into components
            parts = [part.strip() for part in re.split(r'\s+', line, maxsplit=3)]
            if len(parts) < 3:
                continue
                
            vuln_id = parts[0]
            cvss_score = parts[1]
            url = parts[2]
            is_exploit = False
            
            # Check if this is marked as an exploit
            if len(parts) > 3 and '*EXPLOIT*' in parts[3]:
                is_exploit = True
            
            vulnerabilities.append({
                'id': vuln_id,
                'cvss': cvss_score,
                'url': url,
                'cpe': cpe,
                'is_exploit': is_exploit
            })
    
    return vulnerabilities

def scan_vulnerabilities(ip):
    nm = nmap.PortScanner()
    
    print(f"Scanning {ip} for vulnerabilities...")
    result = nm.scan(ip, arguments="-sV --script vuln")

    vulnerabilities = []
    for host in nm.all_hosts():
        print(f"Host: {host} ({nm[host].hostname()})")
        for proto in nm[host].all_protocols():
            print(f"Protocol: {proto}")
            ports = nm[host][proto].keys()
            for port in ports:
                port_data = nm[host][proto][port]
                print(port_data)
                service = port_data.get('name', 'unknown')
                version = port_data.get('version', 'unknown')
                state = port_data.get('state', 'unknown')
                product = port_data.get('product', 'unknown')
                
                vuln_scripts = port_data.get('script', {})
                vulners_output = vuln_scripts.get("vulners", "")
                
                if vulners_output:
                    # print(f"\nRaw vulners output for port {port}:")
                    # print("-" * 50)
                    # print(vulners_output)
                    # print("-" * 50)
                    
                    parsed_vulns = parse_vulners_output(vulners_output)
                    
                    if parsed_vulns:
                        for vuln in parsed_vulns:
                            vulnerabilities.append({
                                "port": port,
                                "service": service,
                                "state": state,
                                "product": product,
                                "version": version,
                                "vuln_id": vuln['id'],
                                "cvss_score": vuln['cvss'],
                                "url": vuln['url'],
                                "cpe": vuln['cpe'],
                                "is_exploit": vuln['is_exploit']
                            })
                    else:
                        print(f"No vulnerabilities could be parsed for port {port}")

    return vulnerabilities

def print_vulnerabilities(vulnerabilities):
    if not vulnerabilities:
        print("\nNo vulnerabilities were found or could be parsed.")
        return
        
    # Sort vulnerabilities by CVSS score (highest first)
    sorted_vulns = sorted(vulnerabilities, 
                         key=lambda x: float(x['cvss_score']) if x['cvss_score'].replace('.','').isdigit() else 0, 
                         reverse=True)
    
    print("\nVulnerabilities Report:")
    print("=" * 100)
    print(f"Total vulnerabilities found: {len(sorted_vulns)}")
    print("=" * 100)
    
    # Group by port
    vulns_by_port = {}
    for vuln in sorted_vulns:
        port = vuln['port']
        if port not in vulns_by_port:
            vulns_by_port[port] = []
        vulns_by_port[port].append(vuln)
    
    for port, port_vulns in vulns_by_port.items():
        print(f"\nPort {port} - {port_vulns[0]['service']} ({port_vulns[0]['product']} {port_vulns[0]['version']})")
        print(f"CPE: {port_vulns[0]['cpe']}")
        print("-" * 100)
        
        # Print high severity vulnerabilities first
        print("Critical/High Severity (CVSS >= 7.0):")
        high_vulns = [v for v in port_vulns if float(v['cvss_score']) >= 7.0]
        for vuln in high_vulns:
            print(f"  - {vuln['vuln_id']} (CVSS: {vuln['cvss_score']}) {'*EXPLOIT*' if vuln['is_exploit'] else ''}")
            print(f"    URL: {vuln['url']}")
        
        # Print medium/low severity vulnerabilities
        print("\nMedium/Low Severity (CVSS < 7.0):")
        low_vulns = [v for v in port_vulns if float(v['cvss_score']) < 7.0]
        for vuln in low_vulns:
            print(f"  - {vuln['vuln_id']} (CVSS: {vuln['cvss_score']}) {'*EXPLOIT*' if vuln['is_exploit'] else ''}")
            print(f"    URL: {vuln['url']}")

def main():
    target_ips = ["10.3.100.60"]
    
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
