import nmap
import argparse
import json
import sys

def main():
    # Set up argument parser to handle command-line inputs nicely
    parser = argparse.ArgumentParser(description="Network Reconnaissance Toolkit - A beginner-friendly port scanner.")
    parser.add_argument("target", help="The target IP address or hostname to scan (e.g., 127.0.0.1 or scanme.nmap.org)")
    parser.add_argument("-o", "--output", help="Save the scan results to a JSON file", default="scan_results.json")
    
    args = parser.parse_args()
    target = args.target
    output_file = args.output

    print(f"[*] Starting scan on target: {target}")

    # Initialize the Nmap PortScanner
    # We use a try-except block to gracefully handle cases where Nmap is not installed
    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError:
        print("[-] Error: Nmap is not installed or not found in your system's PATH.")
        print("[-] Please install Nmap from https://nmap.org/download.html and try again.")
        sys.exit(1)
    except Exception as e:
        print(f"[-] An unexpected error occurred: {e}")
        sys.exit(1)

    # Perform the scan
    print("[*] Running Nmap scan... This might take a moment depending on the target.")
    try:
        # '-sV' probes open ports to determine service and version info
        # '-p 1-1000' scans the top 1000 common ports to keep the scan relatively quick
        nm.scan(target, arguments='-sV -p 1-1000')
    except Exception as e:
        print(f"[-] Scan failed: {e}")
        print("[-] Ensure the target is valid, online, and you have permission to scan it.")
        sys.exit(1)

    scan_data = {}

    # Check if the target was actually found and responded
    if not nm.all_hosts():
        print("[-] No hosts found. The target might be down or blocking ping requests.")
        sys.exit(0)

    for host in nm.all_hosts():
        print(f"\n[+] Host: {host} ({nm[host].hostname()})")
        print(f"[+] Status: {nm[host].state()}")
        
        host_info = {
            "hostname": nm[host].hostname(),
            "state": nm[host].state(),
            "ports": []
        }

        # Iterate over all protocols discovered (like 'tcp' or 'udp')
        for proto in nm[host].all_protocols():
            print(f"\n[*] Protocol: {proto.upper()}")
            
            # Get all scanned ports for this protocol
            ports = nm[host][proto].keys()
            
            # Sort the ports so they display in order
            for port in sorted(ports):
                state = nm[host][proto][port]['state']
                name = nm[host][proto][port]['name']
                product = nm[host][proto][port]['product']
                version = nm[host][proto][port]['version']
                
                # We only really care about open ports for our basic recon
                if state == 'open':
                    service_info = f"{name} {product} {version}".strip()
                    print(f"    Port: {port}\tState: {state}\tService: {service_info}")
                    
                    # Add to our dictionary for JSON export later
                    host_info["ports"].append({
                        "port": port,
                        "state": state,
                        "service": name,
                        "product": product,
                        "version": version
                    })
        
        scan_data[host] = host_info

    # Save our findings to a JSON file so we have a record
    try:
        with open(output_file, 'w') as f:
            json.dump(scan_data, f, indent=4)
        print(f"\n[*] Scan complete. Awesome! Results saved to '{output_file}'.")
    except IOError as e:
        print(f"\n[-] Could not save results to file: {e}")

if __name__ == "__main__":
    main()
