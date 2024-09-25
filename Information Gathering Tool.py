import sys
import socket
import requests
import json
import argparse
import nmap

# Function to get the IP address of the domain
def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        print(f"Unable to get IP address for domain: {domain}")
        sys.exit()

# Function to get location information of an IP address
def get_location_info(ip_address):
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        print(f"Error retrieving location information: {e}")
        sys.exit()

# Function to scan ports using nmap
def nmap_scan(host_id, port_num):
    nm_scan = nmap.PortScanner()
    try:
        nm_scan.scan(host_id, port_num, arguments="-T4")  # T4 increases the speed of the scan
        state = nm_scan[host_id]['tcp'][int(port_num)]['state']  # Indicate the type of scan and port number
        result = ("[*] {host} tcp/{port} {state}".format(host=host_id, port=port_num, state=state))
        return result
    except KeyError:  # If Nmap fails to scan the port, handle the error
        return f"Error: No result for port {port_num} on host {host_id}"

# Function to parse arguments for host and ports
def argument_parser():
    parser = argparse.ArgumentParser(description="Domain info and TCP port scanner.")
    parser.add_argument("-o", "--host", nargs="?", help="Host domain name", required=True)
    parser.add_argument("-p", "--ports", nargs="?", help="Comma-separated port list, such as '25,80,8080'", required=True)

    var_args = vars(parser.parse_args())  # Convert argument namespace to dictionary
    return var_args

# Main function to coordinate the process
def main():
    try:
        user_args = argument_parser()
        domain = user_args["host"]
        ports = user_args["ports"].split(",")  # Make a list from port numbers

        # Get IP address from the domain
        ip_address = get_ip_address(domain)

        # Get location info from the IP address
        location_info = get_location_info(ip_address)

        # Output domain, IP address, and location info
        print(json.dumps({
            "domain": domain,
            "ip_address": ip_address,
            "location_info": location_info
        }, indent=4))

        # Perform Nmap scan on the provided ports
        print("\nStarting Nmap scan:")
        for port in ports:
            print(nmap_scan(ip_address, port))

    except AttributeError:
        print("Error: Please provide the correct host and port(s).")
    except KeyboardInterrupt:
        print("\nScan interrupted. Exiting...")

if __name__ == '__main__':
    main()
