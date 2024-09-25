This Python script retrieves information about a given domain by performing the following tasks:

Get IP Address: Resolves the IP address for a specified domain.
IP Geolocation: Fetches location data (e.g., city, region, country) using the ipinfo.io API for the resolved IP address.
Port Scanning: Scans specified TCP ports using Nmap to check their status (open, closed, etc.).
The script is designed to be used from the command line with arguments for the domain and a comma-separated list of ports.

Features:
Uses socket to resolve domain to IP.
Fetches geolocation using requests from ipinfo.io.
Leverages nmap to scan ports for the given IP.
Error handling for invalid domain/IP and unavailable services.

Usage:
python script.py --host <domain_name> --ports <port_list>

Example:
python script.py --host example.com --ports 80,443,8080

Dependencies:
socket, requests, nmap, argparse, json
This script is useful for basic network reconnaissance or troubleshooting.
