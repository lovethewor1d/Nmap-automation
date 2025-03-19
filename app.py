import subprocess
import pandas as pd
import xml.etree.ElementTree as ET
import os
import requests
import json
import streamlit as st
import re

def get_cipher_security_info():
    try:
        req = requests.get('https://ciphersuite.info/api/cs')
        data = json.loads(req.text)['ciphersuites']
        cipherdict = {}
        for cipher in data:
            cipherdict["".join(cipher.keys())] = list(cipher.values())
        return cipherdict
    except requests.exceptions.RequestException as e:
        st.error(f"Error fetching cipher security info: {e}")
        return {}

def perform_nmap_scan(ip, scan_type):
    st.write(f"\nStarting {scan_type} scan for {ip}...\n")
    
    if scan_type == 'full':
        command = f"nmap -p- -Pn -oA {ip}-full-scan {ip}"
    else:
        command = f"nmap -sC -sV -p- -Pn -oA {ip}-detailed-scan {ip}"
    subprocess.run(command, shell=True, check=True)

def parse_nmap_results(ip, nmap_results_file):
    if not os.path.exists(nmap_results_file):
        st.error(f"Error: {nmap_results_file} not found.")
        return []
    
    root = ET.parse(nmap_results_file).getroot()
    open_services = []

    for port in root.findall(".//port"):
        port_id = port.attrib['portid']
        state = port.find(".//state").attrib['state']
        
        if state == 'open':
            service = port.find(".//service")
            service_name = service.attrib['name'] if service is not None else 'Unknown'
            open_services.append((port_id, service_name))
    
    return open_services

def run_nse_script(ip, port_id, service_name, cipherdict):
    st.write(f"Running NSE script on {ip}:{port_id} for service {service_name}. Please check the output file.\n")
    
    nse_scripts = {
        "http": "ssl-enum-ciphers,http-methods,ssl-cert",
        "ftp": "ftp-anon,ftp-bounce,ftp-syst",
        "ssh": "ssh2-enum-algos,ssh-auth-methods",
        "smtp": "smtp* --script-args=safe",
        "rdp": "rdp-enum-encryption,rdp-ntlm-info,ssl-enum-ciphers",
        "dns": "dns* --script-args=safe",
        "ntp": "ntp-info,ntp-monlist",
        "telnet": "telnet-*",
        "snmp": "snmp* --script-args='not snmp-brute'",
        "smb": "smb-* --script-args=safe"
    }

    service_patterns = {
        "http": [r"http", r"https", r"ssl", r"tls", r"http-proxy", r"http-alt"],
        "smb": [r"smb", r"msrpc", r"netbios-ns", r"netbios-ssn", r"microsoft-ds"],
        "ssh": [r"ssh"],
        "ftp": [r"ftp"],
        "rdp": [r"ms-wbt-server", r"rdp"],
        "dns": [r"dns"],
        "smtp": [r"smtp"],
        "ntp": [r"ntp"],
        "telnet": [r"telnet"],
        "snmp": [r"snmp"]
    }

    for service_type, patterns in service_patterns.items():
        for pattern in patterns:
            if re.search(pattern, service_name, re.IGNORECASE):
                nmap_command = f"nmap -p {port_id} --script {nse_scripts[service_type]} -Pn {ip} -oA {ip}-{port_id}-{service_name}-nse-results"
                subprocess.run(nmap_command, shell=True, check=True)
                parse_service_nse_results(ip, f"{ip}-{port_id}-{service_name}-nse-results.xml", cipherdict, service_name)
                return
    else:
        st.warning(f"No NSE script configured for {service_name}.")

def parse_service_nse_results(ip, nse_results_file, cipherdict, service_name):
    if not os.path.exists(nse_results_file):
        st.error(f"Error: {nse_results_file} not found.")
        return

    try:
        with open(nse_results_file, 'r') as file:
            content = file.read()
            if not content.strip():
                st.error(f"Error: {nse_results_file} is empty.")
                return
            
            root = ET.ElementTree(ET.fromstring(content)).getroot()
    except ET.ParseError as e:
        st.error(f"Error: Failed to parse XML from {nse_results_file}. Please check the file content.")
        st.error(f"Details: {e}")
        return
    except Exception as e:
        st.error(f"Unexpected error while reading {nse_results_file}: {e}")
        return

    if service_name in ['https', 'ssl', 'http', 'tls']:
        st.write(f"\nSSL/TLS Cipher Details for {service_name} on {ip}:")
        ciphers = []

        for port in root.findall(".//ports/port"):
            port_id = port.attrib['portid']
            script = port.find(".//script[@id='ssl-enum-ciphers']")

            if script is not None:
                for table in script.findall(".//table"):
                    for cipher in table.findall(".//table"):
                        cipher_name_elem = cipher.find(".//elem[@key='name']")
                        kex_info_elem = cipher.find(".//elem[@key='kex_info']")
                        strength_elem = cipher.find(".//elem[@key='strength']")

                        if cipher_name_elem is not None and kex_info_elem is not None and strength_elem is not None:
                            cipher_name = cipher_name_elem.text
                            kex_info = kex_info_elem.text
                            strength = strength_elem.text
                            security_info = cipherdict.get(cipher_name, [{"security": "Unknown"}])[0]['security']
                            
                            ciphers.append([ip, port_id, cipher_name, kex_info, strength, security_info])
        
        if ciphers:
            df = pd.DataFrame(ciphers, columns=["IP Address", "Port", "Cipher", "Key Exchange", "Strength", "Security"])
            st.dataframe(df)
        else:
            st.warning("No cipher details found in the NSE scan results.")

def main():
    st.title('Nmap Automation')

    cipherdict = get_cipher_security_info()

    option = st.radio("Choose an option:", ("Scan a new IP", "Upload an existing SSL cipher file"))

    if option == "Scan a new IP":
        ip = st.text_input("Enter the IP address to scan:")
        scan_type = st.selectbox("Do you want to run a 'full' scan (-p-) or a 'detailed' scan (-sC -sV)?", ['full', 'detailed'])

        if st.button('Start Scan'):
            if ip:
                perform_nmap_scan(ip, scan_type)
                nmap_results_file = f"{ip}-{'full' if scan_type == 'full' else 'detailed'}-scan.xml"
                open_services = parse_nmap_results(ip, nmap_results_file)

                for port_id, service_name in open_services:
                    run_nse_script(ip, port_id, service_name, cipherdict)
            else:
                st.error("Please provide a valid IP address.")

    elif option == "Upload an existing SSL cipher file":
        uploaded_files = st.file_uploader("Upload your SSL cipher file (XML):", type=["xml"], accept_multiple_files=True)

        if uploaded_files:
            all_ciphers = []
        
            for uploaded_file in uploaded_files:
                try:
                    tree = ET.parse(uploaded_file)
                    root = tree.getroot()
                    ip_address = root.find(".//address[@addrtype='ipv4']").attrib['addr']
                    hostnames = [hostname.text for hostname in root.findall(".//hostnames/hostname")]
                    for port in root.findall(".//ports/port"):
                        port_id = port.attrib['portid']
                        script = port.find(".//script[@id='ssl-enum-ciphers']")
        
                        if script is not None:
                            for tls_version in ["TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3"]:
                                version_table = script.findall(f".//table[@key='{tls_version}']")
        
                                for table in version_table:
                                    cipher_table = table.find(".//table[@key='ciphers']")
                                    for cipher in cipher_table.findall("table"):
                                        cipher_name = cipher.find(".//elem[@key='name']").text
                                        kex_info = cipher.find(".//elem[@key='kex_info']").text
                                        strength = cipher.find(".//elem[@key='strength']").text
                                        security = cipherdict.get(cipher_name, [{"security": "Unknown"}])[0]['security']
                                        all_ciphers.append([ip_address, port_id, cipher_name, kex_info, strength, tls_version, security])
        
                except ET.ParseError as e:
                    st.error(f"Error parsing XML file {uploaded_file.name}: {e}")
        
            if all_ciphers:
                df = pd.DataFrame(all_ciphers, columns=["IP Address", "Port", "Cipher", "Key Exchange", "Strength", "TLS Version", "Security"])
                st.dataframe(df)
            else:
                st.warning("No cipher details found in the uploaded XML files.")

if __name__ == "__main__":
    main()
