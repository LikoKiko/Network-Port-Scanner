import socket
import ipaddress
import logging
from datetime import datetime

logging.basicConfig(filename='scan.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
def chk_port(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        res = s.connect_ex((ip, port))
        return res == 0

def scan_ips(ipr):
    open_ports = []
    for ip in ipaddress.IPv4Network(ipr):
        logging.info(f"Scanning IP: {ip}")
        for port in range(1, 65536):
            if chk_port(str(ip), port):
                open_ports.append((str(ip), port))
                logging.warning(f"Open port found: {ip}:{port}")
    return open_ports

if __name__ == "__main__":
    ipr = "192.168.1.0/24"
    logging.info("Starting network scan")
    open_ports = scan_ips(ipr)
    if open_ports:
        print("Open ports detected:")
        for ip, port in open_ports:
            print(f"{ip}:{port}")
    else:
        print("No open ports detected.")
    logging.info("Network scan completed")
