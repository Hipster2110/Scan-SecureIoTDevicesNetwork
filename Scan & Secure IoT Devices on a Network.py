import nmap
import scapy.all as scapy

# Function to scan network for IoT devices
def scan_network(network_range):
    print(f"Scanning {network_range} for IoT devices...\n")
    arp_request = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices = []
    for packet in answered_list:
        device = {"IP": packet[1].psrc, "MAC": packet[1].hwsrc}
        devices.append(device)

    return devices

# Function to scan ports of discovered IoT devices
def scan_ports(ip):
    scanner = nmap.PortScanner()
    scanner.scan(ip, '1-65535', '-sV')  # Scan all ports (1-65535)
    open_ports = []

    for port in scanner[ip]['tcp']:
        if scanner[ip]['tcp'][port]['state'] == 'open':
            open_ports.append(port)

    return open_ports

# Main function
if __name__ == "__main__":
    network = "192.168.1.1/24"  # Change this to your network range
    devices = scan_network(network)

    print("\nDiscovered IoT Devices:")
    for device in devices:
        print(f"IP: {device['IP']}, MAC: {device['MAC']}")
        open_ports = scan_ports(device["IP"])
        print(f"Open Ports: {open_ports}\n")

    # Save results to a log file
    with open("iot_scan_results.txt", "w") as file:
        for device in devices:
            file.write(f"IP: {device['IP']}, MAC: {device['MAC']}\n")
            open_ports = scan_ports(device["IP"])
            file.write(f"Open Ports: {open_ports}\n\n")

    print("\nScan complete! Results saved in 'iot_scan_results.txt'")
