# IoT Network Scanner

## Overview
The **IoT Network Scanner** is a Python-based tool designed to scan a network for IoT devices, detect open ports, and log the results for further analysis.

## Features
- **Network Scanning**: Detects IoT devices on a specified network range using ARP requests.
- **Port Scanning**: Identifies open ports on discovered devices using Nmap.
- **Results Logging**: Saves scan results to `iot_scan_results.txt`.

## Prerequisites
Ensure you have the following dependencies installed before running the script:

- **Python 3.x**
- **Scapy** (`pip install scapy`)
- **Nmap** (`apt install nmap` or `brew install nmap`)
- **python-nmap** (`pip install python-nmap`)

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/Hipster2110/Scan-SecureIoTDevicesNetwork.git
   cd Scan-SecureIoTDevicesNetwork
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the tool:
   ```bash
   sudo python iot_scanner.py
   ```
   > **Note:** Running as **root** is required for network scanning.

## Usage
1. Change the network range in the script (default: `192.168.1.1/24`).
2. Run the script, and it will:
   - Detect IoT devices.
   - Scan for open ports.
   - Save results to `iot_scan_results.txt`.

## Example Output
```
Scanning 192.168.1.1/24 for IoT devices...

Discovered IoT Devices:
IP: 192.168.1.10, MAC: AA:BB:CC:DD:EE:FF
Open Ports: [22, 80]

✅ Scan complete! Results saved in 'iot_scan_results.txt'
```

## Known Issues
- Requires **sudo/root** privileges for full functionality.
- Large network scans may take time.
- Ensure **Nmap** is installed before running the script.

## Future Enhancements
- Add **device fingerprinting** to detect IoT device types.
- Provide **CSV and JSON export options**.
- Implement **multi-threading** for faster scanning.

## License
This project is licensed under the MIT License.

## Author
Developed by **Hipster2110**. Contributions and feedback are welcome!

## Repository Link
[GitHub Repository](https://github.com/Hipster2110/Scan-SecureIoTDevicesNetwork.git)

## Disclaimer
This tool is intended for **ethical security testing** only. Do not use it on networks without proper authorization!

