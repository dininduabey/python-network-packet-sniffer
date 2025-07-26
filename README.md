🕵️‍♂️ Python Network Packet Sniffer

A lightweight and efficient packet sniffer built with Python and [Scapy](https://scapy.net/), capable of parsing and displaying Ethernet, IPv4, ICMP, TCP, and UDP packets 
in real-time with structured and readable output formatting.

---
📌 Features

- Real-Time Packet Capturing** – Continuously monitors network traffic using `scapy.sniff()`.
- Protocol Awareness** – Identifies and displays packet details based on the protocol (Ethernet, IPv4, ICMP, TCP, UDP).
- Clean Output Formatting** – Uses indented tabs and colorless formatting for easy terminal viewing.
- Hexadecimal Payload Display** – Converts raw packet payload into a readable hex-dump-like format.
- Keyboard Interrupt Exit** – Safely stops sniffing with `Ctrl+C`.

---
🧠 How It Works

1. The program begins sniffing all incoming/outgoing packets using `sniff(prn=process_packet)`.
2. For each captured packet:
   - Ethernet and IPv4 headers are parsed and displayed.
   - Based on the protocol number:
     - **ICMP**: Type, Code, Checksum, and Data are printed.
     - **TCP**: Source/Destination Ports, Flags, Seq/Ack numbers, and Payload.
     - **UDP**: Source/Destination Ports, Length, and Payload.
   - Remaining or unknown protocols are dumped in a readable format.

---
💻 Sample Output
.............................................................................
Ethernet Frame:
Destination: ff:ff:ff:ff:ff:ff, Source: 00:0c:29:4f:8e:35, Protocol: 2048
     -IPv4 Packet:
         -Version: 4, Header Length: 20, TTL: 64
         -Protocol: 6, Source: 192.168.1.5, Target: 192.168.1.10
     -TCP Segment:
         -Source Port: 443, Destination Port: 59724
         -Sequence: 12345, Acknowledgment: 67890
             -Flags: PA
         -Data:
             \x48\x65\x6c\x6c\x6f\x20\x57\x6f\x72\x6c\x64
.............................................................................

Requirements,
  Python 3.x
  Scapy

Installation

# Clone this repo
.............................................................................
git clone https://github.com/yourusername/python-network-packet-sniffer.git
cd python-network-packet-sniffer
.............................................................................

# Install dependencies
.............................................................................
pip install scapy
.............................................................................

Usage,

Run the script as root/admin for access to network interfaces:
.............................................................................
sudo python packet_sniffer.py
.............................................................................

Press Ctrl+C to stop sniffing.

Contributions,

- Feel free to fork this repository, improve it, and submit a pull request! Ideas for improvements:

    Support for IPv6
    Colorized terminal output
    Packet filtering by port or protocol
