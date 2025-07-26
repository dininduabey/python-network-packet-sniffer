from scapy.all import sniff, Ether, IP, ICMP, TCP, UDP
import textwrap

# Formatting tabs
TAB_1 = '\t -'
TAB_2 = '\t\t -'
TAB_3 = '\t\t\t -'
TAB_4 = '\t\t\t\t -'

DATA_TAB_1 = '\t '
DATA_TAB_2 = '\t\t '
DATA_TAB_3 = '\t\t\t '
DATA_TAB_4 = '\t\t\t\t '

def main():
    print("Sniffing packets... Press Ctrl+C to stop.\n")
    sniff(prn=process_packet, store=False)

def process_packet(packet):
    print('\nEthernet Frame:')
    if Ether in packet:
        eth = packet[Ether]
        print(f'Destination: {eth.dst}, Source: {eth.src}, Protocol: {eth.type}')

    if IP in packet:
        ipv4 = packet[IP]
        print(TAB_1 + 'IPv4 Packet:')
        print(TAB_2 + f'Version: 4, Header Length: {ipv4.ihl * 4}, TTL: {ipv4.ttl}')
        print(TAB_2 + f'Protocol: {ipv4.proto}, Source: {ipv4.src}, Target: {ipv4.dst}')

        # ICMP
        if ipv4.proto == 1 and ICMP in packet:
            icmp = packet[ICMP]
            print(TAB_1 + 'ICMP Packet:')
            print(TAB_2 + f'Type: {icmp.type}, Code: {icmp.code}, Checksum: {icmp.chksum}')
            print(TAB_2 + 'Data:')
            print(format_multi_line_string(DATA_TAB_3, bytes(icmp.payload)))

        # TCP
        elif ipv4.proto == 6 and TCP in packet:
            tcp = packet[TCP]
            flags = tcp.sprintf("%TCP.flags%")
            print(TAB_1 + 'TCP Segment:')
            print(TAB_2 + f'Source Port: {tcp.sport}, Destination Port: {tcp.dport}')
            print(TAB_2 + f'Sequence: {tcp.seq}, Acknowledgment: {tcp.ack}')
            print(TAB_3 + f'Flags: {flags}')
            print(TAB_2 + 'Data:')
            print(format_multi_line_string(DATA_TAB_3, bytes(tcp.payload)))

        # UDP
        elif ipv4.proto == 17 and UDP in packet:
            udp = packet[UDP]
            print(TAB_1 + 'UDP Segment:')
            print(TAB_2 + f'Source Port: {udp.sport}, Destination Port: {udp.dport}, Length: {udp.len}')
            print(TAB_2 + 'Data:')
            print(format_multi_line_string(DATA_TAB_3, bytes(udp.payload)))

        # Other
        else:
            print(TAB_1 + 'Other Protocol:')
            print(format_multi_line_string(DATA_TAB_2, bytes(ipv4.payload)))

    elif Ether in packet:
        print('Data:')
        print(format_multi_line_string(DATA_TAB_1, bytes(packet[Ether].payload)))

# Formats multiline data
def format_multi_line_string(prefix, string, size=80):
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])

main()