import socket  # Retained for reference, not directly used in Scapy-based implementation
import struct  # Optional: for any future low-level packet parsing
from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, Dot1Q
# import requests  # For IP geolocation
import ipaddress  # For private IP checking

# Function to check if an IP is private
def is_private_ip(ip):
    private_ips = [
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16")
    ]
    return any(ipaddress.IPv4Address(ip) in network for network in private_ips)


# Unpacking Ethernet Frame (Data Link Layer)
def parse_ethernet_frame(packet):
    src_mac = packet[Ether].src
    dest_mac = packet[Ether].dst
    proto = packet[Ether].type

    # Check for VLAN tagging (Dot1Q)
    vlan_id = None
    if Dot1Q in packet:
        vlan_id = packet[Dot1Q].vlan
        proto = packet[Dot1Q].type  # Update protocol type after VLAN header

    return src_mac, dest_mac, proto, vlan_id

# Unpacking IPv4 Packet (Network Layer)
def parse_ipv4_packet(packet):
    src_ip = packet[IP].src
    dest_ip = packet[IP].dst
    ttl = packet[IP].ttl
    proto = packet[IP].proto
    flags = packet[IP].flags
    return src_ip, dest_ip, ttl, proto, flags

# Unpacking IPv6 Packet (Network Layer)
def parse_ipv6_packet(packet):
    src_ip = packet[IPv6].src
    dest_ip = packet[IPv6].dst
    return src_ip, dest_ip

# Unpacking TCP Segment (Transport Layer)
def parse_tcp_segment(packet):
    src_port = packet[TCP].sport
    dest_port = packet[TCP].dport
    seq = packet[TCP].seq
    ack = packet[TCP].ack
    window_size = packet[TCP].window  # TCP Window Size
    flags = packet[TCP].flags  # TCP Flags (SYN, ACK, FIN, etc.)
    return src_port, dest_port, seq, ack, window_size, flags

# Unpacking UDP Segment (Transport Layer)
def parse_udp_segment(packet):
    src_port = packet[UDP].sport
    dest_port = packet[UDP].dport
    length = packet[UDP].len
    return src_port, dest_port, length

# Unpacking Application Layer (Raw Data)
def parse_application_data(packet):
    if packet.payload:
        try:
            return bytes(packet.payload).decode('utf-8', 'ignore')
        except:
            return bytes(packet.payload).hex()
    return None

# Sniff HTTP Addresses (Application Layer Enhancement)
def sniff_http_addresses(packet):
    if TCP in packet and packet[TCP].dport == 80:  # HTTP typically uses port 80
        # Check for HTTP request and extract the host
        try:
            raw_data = bytes(packet[TCP].payload)
            if b'GET' in raw_data or b'POST' in raw_data:
                # Extract Host header if present (i.e., domain name of the HTTP request)
                headers = raw_data.decode('utf-8', 'ignore').split("\r\n")
                for header in headers:
                    if header.startswith("Host:"):
                        host = header.split(":")[1].strip()
                        print(f"  HTTP Host: {host}")
                        break
        except Exception as e:
            print(f"  HTTP Parsing Error: {e}")

# Callback function to process each packet
def process_packet(packet):
    print("\n=== New Packet Captured ===")

    # Data Link Layer (Ethernet)
    if Ether in packet:
        src_mac, dest_mac, proto, vlan_id = parse_ethernet_frame(packet)
        print("Ethernet Frame:")
        print(f"  Source MAC: {src_mac}, Destination MAC: {dest_mac}, Protocol: {proto}")
        if vlan_id is not None:
            print(f"  VLAN ID: {vlan_id}")

    # Network Layer (IPv4)
    if IP in packet:
        src_ip, dest_ip, ttl, proto, flags = parse_ipv4_packet(packet)
        print("IPv4 Packet:")
        print(f"  Source IP: {src_ip}, Destination IP: {dest_ip}, TTL: {ttl}, Protocol: {proto}")
        
        # Check if IP is private or public
        ip_type = "Private" if is_private_ip(src_ip) else "Public"
        print(f"  Source IP Type: {ip_type}")

        # # Get geolocation information
        # geo_location = get_geolocation(src_ip)
        # print(f"  Geolocation: {geo_location}")
        
        # Checksum Validation
        checksum = packet[IP].chksum
        print(f"  Checksum: {checksum} (Validation: {'Valid' if checksum == 0 else 'Invalid'})")
        
        # Path MTU Discovery: Check "Don't Fragment" flag
        if flags == 2:
            print("  Path MTU Discovery: Don't Fragment (DF) set")
        
        # Transport Layer (TCP)
        if TCP in packet:
            src_port, dest_port, seq, ack, window_size, flags = parse_tcp_segment(packet)
            print("TCP Segment:")
            print(f"  Source Port: {src_port}, Destination Port: {dest_port}")
            print(f"  Sequence Number: {seq}, Acknowledgment Number: {ack}")
            print(f"  Window Size: {window_size}")
            print(f"  Flags: {flags}")
            
            # TCP Connection State based on flags
            if "S" in flags:
                print("  Connection State: SYN Sent")
            elif "A" in flags:
                print("  Connection State: ACK Sent")
            elif "F" in flags:
                print("  Connection State: FIN Sent")
            
            # Retransmissions and Duplicate ACKs based on sequence and acknowledgment numbers
            if seq == ack:
                print("  Duplicate ACK detected (potential retransmission)")

        # Transport Layer (UDP)
        elif UDP in packet:
            src_port, dest_port, length = parse_udp_segment(packet)
            print("UDP Segment:")
            print(f"  Source Port: {src_port}, Destination Port: {dest_port}, Length: {length}")

        # Application Layer (Sniffing HTTP Addresses)
        sniff_http_addresses(packet)

        # Application Layer Data
        app_data = parse_application_data(packet)
        if app_data:
            print("Application Layer Data:")
            print(f"  {app_data}")

    # Network Layer (IPv6)
    elif IPv6 in packet:
        src_ip, dest_ip = parse_ipv6_packet(packet)
        print("IPv6 Packet:")
        print(f"  Source IP: {src_ip}, Destination IP: {dest_ip}")

# Main Sniffer Function
def main():
    print("Starting Packet Sniffer...")
    print("Press Ctrl+C to stop.")

    # Start sniffing packets on the active network interface
    sniff(prn=process_packet, iface="en6", store=False)

if __name__ == "__main__":
    main()
