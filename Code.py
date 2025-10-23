import sys
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP

# Function to handle each packet
def handle_packet(packet, flag, log):
    # Check if the packet contains TCP layer
    if (flag==1):
        if packet.haslayer(TCP):
            # Extract source and destination IP addresses
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # Extract source and destination ports
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            # Write packet information to log file
            log.write(f"TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")
    
    #UDP
    elif(flag==2):
        if packet.haslayer(UDP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # Extract source and destination ports
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            # Write packet information to log file
            log.write(f"UDP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")
    
    #both        
    else:
        if packet.haslayer(TCP):
            # Extract source and destination IP addresses
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # Extract source and destination ports
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            # Write packet information to log file
            log.write(f"TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")
            
        if packet.haslayer(UDP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # Extract source and destination ports
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            # Write packet information to log file
            log.write(f"UDP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")

#verbose mode
def handle_packetv(packet, flag, log, verbose):
    # Check if the packet contains TCP layer
    if (flag==1):
        if packet.haslayer(TCP):
            # Extract source and destination IP addresses
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # Extract source and destination ports
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            Pflags=packet[TCP].flags
            # Write packet information to log file
            log.write(f"TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port} : Flags {Pflags}\n")
    
    elif(flag==2):
        if packet.haslayer(UDP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # Extract source and destination ports
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            # Write packet information to log file
            log.write(f"UDP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")
            
    else:
        if packet.haslayer(TCP):
            # Extract source and destination IP addresses
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # Extract source and destination ports
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            Pflags=packet[TCP].flags
            # Write packet information to log file
            log.write(f"TCP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port} : Flags {Pflags}\n")
            
        if packet.haslayer(UDP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            # Extract source and destination ports
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            # Write packet information to log file
            log.write(f"UDP Connection: {src_ip}:{src_port} -> {dst_ip}:{dst_port}\n")

# Main function to start packet sniffing
def main(interface, packet, verbose=False):
    # Create log file name based on interface
    if(packet=="TCP"):
        flag=1
    elif(packet=="UDP"):
        flag=2
    else:
        flag=0
    logfile_name = f"sniffer_{interface}_log.txt"
    # Open log file for writing
    print("Capturing packets in "+interface+" interface with packet "+packet)
    print("Flag is : ",format(flag))
    with open(logfile_name, 'w') as logfile:
        try:
            if verbose:
                sniff(iface=interface, prn=lambda pkt: handle_packetv(pkt, flag, logfile, verbose), store=0)
            # Start packet sniffing on specified interface with verbose output
            else:
                sniff(iface=interface, prn=lambda pkt: handle_packet(pkt, flag, logfile), store=0)
        except KeyboardInterrupt:
            sys.exit(0)

    # Check if the script is being run directly
if __name__ == "__main__":
    # Check if the correct number of arguments is provided
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Usage: python sniffer.py <interface> <packet type> <verbose>")
        print("Interfaces supported : eth0 -> Ethernet, lo -> Loopback")
        print("Packet types supported : TCP, UDP, All")
        sys.exit(1)
    # Determine if verbose mode is enabled
    verbose = False
    if len(sys.argv) == 4 and sys.argv[3].lower() == "verbose":
        verbose = True
    # Call the main function with the specified interface and verbose option
    main(sys.argv[1],sys.argv[2],verbose)
