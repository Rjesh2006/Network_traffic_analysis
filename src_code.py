from scapy.all import sniff, IP, TCP, UDP
from scapy.arch.windows import get_windows_if_list
import binascii
import matplotlib.pyplot as plt
from collections import Counter
from tabulate import tabulate

class PacketSniffer:
    def __init__(self):
        self.packet_counts = Counter({'TCP': 0, 'UDP': 0, 'Others': 0})
        self.packet_count = 0

    def update_plots(self):
        plt.clf()

        # Plot bar chart
        plt.subplot(1, 2, 1)
        plt.bar(self.packet_counts.keys(), self.packet_counts.values(), color=['blue', 'green', 'red'])
        plt.xlabel('Protocol')
        plt.ylabel('Packet Count')
        plt.title('Real-time Packet Count by Protocol')

        # Plot pie chart
        plt.subplot(1, 2, 2)
        labels = self.packet_counts.keys()
        sizes = self.packet_counts.values()
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        plt.title('Packet Distribution')

        plt.tight_layout()
        plt.pause(0.1)

    def packet_handler(self, packet):
        self.packet_count += 1

        # Print the raw packet data
        print(f"Packet count: {self.packet_count}")
        raw_data = binascii.hexlify(bytes(packet)).decode('ascii')
        for i in range(0, len(raw_data), 2):
            print(raw_data[i:i+2], end=" ")
            if (i // 2 + 1) % 16 == 0:
                print()
        print()

        # Extract IP layer
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dest_ip = ip_layer.dst

            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                print(f"Packet count: {self.packet_count} (TCP)")
                print(f"Source IP: {src_ip}, Source Port: {tcp_layer.sport}")
                print(f"Destination IP: {dest_ip}, Destination Port: {tcp_layer.dport}")
                self.packet_counts['TCP'] += 1
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                print(f"Packet count: {self.packet_count} (UDP)")
                print(f"Source IP: {src_ip}, Source Port: {udp_layer.sport}")
                print(f"Destination IP: {dest_ip}, Destination Port: {udp_layer.dport}")
                self.packet_counts['UDP'] += 1
            else:
                print(f"Packet count: {self.packet_count} (Other protocol)")
                self.packet_counts['Others'] += 1

        print()
        self.update_plots()

    def final_analysis(self):
        plt.ioff()  # Turn off interactive plotting

        # Final analysis table
        print("\nFinal Analysis:")
        data = [[proto, count] for proto, count in self.packet_counts.items()]
        print(tabulate(data, headers=['Protocol', 'Count'], tablefmt='grid'))

        # Plot final figures
        plt.figure(figsize=(12, 6))

        # Bar chart
        plt.subplot(1, 2, 1)
        plt.bar(self.packet_counts.keys(), self.packet_counts.values(), color=['blue', 'green', 'red'])
        plt.xlabel('Protocol')
        plt.ylabel('Packet Count')
        plt.title('Final Packet Count by Protocol')

        # Pie chart
        plt.subplot(1, 2, 2)
        labels = self.packet_counts.keys()
        sizes = self.packet_counts.values()
        plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=140)
        plt.title('Final Packet Distribution')

        plt.tight_layout()
        plt.show()

def main():
    sniffer = PacketSniffer()

    # Get the list of available network interfaces
    interfaces = get_windows_if_list()
    print("Available interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"{i}: {iface['name']} - {iface['description']}")

    # Prompt the user to select an interface
    iface_index = int(input("Select an interface by number: "))
    interface = interfaces[iface_index]['name']

    print("Starting packet capture... Press Ctrl+C to stop and view final analysis.")
    
    try:
        plt.ion()
        plt.figure(figsize=(12, 6))
        sniff(iface=interface, prn=sniffer.packet_handler)
    except KeyboardInterrupt:
        sniffer.final_analysis()

if __name__ == "__main__":
    main()















