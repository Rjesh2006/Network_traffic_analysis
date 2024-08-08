#include <iostream>
#include <pcap.h>
#include <netinet/ip.h> // For IP header structure
#include <netinet/tcp.h> // For TCP header structure
#include <netinet/udp.h> // For UDP header structure
#include <iomanip> // For std::hex, std::setw, std::setfill

using namespace std;

void packetHandler(unsigned char* userData, const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {
    // Increment the packet count
    static int packetCount = 0;
    packetCount++;

    // Print the raw packet data
    cout << "Packet count: " << packetCount << endl;
    for (int i = 0; i < pkthdr->len; ++i) {
        cout << hex << setw(2) << setfill('0') << static_cast<int>(packet[i]) << " ";
        if ((i + 1) % 16 == 0)
            cout << endl;
    }
    cout << endl;

    // Extract the IP header
    const struct ip* ipHeader = reinterpret_cast<const struct ip*>(packet + 14); // Skip Ethernet header (14 bytes)

    // Get source and destination IP addresses
    const char* srcIP = inet_ntoa(ipHeader->ip_src);
    const char* destIP = inet_ntoa(ipHeader->ip_dst);

    // Determine the transport layer protocol
    if (ipHeader->ip_p == IPPROTO_TCP) {
        const struct tcphdr* tcpHeader = reinterpret_cast<const struct tcphdr*>(packet + 14 + ipHeader->ip_hl * 4);
        
        cout << "Packet count: " << packetCount << " (TCP)" << endl;
        cout << "Source IP: " << srcIP << ", Source Port: " << ntohs(tcpHeader->th_sport) << endl;
        cout << "Destination IP: " << destIP << ", Destination Port: " << ntohs(tcpHeader->th_dport) << endl;
    } else if (ipHeader->ip_p == IPPROTO_UDP) {
        const struct udphdr* udpHeader = reinterpret_cast<const struct udphdr*>(packet + 14 + ipHeader->ip_hl * 4);
        
        cout << "Packet count: " << packetCount << " (UDP)" << endl;
        cout << "Source IP: " << srcIP << ", Source Port: " << ntohs(udpHeader->uh_sport) << endl;
        cout << "Destination IP: " << destIP << ", Destination Port: " << ntohs(udpHeader->uh_dport) << endl;
    } else {
        cout << "Packet count: " << packetCount << " (Other protocol)" << endl;
    }
    
    cout << endl;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcapHandle;

    // Replace "ens33" with the name of your network interface
    const char* device = "ens33";

    // Open the network interface for live packet capture
    pcapHandle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (pcapHandle == nullptr) {
        cerr << "Error opening device: " << errbuf << endl;
        return 1;
    }

    // Set a packet handler callback
    pcap_loop(pcapHandle, 0, packetHandler, nullptr);

    // Close the capture handle when done
    pcap_close(pcapHandle);

    return 0;
}
