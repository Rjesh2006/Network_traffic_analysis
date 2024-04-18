# network traffick analyser project :--🔽
*here the step's of nta project*

**Step -:1**
 - *first we have to creat a cpp file*
 - *i used here the ubuntu terminal to creat my cpp file which is rk1.cppp*
   fig5645


**Step -:2**
*here we understad about the header file wwhichh require in (netwwork analysis project )
 - required hearder file
  - fig54654646

 *now now lstes understand about the header file which we defined there:⏫*
   1. must required file is <pcap.h>
    -  * pcap.h is a header file used in Cpp programming for working with packet capture libraries. It contains declarations for structures, functions, constants, and error codes related to capturing and analyzing 
         network packets. It's essential for developing network monitoring and analysis tools in Cpp*


   2.here we have to understand about the <netinet.>
    - * overview of what you might find in the <netinet> directory:

 Socket-related Headers: Files like <netinet/in.h> provide definitions for Internet address structures (struct sockaddr_in) and constants related to IP addresses and ports.
 Protocol Headers: Headers like <netinet/tcp.h> and <netinet/udp.h> define structures and constants specific to the Transmission Control Protocol (TCP) and User Datagram Protocol (UDP), respectively.
 IP-related Headers: <netinet/ip.h> contains definitions for the IP packet header structure and related constants.
 Other Network-related Headers: Depending on the operating system and networking libraries installed, you might find additional headers for other protocols and network-related operations.*


   2.here we have to understand about the <ioman.ip>.
   - *<iomanip> is a C++ header file used for formatting input and output operations. It provides manipulators and modifiers to control the appearance of data in streams, such as setting field width, precision, 
    alignment, and formatting flags. It's handy for achieving specific formatting requirements in C++ programs.*




**Step -:3**
```cpp
void packetHandler(unsigned char* userData, const struct pcap_pkthdr* pkthdr, const unsigned char* packet) {
```
- This is the definition of the packet handling function. It takes three parameters:
userData: A pointer to user-defined data (not used in this function).
pkthdr: A pointer to a pcap_pkthdr struct, which contains information about the captured packet, such as its length and timestamp.
packet: A pointer to the raw packet data.



**Step -:4**
```cpp
    static int packetCount = 0;
    packetCount++;
```
- This code initializes a static variable packetCount to count the number of packets processed. Every time this function is called, it increments the packetCount.

**Step -:5**

```cpp
    std::cout << "Packet count: " << packetCount << std::endl;
```
- Prints the packet count to the console.


**Step -:5**
```cpp
    for (int i = 0; i < pkthdr->len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(packet[i]) << " ";
        if ((i + 1) % 16 == 0)
            std::cout << std::endl;
    }
```
- This loop iterates over each byte of the packet and prints its hexadecimal representation. It prints 16 bytes per line, then moves to the next line.


**Step -6**
```
const struct ip* ipHeader = reinterpret_cast<const struct ip*>(packet + 14);
```
- This line extracts the IP header from the packet data. It interprets the packet starting from the 15th byte (Ethernet header is typically 14 bytes) as an IP header.

  **Steps-7**

  ```cpp
      const char* srcIP = inet_ntoa(ipHeader->ip_src);
    const char* destIP = inet_ntoa(ipHeader->ip_dst);
  ```
- Extracts the source and destination IP addresses from the IP header and converts them to a human-readable string format.



**Steps-8**

```cpp
    if (ipHeader->ip_p == IPPROTO_TCP) {
        // Handle TCP packets
    } else if (ipHeader->ip_p == IPPROTO_UDP) {
        // Handle UDP packets
    } else {
        // Handle packets with other protocols
    }
```

- This conditional statement checks the protocol of the packet (TCP, UDP, or other) and performs actions accordingly. It extracts additional headers (TCP or UDP) based on the protocol.


**Steps-9**
- Now, let's move to the main function
    ```
    // Replace "ens33" with the name of your network interface
    const char* device = "ens33";

    // Open the network interface for live packet capture
    pcapHandle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    // Check if pcap_open_live failed
    if (pcapHandle == nullptr) {
        // Print error message
        std::cerr << "Error opening device: " << errbuf << std::endl;
        // Return non-zero exit status
        return 1;
    }

    // Set a packet handler callback
    pcap_loop(pcapHandle, 0, packetHandler, nullptr);

    // Close the capture handle when done
    pcap_close(pcapHandle);

    // Return zero exit status indicating successful execution
    return 0;
  }
  ```

***Noe, we can run this code and this will give us output like this (Iterface:⏬)**

   

  





