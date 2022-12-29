/* Compile with: sudo gcc test_libpcap.c -lpcap */

#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>


void my_packet_handler(
    unsigned char *args,
    const struct pcap_pkthdr *header,
    const unsigned char *packet
);
int main(int argc, char **argv) {
   char error[PCAP_ERRBUF_SIZE];/*error buffer find all devs*/
    pcap_if_t *interfaces,*temp;/*interface search*/
    pcap_if_t *tsi;/*selected interface*/
    pcap_t *handle;/*pcap_open_live*/
    char ip[13];
    int timeout_limit = 100; /* In milliseconds *//*pcap_open_live*/
    char *device;/*error buffer*/
    char error_buffer[PCAP_ERRBUF_SIZE]; /* Size defined in pcap.h */
    int i=0;
    if(pcap_findalldevs(&interfaces,error)==-1)
    {
        printf("\nerror in pcap findall devs");
        return -1;
    }

    printf("\n the interfaces present on the system are:");
    for(temp=interfaces;temp;temp=temp->next)
    {
        printf("\n%d  :  %s\n",i++,temp->name);
        
        if(strcmp(temp->name, "enx0023575c2612")==0){
            printf("interface FOUND\n");
            tsi = temp;
        }
            /* Get device info */
   /* lookup_return_code = pcap_lookupnet(
        temp->name,
        &ip_raw,
        &subnet_mask_raw,
        error_buffer
    );*/
    /*address.s_addr = ip_raw;
    strcpy(ip, inet_ntoa(address));*/

    /*if (lookup_return_code == -1) {
        printf("%s\n", error_buffer);
        return 1;
    }  */ 
    }
    printf("selected interface: %s\n", tsi->name);
        /* Open device for live capture */
    handle = pcap_open_live(
            tsi->name,
            BUFSIZ,
            0,
            timeout_limit,
            error_buffer
        );
    if (handle == NULL) {
     fprintf(stderr, "Could not open device %s: %s\n", device, error_buffer);
     return 2;
    }
    pcap_loop(handle, 6, my_packet_handler, NULL);
    return 0;
   }
void print_packet_info(const unsigned char *packet, struct pcap_pkthdr packet_header) {
    printf("Packet capture length: %d\n", packet_header.caplen);
    printf("Packet total length %d\n", packet_header.len);
}
void my_packet_handler(unsigned char *args,const struct pcap_pkthdr *header,const unsigned char *packet)
{
    struct ether_header *eth_header;
    /* The packet is larger than the ether_header struct,
       but we just want to look at the first part of the packet
       that contains the header. We force the compiler
       to treat the pointer to the packet as just a pointer
       to the ether_header. The data payload of the packet comes
       after the headers. Different packet types have different header
       lengths though, but the ethernet header is always the same (14 bytes) */
    eth_header = (struct ether_header *) packet;
    
    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
        printf("IP\n");
            /* Pointers to start point of various headers */
        const unsigned char *ip_header;
        const unsigned char *udp_header;
        const unsigned char *PTPpayload;
            /* Header lengths in bytes */
        int ethernet_header_length = 14; /* Doesn't change */
        int ip_header_length;
        int udp_header_length = 8;
        int payload_length;

        /* Find start of IP header */
        ip_header = packet + ethernet_header_length;
        /* The second-half of the first byte in ip_header
        contains the IP header length (IHL). */
        ip_header_length = ((*ip_header) & 0x0F);
        /* The IHL is number of 32-bit segments. Multiply
        by four to get a byte count for pointer arithmetic */
        ip_header_length = ip_header_length * 4;
        printf("IP header length (IHL) in bytes: %d\n", ip_header_length);
        /* Now that we know where the IP header is, we can 
        inspect the IP header for a protocol number to 
        make sure it is TCP before going any further. 
        Protocol is always the 10th byte of the IP header */
        unsigned char protocol = *(ip_header + 9);
    if (protocol != IPPROTO_UDP) {
        printf("Not a UDP packet. Skipping...\n\n");
        return;
    }
    else {
        printf("UDP packet detected\n");
        /* Add the ethernet and ip header length to the start of the packet
       to find the beginning of the TCP header */
        udp_header = packet + ethernet_header_length + ip_header_length;

    /* Add up all the header sizes to find the payload offset */
    int total_headers_size = ethernet_header_length+ip_header_length+udp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = header->caplen -
        (ethernet_header_length + ip_header_length + udp_header_length);
    printf("Payload size: %d bytes\n", payload_length);
    PTPpayload = packet + total_headers_size;
    printf("Memory address where payload begins: %p\n\n", PTPpayload);

        /* Print payload in ASCII */
      
    if (payload_length > 0) {
        const unsigned char *temp_pointer = PTPpayload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
            printf("%x", *temp_pointer);
            temp_pointer++;
        }
        printf("\n");
    }
    unsigned char messageId = ((*PTPpayload)& 0x0F);
    printf("messageId: %x\n",messageId);
   /* if(messageId == 0){
        unsigned char correctionField = (*(PTPpayload + 8)& 0xFFFFFFFFFFFFFFFF);
        printf("correction value: %x\n",correctionField);
       
        
        sprintf((*(PTPpayload + 8)& 0xFFFFFFFFFFFFFFFF),"%lx", getEpochTime());
        const unsigned char *pointer = PTPpayload;
        printf("new payload: %x", *pointer);
    }*/
    }
    } else  if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
        printf("ARP\n");
    } else  if (ntohs(eth_header->ether_type) == ETHERTYPE_REVARP) {
        printf("Reverse ARP\n");
    }
}
  