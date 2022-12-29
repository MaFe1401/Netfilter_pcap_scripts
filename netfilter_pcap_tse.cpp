#include <memory>
#include <functional>
#include <array>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <stdio.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <pcap.h>
#include <stdint.h>
#include <inttypes.h>
#include<math.h>
#define BILLION  1000000000L
extern "C"
{
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <libnetfilter_queue/libnetfilter_queue_udp.h>
}
 
#define THROW_IF_TRUE(x, m) do { if((x)) { throw std::runtime_error(m); }} while(false)
 
#define CONCAT_0(pre, post) pre ## post
#define CONCAT_1(pre, post) CONCAT_0(pre, post)
#define GENERATE_IDENTIFICATOR(pre) CONCAT_1(pre, __LINE__)
 
using ScopedGuard = std::unique_ptr<void, std::function<void(void *)>>;
#define SCOPED_GUARD_NAMED(name, code) ScopedGuard name(reinterpret_cast<void *>(-1), [&](void *) -> void {}); (void)name
#define SCOPED_GUARD(code) SCOPED_GUARD_NAMED(GENERATE_IDENTIFICATOR(genScopedGuard), code);
 
uint64_t getTimestamp (void){
    long int ns;
    uint64_t all;
    time_t sec;
    struct timespec spec;

    clock_gettime(CLOCK_REALTIME, &spec);
    sec = spec.tv_sec;
    ns = spec.tv_nsec;
    all = (uint64_t) sec * BILLION + (uint64_t) ns;
   

    printf("Current time: %" PRIu64  " nanoseconds since the Epoch\n", all);
    return all;
}

static int netfilterCallback(struct nfq_q_handle *queue, struct nfgenmsg *nfmsg, struct nfq_data *nfad, void *data)
{
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfad);
    THROW_IF_TRUE(ph == nullptr, "Issue while packet header");
 
    unsigned char *rawData = nullptr;
    int len = nfq_get_payload(nfad, &rawData);
    THROW_IF_TRUE(len < 0, "Can't get payload data");
 
    struct pkt_buff * pkBuff = pktb_alloc(AF_INET, rawData, len, 0x1000);
    THROW_IF_TRUE(pkBuff == nullptr, "Issue while pktb allocate");
    SCOPED_GUARD(pktb_free(pkBuff)); // Don't forget to clean up
 
    struct iphdr *ip = nfq_ip_get_hdr(pkBuff);
    THROW_IF_TRUE(ip == nullptr, "Issue while ipv4 header parse.");
 
    THROW_IF_TRUE(nfq_ip_set_transport_header(pkBuff, ip) < 0, "Can't set transport header.");
     
    if(ip->protocol == IPPROTO_UDP)
    {
        struct udphdr *udp = nfq_udp_get_hdr(pkBuff);
        THROW_IF_TRUE(udp == nullptr, "Issue while udp header.");
         
        void *payload = nfq_udp_get_payload(udp, pkBuff);
        
        unsigned int payloadLen = nfq_udp_get_payload_len(udp, pkBuff);
        
        THROW_IF_TRUE(payload == nullptr, "Issue while payload.");
        uint64_t tsi = getTimestamp();
        if (payloadLen>0){
            char *temp_pointer = (static_cast<char *>(payload));
            int byte_count = 0;
            while (byte_count++ < 44) {
            printf("%x", *temp_pointer);
            temp_pointer++;
        }
        printf("\n");
        }
        char ts[15];
        sprintf(ts, "%lx", tsi);
        
        printf("Hex timestamp: %s\n", ts);
        /*int m;
        int charcount;

        charcount = 0;
        for(m=0; ts[m]; m++) {
            if(ts[m] != ' ') {
                charcount ++;
            }
        }
        printf("Contador timestamp: %d\n", charcount);*/
        size_t len = sizeof(static_cast<char *>(payload))-1;
        uint8_t bytes[len/2];
       /*for (size_t i=0; i<len; i+=2){
            sscanf(static_cast<char *>(payload)+i, "%2hhx", &bytes[i/2]);
        }
        int num = 25;
        bytes[3] = (uint8_t)(num >> 24);
        bytes[4] = (uint8_t)(num >> 16);
        bytes[5] = (uint8_t)(num >> 8);
        bytes[6] = (uint8_t)num;
        for (size_t i =0; i<sizeof(bytes);++i){
            sprintf("%02x", bytes[i]);
        }*/

        char hextsi [20];
        for (int x = 9; x<17;x++){
            char temp[3] = {(static_cast<char *>(payload))[x]};
            strncat(hextsi, temp,3);
        }

        long decimaltsi = strtol(hextsi, NULL, 16);
        long decimaltse = getTimestamp() - decimaltsi;
        char hextse[15];
        sprintf(hextse, "%lx", decimaltse);
        for (unsigned int i = 1; i < strlen(hextse); i+=2) {
            char tmp[3] = {hextse[strlen(hextse)-i-1], hextse[strlen(hextse)-i],'\0'};
            long decimal = strtol(tmp, NULL, 16);
            printf("decimal: %ld", decimal);
            (static_cast<char *>(payload))[15-int(round(i/2))] = decimal;
            
            //printf("payload value: %s\n",(static_cast<char *>(payload))[19-i]);
        }
        putchar('\n');
        printf("Payload length: %d\n", payloadLen);
        unsigned char messageId = (*(static_cast<char *>(payload))&0x0F);
        printf("messageId: %x\n",messageId);
        
        for (unsigned int i = 0; i < 6; ++i) {
            //char tmp = (static_cast<char *>(payload))[i];
            
            //ptp[15-i] = ts[6-i];
           
        }
        
         //printf("final packet: %s\n", (static_cast<char *>(payload)));
        if(messageId == 0){
        /*unsigned char correctionField = (*((static_cast<char *>(payload)) + 8)& 0xFFFFFFFFFFFFFFFF);
        printf("correction value: %x\n",correctionField);
       
        
        sprintf((*((static_cast<char *>(payload)) + 8)& 0xFFFFFFFFFFFFFFFF),"%lx", ts);
        unsigned char pointer = *(static_cast<char *>(payload));
        printf("new payload: %x", pointer);*/
        }
        nfq_udp_compute_checksum_ipv4(udp, ip);
        return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, pktb_len(pkBuff), pktb_data(pkBuff));
    }
    return nfq_set_verdict(queue, ntohl(ph->packet_id), NF_ACCEPT, 0, nullptr);
}
 
 
int main()
{
    struct nfq_handle * handler = nfq_open();
    THROW_IF_TRUE(handler == nullptr, "Can't open hfqueue handler.");
    SCOPED_GUARD( nfq_close(handler); ); // Don’t forget to clean up
 
    struct nfq_q_handle *queue = nfq_create_queue(handler, 0, netfilterCallback, nullptr);
    THROW_IF_TRUE(queue == nullptr, "Can't create queue handler.");
    SCOPED_GUARD( nfq_destroy_queue(queue); ); // Do not forget to clean up
 
    THROW_IF_TRUE(nfq_set_mode(queue, NFQNL_COPY_PACKET, 0xffff) < 0, "Can't set queue copy mode.");
 
    int fd = nfq_fd(handler);
    std::array<char, 0x10000> buffer;
    for(;;)
    {
        int len = read(fd, buffer.data(), buffer.size());
        THROW_IF_TRUE(len < 0, "Issue while read");
        nfq_handle_packet(handler, buffer.data(), len);
    }
    return 0;
 }