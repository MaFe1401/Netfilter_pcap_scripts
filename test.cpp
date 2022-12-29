#include <tins/dot1q.h>
#include <tins/ethernetII.h>
#include <tins/pdu.h>
#include <tins/ip.h>
#include <tins/tins.h>
#include <pcap/pcap.h>
#include <net/ethernet.h>
#include <tins/pdu_allocator.h>
#include <tins/ptp.h>
#include <iostream>
#include <chrono>
#include <iostream>
#include <inttypes.h>
using namespace::Tins;
using namespace std::chrono;

bool check_if_ptp(const EthernetII &pdu);
bool check_if_ptp(const EthernetII &pdu){
    if (pdu.payload_type() == ETHERTYPE_PTP) {
        const PTP& ptp = pdu.rfind_pdu<PTP>();
        printf("%x \n", pdu.payload_type());
        return true;
    }
    return false;
}
bool ptp_check_req(uint8_t *data, uint len);
bool ptp_check_req(uint8_t *data, uint len){

    EthernetII pdu(data, len);
    if(check_if_ptp(pdu)==false){
        return false;
    }
    else return true;
}
PTP check_ptp_correctionfield(EthernetII &pdu);
PTP check_ptp_correctionfield(EthernetII &pdu){
    if (check_if_ptp(pdu)){
        PTP ptp = pdu.rfind_pdu<PTP>();
        if(ptp.getMessageType()==0x0000){//Sync message
        printf("Message type: %x \n", ptp.getMessageType());
         uint64_t ms = duration_cast<nanoseconds>(system_clock::now().time_since_epoch()).count();
         printf("timestamp: %" PRIu64  "\n", ms);
         ptp.setcorrectionField(ms);
         return ptp;
    }
    else return ptp;
    }

}
EthernetII create_from_ptp (PTP &pdu){
    uint8_t *payload = pdu.serialize().data();
    EthernetII ethernet = Tins::EthernetII (payload, pdu.size());
    return ethernet;
}

int main(){
    
    Allocators::register_allocator<EthernetII, PTP>(0x88f7);
    uint8_t ptp_packet[] = {
        0x0000, 0x0002, 0x0000, 0x002c, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0080, 0x0063, 0x00ff, 0x00ff, 0x0000, 0x0009, 0x00ba, 0x0000, 0x0002, 0x0004, 0x003e, 0x0000, 0x0000, 0x0000, 0x0000, 0x0045, 0x00b1, 0x0011, 0x004a, 0x002e, 0x002d, 0x00b9, 0x00b8
    };
    uint8_t eth_frame[] = {
        0x0001, 0x001b, 0x0019, 0x0000, 0x0000, 0x0000, 0x0000, 0x0080, 0x0063, 0x0000, 0x0009, 0x00ba, 0x0088, 0x00f7, 0x0000, 0x0002, 0x0000, 0x002c, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0080, 0x0063, 0x00ff, 0x00ff, 0x0000, 0x0009, 0x00ba, 0x0000, 0x0002, 0x0004, 0x003e, 0x0000, 0x0000, 0x0000, 0x0000, 0x0045, 0x00b1, 0x0011, 0x004a, 0x002e, 0x002d, 0x00b9, 0x00b8, 0x0000, 0x0000
    };
    int frame_size = 60; 
    int ptp_packet_size = 44;
    EthernetII frame = Tins::EthernetII(eth_frame, frame_size);
    PTP packet = frame.rfind_pdu<PTP>();
    auto ptp_packet_data = packet.serialize();
    std::cout << "packet BEFORE " << std::endl;
    for (int i = 0; i < ptp_packet_size; i++)
    {
        printf("%x ", ptp_packet_data[i]);
    }

    /*uint8_t b[60];
    for (int i = 0; i < frame_size; i++)
    {
        b[i] = eth_frame[i];
    }*/
    printf("\n");

    Tins::EthernetII new_eth_frame = Tins::EthernetII(eth_frame,frame_size);
    
    if (check_if_ptp(new_eth_frame)==false){
        std::cout << "Ethernet frame not detected" << std::endl;

    }
    else {
        if (ptp_check_req(eth_frame, frame_size)==false){
            std::cout << "PTP frame not detected" << std::endl;
        }
        else {
            PTP ptp = check_ptp_correctionfield(new_eth_frame);
            EthernetII eth = create_from_ptp(ptp);
            auto data = ptp.serialize();
                std::cout << "packet after " << std::endl;
                for (int i = 0; i < ptp.size(); i++)
                {
                printf("%x ", data[i]);
                }
                printf("\n");
            uint64_t timestamp = ptp.correctionField();
            printf("timestamp established: %" PRIu64  "\n", timestamp);
        }
    }
}