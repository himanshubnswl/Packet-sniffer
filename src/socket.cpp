//
// Created by lhbdawn on 04-07-2026.
//

#include "socket.hpp"

#include <stop_token>

namespace Socket {
    const MyModel *mymodel;

    //the struct for the ethernet header
    struct header_type {
        uint8_t MAC_DEST[6];
        uint8_t MAC_SRC[6];
        //type means the internet packet type, IPV4 or IPV6
        uint16_t type;
    };

    pcap_if_t *getdevicelist() {
        pcap_if_t *alldevs;
        int i = 0;
        char errbuf[PCAP_ERRBUF_SIZE];

        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            std::cerr << "cannot get device list" << std::endl;
            std::exit(0);
        }

        for (auto *d = alldevs; d != nullptr; d = d->next) {
            std::cout << ++i << "  " << d->name << std::endl;
            if (d->description) {
                std::cout << d->description << std::endl;
            } else {
                std::cout << "no description" << std::endl;
            }
        }
        if (i == 0) {
            std::cout << "no devices to list!" << std::endl;
        }
        return alldevs;
    }

    //calls getdevicelist internally and returns the selected device
    //will be changed to accodomate the complete gui
    pcap_if_t *selectdev(pcap_if_t *alldevs) {
        alldevs = getdevicelist();
        std::cout << "select the device{use number}: ";
        int device{0};
        std::cin >> device;

        if (std::cin.fail()) {
            std::cerr << "enter a number!!";
            pcap_freealldevs(alldevs);
            std::exit(0);
        }
        pcap_if_t *selected_device{nullptr};

        int i{0};
        for (auto *d = alldevs; d != nullptr; d = d->next) {
            if (++i == device) {
                selected_device = d;
                std::cout << "the selected device is: " << d->name << "  " << d->description << std::endl;
            }
        }
        if (selected_device == nullptr) {
            std::cerr << "wrong number, try again" << std::endl;
            pcap_freealldevs(alldevs);
            std::exit(0);
        }
        return selected_device;
    }

    //starts to print packets by calling a handler function, needs to be passed a device.
    //custom function to handle the handling of packets
    int printpackets(pcap_if_t *dev, MyModel *model, std::stop_token &stop_token) {
        static u_int64 totalpacketcount{0};
        static u_int64 referencetime{0};

        pcap_t *adhandle{nullptr};
        char errbuf[PCAP_ERRBUF_SIZE];
        if ((adhandle = pcap_create(dev->name, errbuf)) == nullptr) {
            std::cerr << errbuf;
            return -1;
        }

        pcap_set_promisc(adhandle, 1);
        pcap_set_snaplen(adhandle, 65536);
        pcap_set_timeout(adhandle, 1000);
        if (pcap_activate(adhandle)) {
            std::cerr << "some bad shit happened";
            return -1;
        }
        std::cout << "listening on " << dev->description << std::endl;

        pcap_pkthdr *header{nullptr};
        const uchar *pkt_data{nullptr};

        while (!stop_token.stop_requested()) {
            int stat = pcap_next_ex(adhandle, &header, &pkt_data);
            if (stat == 1) {
                if (totalpacketcount == 0) {
                    referencetime = (static_cast<u_int64>(header->ts.tv_sec) * 1'000'000) + header->ts.tv_usec;
                }
                packet_handler(reinterpret_cast<uchar *>(model), header, pkt_data, referencetime, totalpacketcount);
                totalpacketcount++;
            } else if (stat == -1) {
                break;
            }
        }
        pcap_close(adhandle);
        return 0;
    }

    void handle_ipv6packet(packet_info &newpacket, const uchar *pkt_data) {
        struct ipv6_header {
            uint8_t version_traffic;//constant 0110
            uint8_t traffic_flow;//holds DS field 6 bits, 2-bits explicit congestion notification
            uint16_t flow_label;//high entropy identifier of a flow
            uint16_t playload_length;//size of playload in octets, including extension headers
            uint8_t next_header;//specifies type of next header, typically specifies transport layer
            uint8_t hop_limit;//replacement to TTL in ipv4
            uint16_t source_addr[8];//unicast ipv6 addr of sending node
            uint16_t dest_addr[8];//unicast or multicast addr of destination node(s)
        };

        const auto *header = reinterpret_cast<const ipv6_header *>(pkt_data);

        newpacket.ip_src = QString::asprintf("%0X:%0X:%0X:%0X:%0X:%0X:%0X:%0x", header->source_addr[0],
                                             header->source_addr[1], header->source_addr[2], header->source_addr[3],
                                             header->source_addr[4], header->source_addr[5], header->source_addr[6],
                                             header->source_addr[7]);
        newpacket.ip_dest = QString::asprintf("%0X:%0X:%0X:%0X:%0X:%0X:%0X:%0X", header->dest_addr[0],
                                              header->dest_addr[1], header->dest_addr[2], header->dest_addr[3],
                                              header->dest_addr[4], header->dest_addr[5], header->dest_addr[6],
                                              header->dest_addr[7]);
    }

    void handle_ipv4packet(packet_info &newpacket, const uchar *pkt_data) {
        //the ipv4 header struct, needs to be changed to incorporate all the fields of the header
        //and remove the constructor mechanism
        struct ipv4_header {
            uint8_t version;
            //always equal to 4 for IPv4, also contains the IHL field, 4-4,IHL specifies the number of 32-bit words in the header
            uint8_t DSCP_ECN; //specifies differentiated service
            uint16_t total_lenght; //specifies the entire packet size in bytes, including header and data
            uint16_t identification;
            //primarily used for uniquely identifying the group of fragments of a single IP datagram
            uint16_t flag_fragmentoffset; //fragment bits,later 13 bits specify offset of fragment
            uint8_t time_to_live; //limits a datagrams lifetime to prevent network failure
            uint8_t protocol; //protocol encapsulated in the data portion of the ip datagram
            uint16_t header_checksum; //error checking of header
            uint8_t source_addr[4]; //constains the ip address of the sender of the packet
            uint8_t dest_addr[4]; //ip address of intended receiver
        };

        const auto *ipv4head = reinterpret_cast<const ipv4_header *>(pkt_data);
        switch (ipv4head->protocol) {
            case 1:
                newpacket.protocol = "ICMP";
                break;
            case 2:
                newpacket.protocol = "IGMP";
                break;
            case 6:
                newpacket.protocol = "TCP";
                break;
            case 17:
                newpacket.protocol = "UDP";
                break;
            case 41:
                newpacket.protocol = "ENCAP";
                break;
            case 89:
                newpacket.protocol = "OSPF";
                break;
            case 132:
                newpacket.protocol = "SCTP";
                break;
            default: break;
        }
        newpacket.ip_src = QString::asprintf("%d.%d.%d.%d", ipv4head->source_addr[0], ipv4head->source_addr[1],
                                             ipv4head->source_addr[2], ipv4head->source_addr[3]);

        newpacket.ip_dest = QString::asprintf("%d.%d.%d.%d", ipv4head->dest_addr[0], ipv4head->dest_addr[1],
                                              ipv4head->dest_addr[2], ipv4head->dest_addr[3]);
    }

    void handle_ARP(packet_info &newpacket, const uchar *pkt_data) {
        //the arp header struct
        struct ARP_Header {
            uint16_t htype; // Hardware type (offset 14)
            uint16_t ptype; // Protocol type (offset 16)
            uint8_t hlen; // Hardware size (offset 18)
            uint8_t plen; // Protocol size (offset 19)
            uint16_t opcode; // Opcode (offset 20)
            uint8_t sender_mac[6]; // Sender MAC (offset 22)
            uint8_t sender_ip[4]; // Sender IP (offset 28)
            uint8_t target_mac[6]; // Target MAC (offset 32)
            uint8_t target_ip[4]; // Target IP (offset 38)
        };

        const auto *packet = reinterpret_cast<const ARP_Header *>(pkt_data);
        newpacket.mac_src = QString::asprintf("%0X:%0X:%0X:%0X:%0X:%0X", packet->sender_mac[0], packet->sender_mac[1],
                                              packet->sender_mac[2], packet->sender_mac[3], packet->sender_mac[4],
                                              packet->sender_mac[5]); //mac source
        newpacket.mac_dest = QString::asprintf("%0X:%0X:%0X:%0X:%0X:%0X", packet->target_mac[0], packet->target_mac[1],
                                               packet->target_mac[2], packet->target_mac[3], packet->target_mac[4],
                                               packet->target_mac[5]); //mac target addr
        newpacket.ip_src = QString::asprintf("%d.%d.%d.%d", packet->sender_ip[0], packet->sender_ip[1],
                                             packet->sender_ip[2], packet->sender_ip[3]); //source ip addr
        newpacket.ip_dest = QString::asprintf("%d.%d.%d.%d", packet->target_ip[0], packet->target_ip[1],
                                              packet->target_ip[2], packet->target_ip[3]); //the target ip addr


        if (ntohs(packet->opcode) == 1) {
            newpacket.protocol = QString{"ARP Request"};
            newpacket.additional_info = QString("who has the ip addr %1").arg(newpacket.ip_dest);
        } else if (ntohs(packet->opcode) == 2) {
            newpacket.protocol = QString("ARP Reply");
            newpacket.additional_info = QString("I have %1").arg(newpacket.ip_src);
        }
    }


    //the main packet handler function, all packets will go through this function and have their mac addresses handled
    //the packets then get routed to different function depending on the type of packet they are,eg arp, ipv4 etc.
    void packet_handler(u_char *param,
                        const struct pcap_pkthdr *header,
                        const u_char *pkt_data, const u_int64 referencetime, const u_int64 packetcount) {
        auto *model = reinterpret_cast<MyModel *>(param);

        const auto *p_header = reinterpret_cast<const header_type *>(pkt_data);
        packet_info newpacket;
        newpacket.mac_dest = QString::asprintf("%02X:%02X:%02X:%02X:%02x:%02X", p_header->MAC_DEST[0],
                                               p_header->MAC_DEST[1], p_header->MAC_DEST[2], p_header->MAC_DEST[3],
                                               p_header->MAC_DEST[4], p_header->MAC_DEST[5]);

        newpacket.mac_src = QString::asprintf("%02X:%02X:%02X:%02X:%02x:%02X", p_header->MAC_SRC[0],
                                              p_header->MAC_SRC[1], p_header->MAC_SRC[2], p_header->MAC_SRC[3],
                                              p_header->MAC_SRC[4], p_header->MAC_SRC[5]);

        long double currenttime = (static_cast<long double>(header->ts.tv_sec) * 1'000'000) + header->ts.tv_usec;
        currenttime = (currenttime - referencetime) / 1'000'000.00;
        newpacket.timestamp = QString::number(currenttime, 'f', 6);
        newpacket.packet_number = packetcount;

        auto ether_type = ntohs(p_header->type);
        switch (ether_type) {
            case 0x0800:
                newpacket.int_type = "IPV4";
                handle_ipv4packet(newpacket, pkt_data + 14);
                break;
            case 0x86DD:
                newpacket.int_type = "IPV6";
                handle_ipv6packet(newpacket, pkt_data + 14);
                break;
            case 0x0806:
                newpacket.int_type = "ARP";
                handle_ARP(newpacket, pkt_data + 14);
                break;
            default: ;
        }
        emit model->newpacketready(newpacket);
        emit model->newpacketadded();
    }
};
