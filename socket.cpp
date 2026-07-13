//
// Created by lhbdawn on 04-07-2026.
//
#include "pcap.h"
#include <iostream>
#include "socket.hpp"
#include <cstdint>
#include <format>
#include <iomanip>
#include <winsock2.h>

namespace Socket {
    struct header_type {
        uint8_t MAC_DEST[6];
        uint8_t MAC_SRC[6];
        uint16_t type;
    };

    struct ipv4_header {
        uint8_t protocol;
        uint8_t source_addr[4];
        uint8_t dest_addr[4];

        ipv4_header(const u_char *pkt) {
            protocol = pkt[9];
            memcpy(source_addr, pkt + 12, 4);
            memcpy(dest_addr, pkt + 16, 4);
        }
    };

    pcap_if_t *getdevicelist() {
        pcap_if_t *alldevs;
        int i = 0;
        char errbuf[PCAP_ERRBUF_SIZE];

        if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, nullptr, &alldevs, errbuf) == -1) {
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

    pcap_if_t *selectdev() {
        auto *alldevs = getdevicelist();
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
        // pcap_freealldevs(alldevs);
        return selected_device;
    }

    int printpackets(pcap_if_t *dev) {
        pcap_t *adhandle{nullptr};
        char errbuf[PCAP_ERRBUF_SIZE];

        if ((adhandle = pcap_open(dev->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, nullptr, errbuf)) == nullptr) {
            std::cerr << "unable to open device!";
            return -1;
        }

        std::cout << "listening on " << dev->description << std::endl;
        std::cout << "MAC_DEST\t\t MAC_SRC\t\t TYPE\t\t PROTOCOL\t\t IP_SRC\t\t IP_DEST" << std::endl;
        pcap_loop(adhandle, 0, packet_handler, nullptr);

        return 0;
    }

    void packet_handler(u_char *param,
                        const struct pcap_pkthdr *header,
                        const u_char *pkt_data) {
        auto *p_header = (header_type *) pkt_data;
        /* convert the timestamp to readable format */
        for (int i{0}; i < 6; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(p_header->MAC_DEST[i]);
            if (i < 5) {
                std::cout << ":";
            }
        }
        std::cout << "\t";
        for (int i{0}; i < 6; i++) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(p_header->MAC_SRC[i]);
            if (i < 5) {
                std::cout << ":";
            }
        }
        std::cout << "\t";
        if (ntohs(p_header->type) == 0x0800) {
            std::cout << "IPV4";
            std::cout << "\t\t";
            ipv4_header ipv4head(pkt_data + 14);
            switch (ipv4head.protocol) {
                case 1:
                    std::cout << "ICMP";
                    break;
                case 2:
                    std::cout << "IGMP";
                    break;
                case 6:
                    std::cout << "TCP";
                    break;
                case 17:
                    std::cout << "UDP";
                    break;
                case 41:
                    std::cout << "ENCAP";
                    break;
                case 89:
                    std::cout << "OSPF";
                    break;
                case 132:
                    std::cout << "SCTP";
                    break;
                default:
                    std::cout << "parsing failed";
            }
            std::cout << "\t\t";
            std::cout << std::dec // switch back to decimal from hex
                    << static_cast<int>(ipv4head.source_addr[0]) << "."
                    << static_cast<int>(ipv4head.source_addr[1]) << "."
                    << static_cast<int>(ipv4head.source_addr[2]) << "."
                    << static_cast<int>(ipv4head.source_addr[3]);
            std::cout << "\t\t";
            std::cout << std::dec // switch back to decimal from hex
                    << static_cast<int>(ipv4head.dest_addr[0]) << "."
                    << static_cast<int>(ipv4head.dest_addr[1]) << "."
                    << static_cast<int>(ipv4head.dest_addr[2]) << "."
                    << static_cast<int>(ipv4head.dest_addr[3]);
            std::cout << std::endl;
        } else if (ntohs(p_header->type) == 0x86DD) {
            std::cout << " Type: " << "IPV6" << std::endl;
        }

        //decoding the ipv4 header now
    }
};
