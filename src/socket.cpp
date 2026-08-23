//
// Created by lhbdawn on 04-07-2026.
//

#include "socket.hpp"

#include <stop_token>

namespace Socket {
    const MyModel *mymodel;

    struct header_type {
        uint8_t MAC_DEST[6];
        uint8_t MAC_SRC[6];
        uint16_t type;
    };

    struct ipv4_header {
        uint8_t protocol;
        uint8_t source_addr[4];
        uint8_t dest_addr[4];

        explicit ipv4_header(const u_char *pkt) {
            protocol = pkt[9];
            memcpy(source_addr, pkt + 12, 4);
            memcpy(dest_addr, pkt + 16, 4);
        }
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

    void handle_ipv4packet(packet_info &newpacket, const uchar *pkt_data) {
        newpacket.int_type = "IPV4";
        ipv4_header ipv4head(pkt_data + 14);
        switch (ipv4head.protocol) {
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
        newpacket.ip4_src = QString::asprintf("%d.%d.%d.%d", ipv4head.source_addr[0], ipv4head.source_addr[1],
                                              ipv4head.source_addr[2], ipv4head.source_addr[3]);

        newpacket.ip4_dest = QString::asprintf("%d.%d.%d.%d", ipv4head.dest_addr[0], ipv4head.dest_addr[1],
                                               ipv4head.dest_addr[2], ipv4head.dest_addr[3]);
    }

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
                handle_ipv4packet(newpacket, pkt_data);
                break;
            case 0x86DD:
                newpacket.int_type = "IPV6";
                break;
            case 0x0806:
                newpacket.int_type = "ARP";
                break;
            default: ;
        }
        emit model->newpacketready(newpacket);
        emit model->newpacketadded();
    }
};
