//
// Created by lhbdawn on 04-07-2026.
//
#include "pcap.h"
#include <iostream>
#include "socket.hpp"

#include <format>
#include <winsock2.h>

namespace Socket {
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
        pcap_freealldevs(alldevs);
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
        pcap_loop(adhandle,0,packet_handler, nullptr);

        return 0;
    }

    void packet_handler(u_char *param,
                        const struct pcap_pkthdr *header,
                        const u_char *pkt_data) {
        struct tm ltime;
        char timestr[16];
        time_t local_tv_sec;

        /*
         * unused variables
         */
        (VOID) (param);
        (VOID) (pkt_data);

        /* convert the timestamp to readable format */
        local_tv_sec = header->ts.tv_sec;
        localtime_s(&ltime, &local_tv_sec);
        strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);

        printf("%s,%.6d len:%d\n",
               timestr, header->ts.tv_usec, header->len);
        std::cout << pkt_data;
    }
};
