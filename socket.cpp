//
// Created by lhbdawn on 04-07-2026.
//
#include "pcap.h"
#include <iostream>
#include "socket.hpp"
#include <winsock2.h>

namespace Socket {
    void getdevices() {
        pcap_if_t* alldevs;
        int i = 0;
        char errbuf[PCAP_ERRBUF_SIZE];

        if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,nullptr,&alldevs,errbuf) == -1) {
            std::cerr << "cannot get device list" << std::endl;
            std::exit(0);
        }

        for (auto* d = alldevs; d != nullptr; d=d->next) {
            std::cout << ++i << "  " << d->name << std::endl;
            if (d->description) {
                std::cout << d->description << std::endl;
            }else {
                std::cout << "no description" << std::endl;
            }
            ifprint(d);
        }
        if (i == 0) {
            std::cout << "no devices to list!" << std::endl;
        }
            pcap_freealldevs(alldevs);
    }
};

