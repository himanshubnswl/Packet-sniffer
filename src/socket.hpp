#pragma once

#include "pcap.h"
#include <iostream>
#include <winsock2.h>
#include "mymodel.hpp"
#include <thread>

namespace Socket {
    pcap_if_t *selectdev(pcap_if_t* alldevs);

    pcap_if_t *getdevicelist();

    int printpackets(pcap_if_t *dev, MyModel* model, std::stop_token& stop_token);

    void packet_handler(u_char *param,
                        const struct pcap_pkthdr *header,
                        const u_char *pkt_data,
                        const timeval referencetime);

    void setmodelinstance(MyModel model);
};
