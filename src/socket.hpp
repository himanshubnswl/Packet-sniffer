#pragma once

#include "pcap.h"
#include <iostream>
#include <winsock2.h>
#include "mymodel.hpp"

namespace Socket {
    pcap_if_t *selectdev();

    pcap_if_t *getdevicelist();

    int printpackets(pcap_if_t *dev);

    void packet_handler(u_char *param,
                        const struct pcap_pkthdr *header,
                        const u_char *pkt_data);

    void setmodelinstance(MyModel model);
};
