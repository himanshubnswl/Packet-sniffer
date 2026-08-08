#pragma once
namespace Socket {
    pcap_if_t *selectdev();

    pcap_if_t *getdevicelist();

    int printpackets(pcap_if_t *dev);

    void packet_handler(u_char *param,
                        const struct pcap_pkthdr *header,
                        const u_char *pkt_data);
};
