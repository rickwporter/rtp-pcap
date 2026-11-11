#include <arpa/inet.h>  // for ntohs()
#include <netinet/in.h> // for IPPROTO_UDP
#include <string.h>     // for memset(), memcpy()

#include "packet_utilities.h"

void rtp_pcap_iph_byteswap(iphdr_t *iph) {
    iph->tot_len = ntohs(iph->tot_len);
    iph->id = ntohs(iph->id);
    iph->frag_off = ntohs(iph->frag_off);
    iph->check = ntohs(iph->check);
    iph->saddr = ntohl(iph->saddr);
    iph->daddr = ntohl(iph->daddr);
}

void rtp_pcap_udph_byteswap(udphdr_t *udph) {
    udph->source = ntohs(udph->source);
    udph->dest = ntohs(udph->dest);
    udph->len = ntohs(udph->len);
    udph->check = ntohs(udph->check);
}

int rtp_pcap_get_next_packet(pcap_t *pcap_file, uint32_t *total_packets, rtp_pcap_filter_t *filter, rtp_pcap_pkt_t *pkt) {
    uint8_t data_buffer[PKT_BUF_BYTES];
    const unsigned char *pcap_data;
    struct pcap_pkthdr *pcap_header_ptr = NULL;
    iphdr_t *iph;
    udphdr_t *udph;
    uint16_t eth_type;
    uint16_t ip_offset; // typical ethernet

    memset(pkt, 0, sizeof(*pkt));

    while (pcap_next_ex(pcap_file, &pcap_header_ptr, &pcap_data) == 1) {
        memset(data_buffer, 0, PKT_BUF_BYTES);
        memcpy(data_buffer, pcap_data, pcap_header_ptr->caplen);

        *total_packets += 1;
        ip_offset = 14; // typical Ethernet

        // TODO: make multiple vlan friendly
        eth_type = ntohs(*(uint16_t *)((unsigned long)data_buffer + 12)); // pointer to Ethernet type
        if (eth_type == 0x8100) {
            // add 4 bytes for size of VLAN header
            DEBUG_PRINT("pkt[%u]: adding 4-bytes for VLAN header (type=0X%x)\n", *total_packets, eth_type);
            ip_offset += 4;
        }
        // ignore non-IP, non-VLAN packets
        else if (eth_type != 0x0800) {
            DEBUG_PRINT("pkt[%u]: non-IP packet (type=0X%x)\n", *total_packets, eth_type);
            continue;
        }

        iph = (iphdr_t *)((unsigned long)data_buffer + ip_offset);
        rtp_pcap_iph_byteswap(iph);

        // ignore non-UDP packets
        if (iph->protocol != IPPROTO_UDP) {
            DEBUG_PRINT("pkt[%u]: non-UDP packet (proto=%d)\n", *total_packets, iph->protocol);
            continue;
        }

        // if a different destination IP address, ignore it
        if ((filter->flags & FILTER_FLAG_DADDR_SET) && iph->daddr != filter->daddr) {
            DEBUG_PRINT(
                "pkt[%u]: address (0x%08x) does not match destination filter "
                "(0x%08x)\n",
                *total_packets,
                iph->daddr,
                filter->daddr
            );
            continue;
        }

        if ((filter->flags & FILTER_FLAG_SADDR_SET) && iph->saddr != filter->saddr) {
            DEBUG_PRINT(
                "pkt[%u]: address (0x%08x) does not match source "
                "filter (0x%08x)\n",
                *total_packets,
                iph->saddr,
                filter->saddr
            );
            continue;
        }

        udph = (udphdr_t *)((unsigned long)iph + (iph->ihl << 2));
        rtp_pcap_udph_byteswap(udph);

        // if a different destination UDP port, ignore it
        if ((filter->flags & FILTER_FLAG_DPORT_SET) && udph->dest != filter->dport) {
            DEBUG_PRINT(
                "pkt[%u]: port (0x%04x) does not match destination "
                "filter (0x%04x)\n",
                *total_packets,
                udph->dest,
                filter->dport
            );
            continue;
        }

        if ((filter->flags & FILTER_FLAG_SPORT_SET) && udph->source != filter->sport) {
            DEBUG_PRINT(
                "pkt[%u]: port (0x%04x) does not match source filter "
                "(0x%04x)\n",
                *total_packets,
                udph->source,
                filter->sport
            );
            continue;
        }

        // we've got a match, copy it to the packet
        pkt->pcap_hdr = *pcap_header_ptr;
        memcpy(pkt->buffer, data_buffer, sizeof(pkt->buffer));
        pkt->iph = (iphdr_t *)((unsigned long)pkt->buffer + (unsigned long)iph - (unsigned long)data_buffer);
        pkt->udph = (udphdr_t *)((unsigned long)pkt->buffer + (unsigned long)udph - (unsigned long)data_buffer);
        pkt->rtph = (rtphdr_t *)(pkt->udph + 1);
        return 0;
    } // while

    return -1;
}
