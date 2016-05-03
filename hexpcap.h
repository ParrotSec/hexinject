/**
 * HEXPCAP HEADER
 *
 * Utilities to sniff and inject packets (in raw or hexstring formats)
 * via pcap libraries.
 */

#ifndef HEXPCAP_H_
#define HEXPCAP_H_

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <assert.h>
#include <arpa/inet.h>

#include "hexstring.h"

/**
 * Checksum IP
 */
uint16_t ip_cksum (uint16_t *buff, size_t len)
{
    
    uint32_t sum = 0;
    uint16_t answer = 0;

    while(len > 1) {
        sum += *buff++;
        len -= 2;
    }

    if (len) {
        sum += * (uint8_t *) buff;
    }

    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    answer = ~sum;

    return(answer);
}

/**
 * Checksum TCP
 */
uint16_t tcp_cksum(uint16_t *src_addr, uint16_t *dest_addr, uint16_t *buff, uint16_t len)
{

    uint32_t sum = 0;
    uint16_t answer = 0;

    sum += src_addr[0];
    sum += src_addr[1];
    
    sum += dest_addr[0];
    sum += dest_addr[1];

    sum += htons(0x6);

    sum += htons(len);

    while(len > 1) {
        sum += *buff++;
        len -= 2;
    }

    if (len) {
        sum += * (uint8_t *) buff;
    }

    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    answer = ~sum;

    return(answer);
}

/**
 * Checksum UDP
 */
uint16_t udp_cksum(uint16_t *src_addr, uint16_t *dest_addr, uint16_t *buff, size_t len)
{
   
    uint32_t sum = 0;
    uint16_t answer = 0;
    
    sum += src_addr[0];
    sum += src_addr[1];
    
    sum += dest_addr[0];
    sum += dest_addr[1];

    sum += htons(0x11);

    sum += htons(len);

    while(len > 1) {
        sum += *buff++;
        len -= 2;
    }

    if (len) {
        sum += * (uint8_t *) buff;
    }

    while (sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    answer = ~sum;

    return(answer);
}

/**
 * Do checksum (if the packet requires it...)
 */
void do_cksum (char *raw, size_t size)
{
    
    uint16_t *cksum = NULL;

    // is ip?
    if ( size >= 34 && raw[12]==0x08  && raw[13]==0x00  ) {
       
        // ip checksum
        cksum = (uint16_t *) &raw[24];
        *cksum = 0;

        *cksum = ip_cksum((uint16_t *) &raw[14], 20);

        // next protocol
        switch(raw[23]) {

            // tcp
            case 0x06:
                if (size < 54) return; // size check
                cksum = (uint16_t *) &raw[50];
                *cksum = 0;
                *cksum = tcp_cksum((uint16_t *) &raw[26], (uint16_t *) &raw[30], (uint16_t *) &raw[34], (size-34));
                break;

            // udp
            case 0x11:
                if (size < 42) return; // size check
                cksum = (uint16_t *) &raw[40];
                *cksum = 0;
                *cksum = udp_cksum((uint16_t *) &raw[26], (uint16_t *) &raw[30], (uint16_t *) &raw[34], (size-34));
                break;

            // icmp
            case 0x01:
                if (size < 42) return; // size check
                cksum = (uint16_t *) &raw[36];
                *cksum = 0;
                *cksum = ip_cksum((uint16_t *) &raw[34], (size-34));
                break;

            // igmp
            case 0x02:
                if (size < 42) return; // size check
                cksum = (uint16_t *) &raw[36];
                *cksum = 0;
                *cksum = ip_cksum((uint16_t *) &raw[34], (size-34));
                break;
        }
    }
}

/**
 * Adjust packet size fields (if the packet requires it...)
 */
void do_size (char *raw, size_t size)
{
    
    uint16_t *len_field = NULL;

    // is ip?
    if ( size >= 34 && raw[12]==0x08  && raw[13]==0x00  ) {
       
        // ip total length
        len_field = (uint16_t *) &raw[16];

        *len_field = size - 14; // size - ethernet header
        *len_field = htons(*len_field);

        // next protocol
        switch(raw[23]) {

            // tcp
            case 0x06:
                if (size < 54) return; // size check
                // tcp uses header length field
                break;

            // udp
            case 0x11:
                if (size < 42) return; // size check
                len_field = (uint16_t *) &raw[38];
                *len_field = size - 14 - ((raw[14] & 0xF) * 4); // size - ethernet header - ip header
                *len_field = htons(*len_field);
                break;

            // icmp
            case 0x01:
                //if (size < 42) return; // size check
                // no size field
                break;

            // igmp
            case 0x02:
                //if (size < 42) return; // size check
                // no size field
                break;
        }
    }
}

/**
 * Inject a raw buffer to the network
 */
int inject_raw(pcap_t *fp, char *raw, size_t size, int disable_cksum, int disable_size)
{

    assert(fp != NULL);
    assert(raw != NULL);

    int err = 0;
    
    /* packet size (if enabled) */
    if(!disable_size) do_size (raw, size);

    /* checksum */
    if(!disable_cksum) do_cksum (raw, size);

    /* Send down the packet */
    err = pcap_sendpacket(fp, (unsigned char *) raw, size);

    return err;
}

/**
 * Inject an hexstring to the network
 */
int inject_hexstr(pcap_t *fp, char *hexstr, int disable_cksum, int disable_size)
{

    assert(fp != NULL);
    assert(hexstr != NULL);

    int err = 0;
    int size = 0;
    char *raw = NULL;

    raw = hexstr_to_raw(hexstr, &size);

    /* Send down the packet */
    err = inject_raw(fp, raw, size, disable_cksum, disable_size);

    free(raw);

    return err;
}

/**
 * Sniff a packet from the network as an hexstring. The hexstring must be manually free()d.
 */
char *sniff_hexstr(pcap_t *fp)
{

    assert(fp != NULL);

    struct pcap_pkthdr hdr;
    char *hexstr = NULL;
    char *raw    = NULL;

    /* Sniff the packet */
    raw = (char *) pcap_next(fp, &hdr);

    if(raw == NULL)
        return NULL;

    hexstr = raw_to_hexstr(raw, hdr.len);

    return hexstr;
}

/**
 * Sniff a packet from the network as a raw buffer. The buffer must NOT be modified or free()d.
 */
const uint8_t *sniff_raw(pcap_t *fp, size_t *size)
{

    assert(fp != NULL);
    assert(size != NULL);

    struct pcap_pkthdr hdr;
    const char *raw = NULL;

    /* Sniff the packet */
    raw = (const char *) pcap_next(fp, &hdr);

    *size = hdr.len;

    return raw;
}

#endif /* HEXPCAP_H_ */
