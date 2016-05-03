/*
 * prettypacket.c
 *
 *  Created on: 03/dec/2012
 *      Author: Acri Emanuele <crossbower@gmail.com>
 *
 * Disassemble network packet and print their fields.
 * Uses the stdin to receive raw packet data. Prints on stdout.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "prettypacket.h"

#define VERSION "1.5"

#define BUFFER_SIZE 8192

/**
 * Packet type arguments
 */
enum packet_type {
    no_type = 0,
    tcp,
    udp,
    icmp,
    igmp,
    arp,
    stp
};

/**
 * Packets disassembling loop
 */
int dis_packet_loop()
{

    char buffer[BUFFER_SIZE];
    ssize_t size;

    int input = fileno(stdin);

    while (!feof(stdin)) {

        /* Read raw */
        size = read(input, buffer, BUFFER_SIZE);

        /* Print sisassembled packet */
        layer_2_dispatcher(buffer, size, 0);

        /* Print end of packet */
        puts("\n ----------- ");
        fflush(stdout);

    }

    puts("");

    return 0;
}

/**
 * Print disassembled example packet
 */
void print_dis_example_packet (enum packet_type type) {
    switch (type) {
    case tcp:  layer_2_dispatcher(tcp_packet,  sizeof(tcp_packet)-1, 0);  break;
    case udp:  layer_2_dispatcher(udp_packet,  sizeof(udp_packet)-1, 0);  break;
    case icmp: layer_2_dispatcher(icmp_packet, sizeof(icmp_packet)-1, 0); break;
    case igmp: layer_2_dispatcher(igmp_packet, sizeof(igmp_packet)-1, 0); break;
    case arp:  layer_2_dispatcher(arp_packet,  sizeof(arp_packet)-1, 0);  break;
    case stp:  layer_2_dispatcher(stp_packet,  sizeof(stp_packet)-1, 0);  break;
    }
    puts("");
}

/**
 * Convert string to packet_type
 */
enum packet_type str_to_packet_type(const char *str)
{
    if (strcmp(str, "tcp") == 0)
        return tcp;
    if (strcmp(str, "udp") == 0)
        return udp;
    if (strcmp(str, "icmp") == 0)
        return icmp;
    if (strcmp(str, "igmp") == 0)
        return igmp;
    if (strcmp(str, "arp") == 0)
        return arp;
    if (strcmp(str, "stp") == 0)
        return stp;
    return no_type;
}

/**
 * Usage
 */
void usage(char *progname) {
    printf("PrettyPacket " VERSION " [disassembler for raw network packets]\n"
           "written by: Emanuele Acri <crossbower@gmail.com>\n\n"
           "Usage:\n"
           "\t%s [-x|-h]\n"
           "\nOptions:\n"
           "\t-x type\tprint example packet, to see its structure\n"
           "\t       \t(available types: tcp, udp, icmp, igmp, arp, stp)\n"
           "\t-h\tthis help screen\n", progname);
    exit(0);
}

/**
 * Main function
 */
int main(int argc, char **argv) {

    enum packet_type type = no_type;

    // check arguments
    if(argc > 1) {

        // print example packet
        if(!strcmp(argv[1], "-x")) {

            if(argc < 3) usage(argv[0]);

            type = str_to_packet_type(argv[2]);

            if(type == no_type) usage(argv[0]);
        }

        // unknown options
        else {
            usage(argv[0]);
        } 
    }

    // example packet
    if(type != no_type) {
        print_dis_example_packet(type);
    }

    // disassemble packets
    else {
        dis_packet_loop();
    }

    return 0;
}
