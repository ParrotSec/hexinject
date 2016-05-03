#ifndef __PRETTYPACKET_H__
#define __PRETTYPACKET_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hexstring.h"

/**
 * Enable disable colored output (enabled by default)
 */
static int colored_output = 1;

/**
 * List of available colors
 */
static const char *colors[] = {
    /// Black
    "\\e[0;30m",
    /// Red
    "\\e[0;31m",
    /// Green
    "\\e[0;32m",
    /// Yellow
    "\\e[0;33m",
    /// Blue
    "\\e[0;34m",
    /// Purple
    "\\e[0;35m",
    /// Cyan
    "\\e[0;36m",
    /// White
    "\\e[0;37m",
};

/**
 * Reset color
 */
static const char *color_reset = "\\e[0m";

/**
 * Default terminal rows
 */
static const int rows = 24;

/**
 * Default terminal columns
 */
static const int cols = 80;

/**
 * Example ARP packet
 */
static const char arp_packet[] = "\xFF\xFF\xFF\xFF\xFF\xFF\xAA\x00\x04\x00\x0A\x04\x08\x06\x00\x01\x08\x00\x06\x04\x00\x01\xAA\x00\x04\x00\x0A\x04\xC0\xA8\x01\x09\x00\x00\x00\x00\x00\x00\xC0\xA8\x01\x04";

/**
 * Example TCP packet
 */
static const char tcp_packet[] = "\x1C\xAF\xF7\x6B\x0E\x4D\xAA\x00\x04\x00\x0A\x04\x08\x00\x45\x00\x00\x34\x5A\xAE\x40\x00\x40\x06\x5E\x67\xC0\xA8\x01\x09\x58\xBF\x67\x3E\x9B\x44\x00\x50\x8E\xB5\xC6\xAC\x15\x93\x47\x9E\x80\x10\x00\x58\xA5\xA0\x00\x00\x01\x01\x08\x0A\x00\x09\xC3\xB2\x42\x5B\xFA\xD6";

/**
 * Example ICMP packet
 */
static const char icmp_packet[] = "\x1C\xAF\xF7\x6B\x0E\x4D\xAA\x00\x04\x00\x0A\x04\x08\x00\x45\x00\x00\x54\x00\x00\x40\x00\x40\x01\x54\x4E\xC0\xA8\x01\x09\xC0\xA8\x64\x01\x08\x00\x34\x98\xD7\x10\x00\x01\x5B\x68\x98\x4C\x00\x00\x00\x00\x2D\xCE\x0C\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2A\x2B\x2C\x2D\x2E\x2F\x30\x31\x32\x33\x34\x35\x36\x37";

/**
 * Example UDP packet
 */
static const char udp_packet[] = "\x1C\xAF\xF7\x6B\x0E\x4D\xAA\x00\x04\x00\x0A\x04\x08\x00\x45\x00\x00\x3C\x9B\x23\x00\x00\x40\x11\x70\xBC\xC0\xA8\x01\x09\xD0\x43\xDC\xDC\x91\x02\x00\x35\x00\x28\x6F\x0B\xAE\x9C\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03\x77\x77\x77\x06\x67\x6F\x6F\x67\x6C\x65\x03\x63\x6F\x6D\x00\x00\x01\x00\x01";

/**
 * Example IGMP packet
 */
static const char igmp_packet[] = "\x1C\xAF\xF7\x6B\x0E\x4D\xAA\x00\x04\x00\x0A\x04\x08\x00\x45\x00\x00\x1C\x00\x00\x40\x00\x40\x02\x54\x4E\xC0\xA8\x01\x09\xC0\xA8\x64\x01\x11\xFF\x0D\xFF\xE0\x00\x00\x01";

/**
 * Example Spanning Tree Protocol (STP) packet
 */
static const char stp_packet[]="\x01\x80\xc2\x00\x00\x00\x00\x1c\x0e\x87\x85\x04\x00\x26\x42\x42\x03\x00\x00\x00\x00\x00\x80\x64\x00\x1c\x0e\x87\x78\x00\x00\x00\x00\x04\x80\x64\x00\x1c\x0e\x87\x85\x00\x80\x04\x01\x00\x14\x00\x02\x00\x0f\x00";

// functions that need prototypes
void layer_2_dispatcher(const char *, int, uint64_t);
void layer_3_dispatcher(const char *, int, uint64_t);
void layer_4_dispatcher(const char *, int, uint64_t);

/**
 * Return the successive color iterating on colors
 *
 * @return pointer to the next color string
 */
const char *next_color() {
    static int total_colors = sizeof(colors)/sizeof(char *);
    static int index = -1;

    return colors[ (++index) % total_colors ];
}

/**
 * Extract protocol number (8bit version)
 *
 * @param packet_buffer raw packet captured from the network
 * @param counter protocol number offset
 * @return protocol number in host format
 */
inline uint8_t protocol_8bit_extract(const char *packet_buffer, int counter) {
    return *(packet_buffer + counter);
}

/**
 * Extract protocol number (16bit version)
 *
 * @param packet_buffer raw packet captured from the network
 * @param counter protocol number offset
 * @return protocol number in host format
 */
inline uint16_t protocol_16bit_extract(const char *packet_buffer, int counter) {
    return ntohs(*((uint16_t *)(packet_buffer + counter)));
}

/**
 * Extract protocol type from ethernet Destination MAC Address (48bit)
 * @param packet_buffer raw packet captured from the network
 * @param counter protocol number offset
 * @return protocol number in host format
 */
inline uint64_t protocol_48bit_extract(const char *packet_buffer, int counter) {
    uint64_t value = 0;

    int i;
    for(i=0; i < 6; i++) {
	uint8_t byte =  *((uint8_t *)(packet_buffer + counter + i));

	value = byte + (value * 256);
    }

    return value;
}

/**
 * Diplay a single field of an header
 *
 * @param packet_buffer raw packet captured from the network, starting at the part to process
 * @param field_size size in bytes of the field to print
 * @param counter read bytes counter
 * @param field_text description of the field
 */
inline field_print (const char *packet_buffer, int field_size, int *counter, const char *field_text) {
    
    char *tmp_hexstr = raw_to_hexstr(packet_buffer + *counter, field_size);
    *counter += field_size;

    printf(" %-24s %s\n", tmp_hexstr, field_text);
    
    free(tmp_hexstr);
}

/**
 * Print the payload part of the packet
 *
 * @param packet_buffer raw packet captured from the network, starting at the part to process
 * @param size packet_buffer size
 */
void payload_print (const char *packet_buffer, int size) {
    
    if (size < 1) {
        return;
    }
    
    puts("\nPayload or Trailer:");

    int bytes_per_row = cols / BYTE_MULT;

    int i, j=0;

    // new line
    while (j < size) {
       
        // bytes in the line
        for (i = 0; (i < bytes_per_row) && (j < size); i++, j++) { // columns
            char str[BYTE_MULT];

            hex_to_str(packet_buffer[j], str);

            printf(" %s", str);
        }
        
        puts("");
    }

}

/**
 * Print the TCP header of the packet
 *
 * @param packet_buffer raw packet captured from the network, starting at the part to process
 * @param size packet_buffer size
 */
void tcp_print (const char *packet_buffer, int size) {
    int counter = 0;

    puts("\nTCP Header:");

    if (size < 8) {
        puts (" invalid header size");
        return;
    }

    // print header fields
    field_print(packet_buffer, 2, &counter, "Source port");
    field_print(packet_buffer, 2, &counter, "Destination port");
    field_print(packet_buffer, 4, &counter, "Sequence number");
    field_print(packet_buffer, 4, &counter, "Acknowledgement number");
    field_print(packet_buffer, 1, &counter, "Header length");
    field_print(packet_buffer, 1, &counter, "Flags");
    field_print(packet_buffer, 2, &counter, "Window");
    field_print(packet_buffer, 2, &counter, "Checksum");
    field_print(packet_buffer, 2, &counter, "Urgent pointer");

    // print remaining payload
    payload_print(packet_buffer + counter, size - counter);
}

/**
 * Print the UDP header of the packet
 *
 * @param packet_buffer raw packet captured from the network, starting at the part to process
 * @param size packet_buffer size
 */
void udp_print (const char *packet_buffer, int size) {
    int counter = 0;

    puts("\nUDP Header:");

    if (size < 8) {
        puts (" invalid header size");
        return;
    }

    // print header fields
    field_print(packet_buffer, 2, &counter, "Source port");
    field_print(packet_buffer, 2, &counter, "Destination port");
    field_print(packet_buffer, 2, &counter, "Length");
    field_print(packet_buffer, 2, &counter, "Checksum");

    // print remaining payload
    payload_print(packet_buffer + counter, size - counter);
}

/**
 * Print the ICMP header of the packet
 *
 * @param packet_buffer raw packet captured from the network, starting at the part to process
 * @param size packet_buffer size
 */
void icmp_print (const char *packet_buffer, int size) {
    int counter = 0;

    puts("\nICMP Header:");

    if (size < 8) {
        puts (" invalid header size");
        return;
    }

    // print header fields
    field_print(packet_buffer, 1, &counter, "Type");
    field_print(packet_buffer, 1, &counter, "Code");
    field_print(packet_buffer, 2, &counter, "Checksum");
    field_print(packet_buffer, 2, &counter, "ID");
    field_print(packet_buffer, 2, &counter, "Sequence number");

    // print remaining payload
    payload_print(packet_buffer + counter, size - counter);
}

/**
 * Print the IGMP header of the packet
 *
 * @param packet_buffer raw packet captured from the network, starting at the part to process
 * @param size packet_buffer size
 */
void igmp_print (const char *packet_buffer, int size) {
    int counter = 0;

    puts("\nIGMP Header:");

    if (size < 8) {
        puts (" invalid header size");
        return;
    }

    // print header fields
    field_print(packet_buffer, 1, &counter, "Type");
    field_print(packet_buffer, 1, &counter, "Max response time");
    field_print(packet_buffer, 2, &counter, "Checksum");
    field_print(packet_buffer, 4, &counter, "Group address");

    // print remaining payload
    payload_print(packet_buffer + counter, size - counter);
}

/**
 * Print the IP header of the packet
 *
 * @param packet_buffer raw packet captured from the network, starting at the part to process
 * @param size packet_buffer size
 */
void ip_print (const char *packet_buffer, int size) {
    int counter = 0;

    puts("\nIP Header:");

    if (size < 20) {
        puts (" invalid header size");
        return;
    }

    // print header fields
    field_print(packet_buffer, 1, &counter, "Version / Header length");
    field_print(packet_buffer, 1, &counter, "ToS / DFS");
    field_print(packet_buffer, 2, &counter, "Total length");
    field_print(packet_buffer, 2, &counter, "ID");
    field_print(packet_buffer, 2, &counter, "Flags / Fragment offset");
    field_print(packet_buffer, 1, &counter, "TTL");

    int next_protocol = protocol_8bit_extract(packet_buffer, counter);
    field_print(packet_buffer, 1, &counter, "Protocol");

    field_print(packet_buffer, 2, &counter, "Checksum");
    field_print(packet_buffer, 4, &counter, "Source address");
    field_print(packet_buffer, 4, &counter, "Destination address");

    // go up to the next layer
    layer_4_dispatcher(packet_buffer + counter, size - counter, next_protocol);
}

/**
 * Print the ARP header of the packet
 *
 * @param packet_buffer raw packet captured from the network, starting at the part to process
 * @param size packet_buffer size
 */
void arp_print (const char *packet_buffer, int size) {
    int counter = 0;

    puts("\nARP Header:");

    if (size < 28) {
        puts (" invalid header size");
        return;
    }

    // print header fields
    field_print(packet_buffer, 2, &counter, "Hardware type");
    field_print(packet_buffer, 2, &counter, "Protocol type");

    int hs = *(packet_buffer + counter);
    field_print(packet_buffer, 1, &counter, "Hardware size");

    int ps = *(packet_buffer + counter);
    field_print(packet_buffer, 1, &counter, "Protocol size");

    field_print(packet_buffer, 2, &counter, "Opcode");

    field_print(packet_buffer, hs, &counter, "Sender hardware address");
    field_print(packet_buffer, ps, &counter, "Sender protocol address");
    field_print(packet_buffer, hs, &counter, "Target hardware address");
    field_print(packet_buffer, ps, &counter, "Target protocol address");

    // print remaining payload
    payload_print(packet_buffer + counter, size - counter);
}

/**
 * Print the ETHERNET header of the packet
 *
 * @param packet_buffer raw packet captured from the network, starting at the part to process
 * @param size packet_buffer size
 */
void ethernet_print (const char *packet_buffer, int size) {
    int counter = 0;

    puts("\nEthernet Header:");

    if (size < 14) {
        puts (" invalid header size");
        return;
    }

    // print header fields
    uint64_t dst_mac = protocol_48bit_extract(packet_buffer, counter);
    field_print(packet_buffer, 6, &counter, "Destination hardware address");
    field_print(packet_buffer, 6, &counter, "Source hardware address");

    int next_protocol = protocol_16bit_extract(packet_buffer, counter);
    field_print(packet_buffer, 2, &counter, "Lenght/Type");

    /*
     * if the last field value is less or equal to 1500 is a lenght
     * otherwise is a protocol type (check IEEE 802.3 documentation...)
     */

    if (next_protocol > 1500) {

	// go up to the next layer
	layer_3_dispatcher(packet_buffer + counter, size - counter, next_protocol);
    
    } else {

	// remain on the same layer
	layer_2_dispatcher(packet_buffer + counter, size - counter, dst_mac);
	
    }
}

/**
 * Print the ISL header of the packet
 *
 * @param packet_buffer raw packet captured from the network, starting at the part to process
 * @param size packet_buffer size
 */
void isl_print (const char *packet_buffer, int size) {
    int counter = 0;

    puts("\nISL Header:");

    if (size < 30) {
        puts (" invalid header size");
        return;
    }

    // print header fields
    field_print(packet_buffer, 5, &counter, "Destination");


    int next_protocol = protocol_8bit_extract(packet_buffer, counter);
    next_protocol >>= 4;

    field_print(packet_buffer, 1, &counter, "Type/User");
    field_print(packet_buffer, 6, &counter, "Source");
    field_print(packet_buffer, 2, &counter, "Length");
    field_print(packet_buffer, 1, &counter, "DSAP");
    field_print(packet_buffer, 1, &counter, "SSAP");
    field_print(packet_buffer, 1, &counter, "Control");
    field_print(packet_buffer, 3, &counter, "HSA");
    field_print(packet_buffer, 2, &counter, "Vlan ID/BPDU");
    field_print(packet_buffer, 2, &counter, "Index");
    field_print(packet_buffer, 2, &counter, "RES");

    /*
     * Note: we subtrack 4 to the size of the packet to exclude
     * the final frame check sequence
     */

    if (next_protocol == 0) {

	// go up to the next layer
	ethernet_print(packet_buffer + counter, size - counter - 4);
    
    } else {

	// go up to the next layer
	payload_print(packet_buffer + counter, size - counter - 4);
	
    }

    counter = size - 4;

    puts("\nISL Header (end):");

    field_print(packet_buffer, 4, &counter, "Frame check seq.");
}

/**
 * Print the DTP header of the packet
 *
 * @param packet_buffer raw packet captured from the network, starting at the part to process
 * @param size packet_buffer size
 */
void dtp_print (const char *packet_buffer, int size) {
    int counter = 0;

    puts("\nDinamic Trunking Protocol Header:");

    if (size < 29) {
        puts (" invalid header size");
        return;
    }

    // print header fields
    field_print(packet_buffer, 1, &counter, "Version");
    field_print(packet_buffer, 8, &counter, "Domain");

    field_print(packet_buffer, 5, &counter, "Status");
    field_print(packet_buffer, 5, &counter, "DTP Type");

    field_print(packet_buffer, 8, &counter, "Neighbor");
    field_print(packet_buffer, 2, &counter, ""); // splitted since too long...

    // print remaining payload
    payload_print(packet_buffer + counter, size - counter);
}

/**
 * Print the STP header of the packet
 *
 * @param packet_buffer raw packet captured from the network, starting at the part to process
 * @param size packet_buffer size
 */
void stp_print (const char *packet_buffer, int size) {
    int counter = 0;

    puts("\nSpanning Tree Protocol Header:");

    if (size < 38) {
        puts (" invalid header size");
        return;
    }

    // print header fields
    field_print(packet_buffer, 2, &counter, "Protocol Identifier");
    field_print(packet_buffer, 1, &counter, "Protocol Version Identifier");

    field_print(packet_buffer, 1, &counter, "BPDU Type");
    field_print(packet_buffer, 1, &counter, "BPDU Flags");

    field_print(packet_buffer, 2, &counter, "Root Priority/System ID Extension");
    field_print(packet_buffer, 6, &counter, "Root System ID");

    field_print(packet_buffer, 4, &counter, "Root Path Cost");

    field_print(packet_buffer, 2, &counter, "Bridge Priority/System ID Extension");
    field_print(packet_buffer, 6, &counter, "Bridge System ID");

    field_print(packet_buffer, 2, &counter, "Port Identifier");
    field_print(packet_buffer, 2, &counter, "Message Age");
    field_print(packet_buffer, 2, &counter, "Max Age");
    field_print(packet_buffer, 2, &counter, "Hello Time");
    field_print(packet_buffer, 2, &counter, "Forward Delay");

    // print remaining payload
    payload_print(packet_buffer + counter, size - counter);
}

/**
 * Print the LLC header of the packet
 *
 * @param packet_buffer raw packet captured from the network, starting at the part to process
 * @param size packet_buffer size
 */
void llc_print (const char *packet_buffer, int size) {
    int counter = 0;

    puts("\nLogical-Link Control Header:");

    if (size < 3) {
        puts (" invalid header size");
        return;
    }

    // print header fields
    int dsap = protocol_8bit_extract(packet_buffer, counter);
    field_print(packet_buffer, 1, &counter, "DSAP");

    int ssap = protocol_8bit_extract(packet_buffer, counter);
    field_print(packet_buffer, 1, &counter, "SSAP");

    field_print(packet_buffer, 1, &counter, "Control field");

    if (dsap == 0x42 && ssap == 0x42) {

	// spanning tree protocol
	stp_print(packet_buffer + counter, size - counter);

    } else if (dsap == 0xaa && ssap == 0xaa) {
    
	if (size < 8) {
	    puts (" invalid header size");
	    return;
	}

	// continue printing LLC fields
	field_print(packet_buffer, 3, &counter, "Organization code");
	
	int pid = protocol_16bit_extract(packet_buffer, counter);
	field_print(packet_buffer, 2, &counter, "PID");

	if (pid == 0x2004) {

	    // dinamic trunking protocol
	    dtp_print(packet_buffer + counter, size - counter);

	} else {

	    // print remaining payload
	    payload_print(packet_buffer + counter, size - counter);

	}

    }
	
}

/**
 * Determine the packet type and call the appropriate function to disassemble it.
 * Operates on layer 2 (OSI model) packet's headers.
 *
 * @param packet_buffer raw packet captured from the network, starting at layer 2
 * @param size packet_buffer size
 * @param protocol protocol number
 */
void layer_2_dispatcher (const char *packet_buffer, int size, uint64_t protocol) {

    uint64_t llc1 = 0x0180C20000LLU, llc2 = 0x01000CCCCCCCLLU;

    if (size < 1) {
        return;
    }

    if (memcmp(packet_buffer, "\x01\x00\x0C\x00\x00", 5)==0 ||
	memcmp(packet_buffer, "\x03\x00\x0c\x00\x00", 5)==0 ) {

	isl_print(packet_buffer, size);

    } else if ((protocol / 256) == llc1) {

	llc_print(packet_buffer, size); // spanning tree

    } else if (protocol == llc2) {

	llc_print(packet_buffer, size);

    } else {

	ethernet_print(packet_buffer, size);

    }

}

/**
 * Determine the packet type and call the appropriate function to disassemble it.
 * Operates on layer 3 (OSI model) packet's headers.
 *
 * @param packet_buffer raw packet captured from the network, starting at layer 3
 * @param size packet_buffer size
 * @param protocol protocol number
 */
void layer_3_dispatcher (const char *packet_buffer, int size, uint64_t protocol) {

    if (size < 1) {
        return;
    }

    /*
     * if the last field value (of an ethernet header) is less or equal to 1500
     * then is a lenght otherwise is a protocol type (check IEEE 802.3 documentation...)
     */

    if (protocol <= 0xffff) { // check if it's a 16bit field
	                      // (i.e. last ethernet field was a protocol)
        switch (protocol) {

            case 0x0800: ip_print(packet_buffer, size); break;
            case 0x0806: arp_print(packet_buffer, size); break;

            default: payload_print(packet_buffer, size);

        }

    } else {
	payload_print(packet_buffer, size);
    }

}

/**
 * Determine the packet type and call the appropriate function to disassemble it.
 * Operates on layer 4 (OSI model) packet's headers.
 *
 * @param packet_buffer raw packet captured from the network, starting at layer 4
 * @param size packet_buffer size
 * @param protocol protocol number
 */
void layer_4_dispatcher (const char *packet_buffer, int size, uint64_t protocol) {
    
    if (size < 1) {
        return;
    }

    switch (protocol) {
        case 1:  icmp_print(packet_buffer, size); break;
        case 2:  igmp_print(packet_buffer, size); break;
        case 6:  tcp_print(packet_buffer, size); break;
        case 17: udp_print(packet_buffer, size); break;
        default: payload_print(packet_buffer, size);
    }

}


#endif /* __PRETTYPACKET_H__ */

