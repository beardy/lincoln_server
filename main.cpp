//
//main.cpp ~ sniffer & database writer
//
// requires libpcap, mysql, mysql++
//
//design notes:
//
// A "stream" represents a set of packets traveling from a specific IP address
// and portnumber to another specific IP address and portnumber.
//
// A "window" aggregrates a set of packets within a stream over a small time interval (WINDOW_INTERVAL).
//
// The program maintains a list of "active streams". A stream is active as long as a packet
// belonging to it has been recieved in the last WINDOW_INTERVAL seconds.
//
// When a new packet is received, either another stream is created and the packet added to it, or it is
// added to an active stream.
//
//  -If a new stream is created, so is a new window.
//
//  -If it is added to an active stream,
//
// The sniffer detects TCP packets
//
//
// a "packet belonging to a stream" means that it has matching port_number, IP_source and IP_destination
// a "packet belonging to a window" means that it was received in the window's 5 minute time interval
//
//
//
//1. New TCP packet is sniffed:
//2. If packet DOES NOT belong to a stream in CACHE:
//      -create new stream, create new window, add both to DB and cache.
//3. If packet DOES belong to a stream in CACHE:
//      -If the current window is over,
//          -close the window
//          -create new window
//       else
//          -
//

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <vector>
using namespace std;

#include "LincolnDatatypes.h"
#include "DatabaseInterface.h"
#include "Config.h"

// default snap length (maximum bytes per packet to capture)
#define SNAP_LEN 1518

// ethernet headers are always exactly 14 bytes [1]
#define SIZE_ETHERNET 14

// Ethernet addresses are 6 bytes
#define ETHER_ADDR_LEN	6

// Ethernet header
struct sniff_ethernet
{
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

// IP header
struct sniff_ip
{
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

// TCP header
typedef u_int tcp_seq;

struct sniff_tcp
{
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);


//Windows are at most 300 seconds long (5 minutes)
#define WINDOW_TIME 20


 // activeStreams are the streams that are currently open,
 // Streams that have at least one closed window have been added to the DB.
 // Streams are removed from activeStreams when their last window was closed WINDOW_TIME ago.

 map<StreamKey, Stream,  LessStreamKey> activeStreams;

 DatabaseInterface dbinterface;
 Config config;

 time_t sniff_time;
 time_t last_time;


void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    //hash_map<const char*, int, hash<const char*>, eqstr> months;

    //unordered_set<Stream, SameStream> activeStreams;


	static int count = 1;                   // packet counter

	// declare pointers to packet headers
	const struct sniff_ethernet *ethernet;  // The ethernet header [1]
	const struct sniff_ip *ip;              // The IP header
	const struct sniff_tcp *tcp;            // The TCP header
	//const u_char *payload;                 // Packet payload

	int size_ip;
	int size_tcp;
	//int size_payload;

	printf("\nPacket number %d:\n", count);
	count++;

	// define ethernet header
	ethernet = (struct sniff_ethernet*)(packet);

	// define/compute ip header offset
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20)
	{
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	// print source and destination IP addresses
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	// determine protocol
	switch(ip->ip_p)
	{
		case IPPROTO_TCP:
			printf("   Protocol: TCP\n");
			break;
		case IPPROTO_UDP:
			printf("   Protocol: UDP\n");
			return;
		case IPPROTO_ICMP:
			printf("   Protocol: ICMP\n");
			return;
		case IPPROTO_IP:
			printf("   Protocol: IP\n");
			return;
		default:
			printf("   Protocol: unknown\n");
			return;
	}

	/*
	 *  OK, this packet is TCP.
	 */

	// define/compute tcp header offset
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20)
	{
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));



	StreamKey streamKey;
	streamKey.raw_ip_incoming = ip->ip_dst;
	streamKey.raw_ip_outgoing = ip->ip_src;
	streamKey.port_incoming = tcp->th_dport;
	streamKey.port_outgoing = tcp->th_sport;


	Stream tempStream;
	//ID of zero means it hasn't been added to the db yet
	tempStream.id = 0;
	tempStream.raw_ip_incoming = ip->ip_dst;
	tempStream.raw_ip_outgoing = ip->ip_src;
	tempStream.port_incoming = tcp->th_dport;
	tempStream.port_outgoing = tcp->th_sport;

	//printf("STREAM INSERT ID: %d\n", dbinterface.InsertStream(tempStream1) );



    //TODO: Need to determine if it's incoming or not.
	bool incoming= config.IsLocal( inet_ntoa(ip->ip_src) );
	if(incoming)
        printf("Incoming Packet\n");
	else
        printf("Outgoing Packet\n");

	int packet_length = ip->ip_len;

	sniff_time = time(NULL);

	//unordered_set<Stream>::iterator iter = activeStreams.find(tempStream);

	// Find the stream that matches packet
    map<StreamKey, Stream,  LessStreamKey>::iterator iter = activeStreams.find(streamKey);

    // If the stream is not found,
	if( iter == activeStreams.end() )
	{
	    // Then we need to create a stream, which
	    // requires we create a window.

        Window tempWindow;

        // The stream this window belongs to isnt in the DB yet,
        // so it has no id.

        tempWindow.stream_id = 0;


        tempWindow.start_time = sniff_time;
        tempWindow.end_time = sniff_time;

        if(incoming)
        {
            tempWindow.num_packets_incoming = 1;
            tempWindow.num_packets_outgoing = 0;
            tempWindow.size_packets_incoming = packet_length;
            tempWindow.size_packets_outgoing = 0;
        }
        else
        {
            tempWindow.num_packets_incoming = 0;
            tempWindow.num_packets_outgoing = 1;
            tempWindow.size_packets_incoming = 0;
            tempWindow.size_packets_outgoing = packet_length;
        }

        // Okay, window's ready. Stream time.
        // We just need to create a new element in activeStream,
        // and set it's current_window to tempWindow

        tempStream.current_window = tempWindow;
        activeStreams.insert( pair<StreamKey, Stream>(streamKey, tempStream) );


        //printf("WINDOW INSERT ID: %d\n",  dbinterface.InsertWindow(tempWindow) );
	}
	else // Packet belongs to an active stream!
	{

	    // Let's update current_window of the stream it belongs to.
	    iter->second.current_window.end_time = sniff_time;

        if(incoming)
        {
            iter->second.current_window.size_packets_incoming += packet_length;
            iter->second.current_window.num_packets_incoming++;
            //activeWindows[iter->id].size_packets_incoming += packet_length;
            //activeWindows[iter->id].num_packets_incoming++;
        }
        else
        {
            iter->second.current_window.size_packets_outgoing += packet_length;
            iter->second.current_window.num_packets_outgoing++;
            //activeWindows[iter->id].size_packets_outgoing += packet_length;
            //activeWindows[iter->id].num_packets_outgoing++;
        }

	}


return;
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "tcp";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */

	//For now, lets just capture a certain number of packets.
	int num_packets = 20;			/* number of packets to capture */


	// check for capture device name on command-line
	if (argc == 2)
	{
		dev = argv[1];
	}
	else if (argc > 2)
	{
		fprintf(stderr, "error: unrecognized command-line options\n\n");
		exit(EXIT_FAILURE);
	}
	else
	{
		/* find a capture device if not specified on command-line */
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL)
		{
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			exit(EXIT_FAILURE);
		}
	}

	/* get network number and mask associated with capture device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n",
		    dev, errbuf);
		net = 0;
		mask = 0;
	}

	/* print capture info */
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	/* open capture device */
	handle = pcap_open_live(dev, SNAP_LEN, 0, 1000, errbuf);
	if (handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}

	/* make sure we're capturing on an Ethernet device [2] */
	if (pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	/* compile the filter expression */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the compiled filter */
	if (pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n",
		    filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	dbinterface.EstablishConnection();
	config.Load( "config.txt" );

    bool done = false;

    // last_time stores the last time we did window garbage collection
    last_time = time(NULL);
    time_t current_time;

    while( !done )
    {
        current_time = time(NULL);

        //  ~~Sniffing:
        //  Set a callback function to process each batch of packets.

        pcap_dispatch(handle, num_packets, got_packet, NULL);

        //  ~~Garbage Collection:
        //  Here we close windows that have been open for longer than WINDOW_TIME.
        //  Closing a window means adding it to the DB and reseting the stream's current_window.
        //
        //  We also close Streams that haven't gotten a packet in longer than WINDOW_TIME.
        //  These are already in the DB, so we just remove them from activeStreams.
        //

        //Has it been WINDOW_TIME since the last time we did garbage collection?
        printf("Current Windowtime: %d\n", current_time - last_time );
        if( current_time - last_time >= WINDOW_TIME )
        {
            // If so, we go through all the active streams and their windows,
            // checking to see if they need to be closed.
            map<StreamKey, Stream,  LessStreamKey>::iterator i  = activeStreams.begin();
            while(  i != activeStreams.end() )
            {
                // How long has it been since the first time a packet in each window was recieved?
                // If it's longer than WINDOW_TIME, then close window and add it to the db
                if(sniff_time - i->second.current_window.start_time >= WINDOW_TIME)
                {

                    // If the window being closed is the first in a stream (its stream_id = 0),
                    //  then the stream hasn't been added to the db yet.
                    //  So add the stream and the window to the db, reset the stream's current_window.
                    //

                    if( i->second.id == 0 )
                    {
                         printf("Inserting a Stream!\n" );

                        //Important: This is where streams are added to the db.
                        i->second.current_window.stream_id = i->second.id = dbinterface.InsertStream( i->second );
                    }
                    else
                    {
                        i->second.current_window.stream_id = i->second.id;
                    }

                    //Important: This is where windows are added to the db.
                    printf("Inserting a Window.\n" );
                    dbinterface.InsertWindow( i->second.current_window );

                    i->second.current_window.id = 0;
                    i->second.current_window.stream_id = 0;
                    i->second.current_window.start_time = 0;
                    i->second.current_window.end_time = 0;
                    i->second.current_window.num_packets_incoming = 0;
                    i->second.current_window.num_packets_outgoing = 0;
                    i->second.current_window.size_packets_incoming = 0;
                    i->second.current_window.size_packets_outgoing = 0;

                }
                //How long has it been since the stream has gotten a packet?
                if(sniff_time - i->second.current_window.end_time >= WINDOW_TIME)
                {
                    printf("Removing an activeStream\n" );
                    // Longer than WINDOW_TIME? Remove stream from activeStreams.
                    // This is the only place Streams are removed from activeStreams.
                    map<StreamKey, Stream,  LessStreamKey>::iterator itemp = i;
                    ++i;
                    activeStreams.erase(itemp);
                    printf("Removed.\n" );
                    //i--;
                    //continue;
                }
                else
                    ++i;
            }

            last_time = current_time;
        }


    }

	// cleanup
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}
