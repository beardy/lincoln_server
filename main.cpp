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

#include <unordered_set>
using namespace __gnu_cxx;

#include <mysql++/mysql++.h>

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

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);



struct eqstr
{
  bool operator()(const char* s1, const char* s2) const
  {
    return strcmp(s1, s2) == 0;
  }
};


template< typename T_TypeToHash >
struct SizeTCastHasher {
  size_t operator()( const T_TypeToHash& i_TypeToHash ) const {
      return size_t( i_TypeToHash );
  }
};

 struct Window
 {
     u_short id;
     u_short stream_id;

     time_t start_time;
     time_t end_time;
     int num_packets_incoming;
     int num_packets_outgoing;

     int size_packets_incoming;
     int size_packets_outgoing;

 };

 struct Stream
 {
     u_short id;
     in_addr raw_ip_incoming;
     in_addr raw_ip_outgoing;
     u_short port_incoming;
     u_short port_outgoing;

     //Window current_window;
 };

 struct SameStream
{
    bool operator()(Stream s1, Stream s2) const
    {
        return( s1.raw_ip_incoming.s_addr == s2.raw_ip_incoming.s_addr &&
            s1.port_incoming   == s2.port_incoming   &&
            s1.raw_ip_outgoing.s_addr == s2.raw_ip_outgoing.s_addr &&
            s1.port_outgoing   == s2.port_outgoing   );
    }
};

 struct SameWindow
{
    bool operator()(Window w1, Window w2) const
    {
        return( w1.stream_id == w2.stream_id );
    }
};

//Windows are at most 300 seconds long (5 minutes)
#define WINDOW_TIME 300


 //activeStreams are the streams that are currently open,
 //Streams that have at least one closed window have been added to the DB
 unordered_set<Stream, SameStream> activeStreams;

 //activeWindows are windows that have not finished aggregrating traffic
 //None of windows are in the database yet.
 //unordered_map<Window, u_short, hash<u_short>, SameWindow> activeWindows;
 vector<Window> activeWindows;


void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    mysqlpp::Connection conn(false);
    //hash_map<const char*, int, hash<const char*>, eqstr> months;

    unordered_set<Stream, SameStream> strrrms;

	static int count = 1;                   /* packet counter */

	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	//const u_char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	//int size_payload;

	printf("\nPacket number %d:\n", count);
	count++;

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	/* define/compute ip header offset */
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		printf("   * Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	/* print source and destination IP addresses */
	printf("       From: %s\n", inet_ntoa(ip->ip_src));
	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

	/* determine protocol */
	switch(ip->ip_p) {
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

	/* define/compute tcp header offset */
	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if (size_tcp < 20) {
		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	printf("   Src port: %d\n", ntohs(tcp->th_sport));
	printf("   Dst port: %d\n", ntohs(tcp->th_dport));



	Stream tempStream;
	tempStream.raw_ip_incoming;
	tempStream.raw_ip_outgoing;
	tempStream.port_incoming = tcp->th_dport;
	tempStream.port_outgoing = tcp->th_sport;

	static int lastStreamID = 1;
	static int lastWindowID = 1;

	bool incoming=0;

	int packet_length = ip->ip_len;

	time_t sniff_time = time(NULL);

	unordered_set<Stream>::iterator iter = activeStreams.find(tempStream);
	if( iter == activeStreams.end() )
	{
        lastStreamID++;
        tempStream.id = lastStreamID;



        Window tempWindow;
        lastWindowID++;
        tempWindow.id = lastWindowID;
        tempWindow.stream_id = tempStream.id;

        tempWindow.start_time = sniff_time;

        if(incoming)
            tempWindow.num_packets_incoming = 1;
        else
            tempWindow.num_packets_outgoing = 1;

	}
	else
	{
        if(incoming)
        {
            activeWindows[iter->id].size_packets_incoming += packet_length;
            activeWindows[iter->id].num_packets_incoming++;
        }
        else
        {
            activeWindows[iter->id].size_packets_outgoing += packet_length;
            activeWindows[iter->id].num_packets_outgoing++;
        }

	}

	for( unordered_set<Stream>::iterator i = activeStreams.begin(); i!=activeStreams.end(); i++)
	{
        if(sniff_time - activeWindows[i->id].start_time >= WINDOW_TIME)
        {
            activeWindows[i->id].end_time = sniff_time;

            //DB_Interface.AddWindow( activeWindows[i->id] );
            //

            /*
            //Add stream to database if
            if(i->last_window_end_time > 0 )
            {
                //DB_Interface.AddStream(*i);
            }

            i->last_window_end_time = time
            */
        }
        /*
        if( time - i->last_window_end_time >= WINDOW_TIME )
        {
            DB_Interface.AddStream(*i);
            currentStreams.remove(i);
        }*/
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

	/* now we can set our callback function */
	pcap_loop(handle, num_packets, got_packet, NULL);

	/* cleanup */
	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");

return 0;
}
