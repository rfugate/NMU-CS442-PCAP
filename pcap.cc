#include <pcap.h>
#include <stdio.h>
#include <iostream>
#include <assert.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <iomanip>
#include <sys/unistd.h>
#include <cstring>
#include <net/if_arp.h>
#include <netinet/udp.h>

using namespace std;

const char *FILENAME = "/home/rappleto/pub/Classes/CS442/Assignments/PacketSniffer/packets.db";

struct sniff_ip{
	u_char ip_vhl;				/* Version << 4 | header length >> 2 */
	u_char ip_tos;				/* Type of Service */
	u_short ip_len;				/* Total Length */
	u_short ip_id;				/* Identification */
	u_short ip_off;				/* Fragment offset field */
#define IP_RF 0x8000			/* Reserved Fragment Flag */
#define IP_DF 0x4000			/* Dont Fragment Flag */
#define IP_MF 0x2000			/* More Fragment Flags */
#define IP_OFFMASK 0x1fff		/* Mask for fragmenting bits */
	u_char ip_ttl;				/* Time to Live */
	u_char ip_p;				/* Protocol */
	u_short ip_sum;				/* Checksum */
	struct in_addr ip_src,ip_dst;	/* Source and Dest Address */
};
#define IP_HL(ip)	(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)	(((ip)->ip_vhl) >> 4)

/*struct sniff_tcp{
	tcp_seq th_seq;			/* Sequence Number 
	tcp_seq th_ack;			/* acknowledgement Number 

#define TH_ACK 0x10
#define SIZE_ETERNET 14
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	u_int size_ip;
	u_int size_tcp;
};*/

void ipPacket(unsigned const char *packet){
	/* IP Data Information */
	cout << "IP Information:" << endl;
	int version = (*(packet + 14) & 0xf0) >> 4;
	int len = (*(packet+14) & 0x0f);
	int t1 = *(packet + 16);
	int t2 = *(packet + 17);
	int total = t1*256 + t2;
	int TimeToLive = *(packet + 22);
	int Protocol = *(packet + 23);

	cout << std::hex << "\tVersion: \t" << version << endl;
	cout << std::hex << "\tIHL: \t\t" << len << endl;
	cout << std::dec << "\tTotal Length: \t" << t1 << "." << t2 << " = " << total << endl;
	//cout << "\tProtocol: \t" << (int)packet->ip_ttl << endl;
	cout << std::dec << "\tTTL: \t\t" << TimeToLive << endl;
	cout << std::dec << "\tProtocol: \t" << Protocol << endl;
	if(len > 5){
		cout << "\tPadded:\t\tYes" << endl;
	}
	else{
		cout << "\tPadded:\t\tNo" << endl;
	}
	cout << "\tFrom: \t\t";
	for(int i = 26; i <= 29; i++){
		cout << (int)*(packet + i);
		if(i < 29)
			cout << ".";
			//sourceHostname += (int)*(packet+i) + ".";
	}
	cout << endl;
	cout << "\tTo: \t\t";
	for(int i = 30; i <=33; i++){
		cout << (int)*(packet + i);
		if(i < 33)
			cout << ".";
	}
	cout << endl;
}

void tcpPacket(unsigned const char *packet){
	/* TCP Data Information */
	int Options = 0;
	int ipLen = (*(packet + 14) & 0x0f);
	if(ipLen  > 5){
		Options = 4*(ipLen - 5);
	}
	int sourcePort = (*(packet + 34 + Options)*256 + *(packet + 35 + Options));
	int destinPort = (*(packet + 36 + Options)*256 + *(packet + 37 + Options));
	unsigned int sequence = ((*(packet + 38 + Options)*16777216 + *(packet + 39 + Options))*65536 + (*(packet + 40 + Options)*256 + *(packet + 41 + Options)));
	unsigned int acknowledgement = ((*(packet + 42 + Options)*16777216 + *(packet + 43 + Options))*65536 + (*(packet + 44 + Options)*256 + *(packet + 45 + Options)));
	int fin = (*(packet + 47 + Options) & 0x1);
	int syn = (*(packet + 47 + Options) & 0x2) >> 1;
	int ack = (*(packet + 47 + Options) & 0x10) >> 4;
	cout << "\tSource Port:      " << sourcePort << endl;
	cout << "\tDestination Port: " << destinPort << endl;
	cout << "\tSequence Number:  " << sequence << endl;
	cout << "\tAcknowledgement:  " << acknowledgement << endl;
	cout << "\tFIN:		  " << fin << endl;					/*No more data from sender */
	cout << "\tSYN:              " << syn << endl;			/*Synchronize Sequence Number */
	cout << "\tACK:              " << ack << endl;			/*Indicates the Acknowledgement feild is significant */
//	cout << (struct sniff_tcp *tcp)(packet+38) << endl;
//	cout << ntohs(tcp->th_seq) << endl;
}

void udpPacket(unsigned const char *packet){
	/* UDP Data Information */
	int Options = 0;
	int udpLen = (*(packet + 14) & 0x0f);
	if(udpLen > 5){
		Options = 4*(udpLen - 5);
	}
	struct udphdr* udpHeader = (struct udphdr*)(packet + 34 + Options);
	cout << "\tSource Port:		" << udpHeader->source << endl;
	cout << "\tDestination Port:	" << udpHeader->dest << endl;
	cout << "\tLength: 		" << udpHeader->len << endl;
	cout << "\tChecksum:		" << udpHeader->check << endl;
}

int main(){
	char errbuf[PCAP_ERRBUF_SIZE];		/* Where Errors Go */
	pcap_t *handle;						/* Session Handle */
	struct pcap_pkthdr pheader;			/* Pointer to the Header Below */
	const unsigned char *packet;		/* Data from the Packet */
	int packetNumber = 1;
	handle = pcap_open_offline(FILENAME, errbuf);
	if(handle == NULL){
		cout << errbuf << endl;
		exit(1);
	}
	while((packet = pcap_next(handle, &pheader)) != NULL){
		cout << std::dec << "Packet Number: " << packetNumber << endl;
		cout << "Ethernet: " << endl;
		cout << "\t Destination: ";			/* Packets 1 - 5 Hold Source MAC address */
		for(int i = 0; i < 6; i++){
			cout << std::hex << setfill('0') << setw(2) << (int)*(packet + i);
			if(i < 5)
				cout << ":";
		}
		cout << endl;
		cout << "\t Source: ";				/* Packets 6 - 11 hold Source MAC address */
		for(int i = 6; i < 12; i++){
			cout << std::hex << setfill('0') << setw(2) << (int)*(packet + i);
			if(i < 11)
				cout << ":";
		}
		cout << endl;
		if((*(packet + 12)*256 + *(packet + 13)) < 1500){				/* if this field is 1500(0x05DC) or below it indicates payload size */
			cout << "\t Length: " << (*(packet + 12)*256 + *(packet + 13));
		}
		if((*(packet + 12)*256 + *(packet + 13)) > 1536){				/* if this field is 1536(0x0600) or above it indicates Ethertype */
			cout << "\t Type: 0x";
			cout << std::hex << setfill('0') << setw(2) << (int)*(packet+12);
			cout << std::hex << setfill('0') << setw(2) << (int)*(packet+13);
		}
		cout << endl;
		if (*(packet + 12) == 8 && *(packet + 13) == 0){	/* if 8 & 0 then IPv4 Packet */
			ipPacket(packet);
			if(*(packet + 23) == 1){
				cout << "ICMP Packet" << endl;		/* if 001 then ICMP Packet */
			}
			if(*(packet + 23) == 6){			/* if 006 then TCP Packet */
				cout << "TCP Information:" << endl;
				tcpPacket(packet);
			}
			if(*(packet + 23) == 17){			/* if 017 then UDP Packet */
				cout << "UDP Information:" << endl;
				udpPacket(packet);
			}
			cout << endl;
		}

		if(*(packet + 12) == 80 && *(packet + 13) == 40){	/* if 8040 then NetBIOS Packet */
			cout << "Jacked NetBIOS Packet" << endl << endl;
		}

		cout << "Data: "; // << (int)*(packet +46);
		for(int i=0; i<=44; i++){
			cout << std::dec << setfill('0') << setw(3) << (int)*(packet+i) << ".";
		}
		cout << endl << endl;
		for(int i=0; i<168; i++) cout << "-";
		cout << endl << endl;
		packetNumber++;
	}
}
