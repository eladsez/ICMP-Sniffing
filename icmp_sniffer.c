#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <net/ethernet.h>
#include <netinet/ip_icmp.h> // icmp headder declaration.
#include <string.h>
#include <arpa/inet.h>


#define TRUE 1
#define FALSE 0

// src,dest ip getters.
struct sockaddr_in src;
struct sockaddr_in dst;

// Displays the data of the icmp packet.
void icmp_display(unsigned char * buff, int data_size){

  struct ethhdr *eth = (struct ethhdr *)buff;
  struct iphdr *iph;
  if (ntohs(eth->h_proto) == 0x0800) { // 0x0800 is IP type
    iph = (struct iphdr *)(buff + sizeof(struct ethhdr));
  }
  else return; // return to listen

  //getting the length of the ip header length field in bits in case of icmp protocol.
  int iph_len = iph->ihl *4;
  // if protocl is icmp, then print it, we only looking for icmp headers.
  if(iph->protocol == IPPROTO_ICMP){
    // Starts after IP HEADER so we head there.
    struct icmphdr *icmph = (struct icmphdr *)(buff + sizeof(struct ethhdr) + iph_len);

    // Getting the data :
    bzero(&src,sizeof(src));
    bzero(&dst,sizeof(dst));
    src.sin_addr.s_addr = iph->saddr;
    dst.sin_addr.s_addr = iph->daddr;

    printf("----------------ICMP----------------\n");
    printf("SRC Address: %s\n",inet_ntoa(src.sin_addr)); //convert back
    printf("DST Address: %s\n",inet_ntoa(dst.sin_addr)); // convert back
    printf("ICMP_TYPE: %d\n",icmph->type);
    printf("ICMP_CODE: %d\n",icmph->code);
    printf("ICMP_seq: %d/%d\n",icmph->un.echo.sequence>>8, icmph->un.echo.sequence);

  }

}

int main(){
  int PACKET_LEN = 65536;
  int raw_socket;
  int data_size;
  char buff[PACKET_LEN];
  struct sockaddr saddr;

  //creating raw socket:
  //the third paramter enables the socket to read full packet content
  raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if(raw_socket < 0)
    printf("Error creating socket\n");

  // //Enable promiscous mode:
  // struct packet_mreq mr;
  // mr.mr_type = PACKET_MR_PROMISC;
  // setsockopt(raw_socket, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof(mr));

  // Receive all packets:
  while(TRUE){
    bzero(buff, sizeof(buff)); // init buffer.
    data_size = recvfrom(raw_socket, buff,PACKET_LEN, 0, NULL, NULL);
    if(data_size < 0)
      printf("failed to get the packet\n");

    else //reading from icmp:
      icmp_display(buff,data_size);
  }
  close(raw_socket);
  return 0;
}
