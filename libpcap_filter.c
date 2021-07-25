#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <string.h>
#include<netinet/ip.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("Got a packet \n");
}

int main()
{
    pcap_t *handle;
    int err,ret, sockfd, buflen;
    char * buf;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "port 80";
    bpf_u_int32 net;
    struct sock_fprog bpf;
    struct sockaddr saddr;
    int saddr_len = sizeof (saddr);
    struct sockaddr_in source_socket_address, dest_socket_address;


    // Open live pcap session
    handle = pcap_open_live("wlp3s0", BUFSIZ, 1, 1000, errbuf);
    
    if(!handle) {
    	printf("error in pcap_open_live\n");
    	return -1;
    }
    
    
    // Compile Filter into the Berkeley Packet Filter (BPF)
    err = pcap_compile(handle, &fp, filter_exp, 0, net);
    
    if (err) {
    	printf("error in pcap_compile: %s\n",pcap_geterr(handle));
    	//pcap_perror();
    	return -1;
    }
    
	 
	bpf.len = fp.bf_len;
	bpf.filter =  (struct sock_filter *) fp.bf_insns;
	
	buf = (unsigned char *) malloc(65536);
	if (!buf) {
		printf("Low memory\n");
		return -1;		
	}
		
	memset(buf,0,65536);

	sockfd = socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL)); //socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sockfd < 0) {
		
		printf("Error\n");
	}
	
	
	ret = setsockopt(sockfd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf));
	if (ret < 0) {
	
		printf("Unsuccessful\n");
	}
	

	while(1) {
	
		buflen = recvfrom(sockfd, buf, 65536, 0, &saddr, (socklen_t *)&saddr_len);
		if(buflen < 0) {
		
		printf("recvfrom failed\n");
		return -1;
		}
		

	      struct iphdr *ip_packet = (struct iphdr *)buf;

	      memset(&source_socket_address, 0, sizeof(source_socket_address));
	      source_socket_address.sin_addr.s_addr = ip_packet->saddr;
	      memset(&dest_socket_address, 0, sizeof(dest_socket_address));
	      dest_socket_address.sin_addr.s_addr = ip_packet->daddr;

	      printf("Incoming Packet: \n");
	      printf("Packet Size (bytes): %d\n",ntohs(ip_packet->tot_len));
	      printf("Source Address: %s\n", (char *)inet_ntoa(source_socket_address.sin_addr));
	      printf("Destination Address: %s\n", (char *)inet_ntoa(dest_socket_address.sin_addr));
	      printf("Identification: %d\n\n", ntohs(ip_packet->id));
	   
      } 


	close(sockfd);

#if 0
    if (pcap_setfilter(handle, &fp) == -1)
    {
    	printf("error\n");
        pcap_perror(handle, "ERROR");
        exit(EXIT_FAILURE);
    }
    
    
        // Sniffing..
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);
#endif
    return 0;
}

