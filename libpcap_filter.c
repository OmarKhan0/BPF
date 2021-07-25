#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("Got a packet \n");
}

int main()
{
    pcap_t *handle;
    int err;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp";
    bpf_u_int32 net;

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

    if (pcap_setfilter(handle, &fp) == -1)
    {
    	printf("error\n");
        pcap_perror(handle, "ERROR");
        exit(EXIT_FAILURE);
    }
    
    
        // Sniffing..
    pcap_loop(handle, -1, got_packet, NULL);
    pcap_close(handle);

    return 0;
}

