#include "Ethernet.h"

int main()
{

	pcap_t *handle;
	char *device;
	char error_buffer[PCAP_ERRBUF_SIZE];

	pcap_if_t *alldevs;
	if (pcap_findalldevs(&alldevs, error_buffer) == -1)
    {
        printf("Error in pcap_findalldevs: %s\n", error_buffer);
        return 1;
    }

    pcap_if_t *d;
    int i = 0;
    for(d=alldevs; d; d=d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }
    if(i==0)
    {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return -1;
    }

    printf("Enter the interface number (1-%d):",i);
    int inum;
    scanf("%d", &inum);
    if(inum < 1 || inum > i)
    {
        printf("\nInterface number out of range.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }


    /* Jump to the selected adapter */
    for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);


    if ( (handle= pcap_open_live(d->name, // name of the device
            65536, // portion of the packet to capture.
            // 65536 grants that the whole packet will be
            //captured onall the MACs.
            1,     // promiscuous mode
            1000,  // read timeout
            error_buffer // error buffer
            ) ) == NULL)
    {
        printf("\nUnable to open the adapter. %s is not supported by WinPcap\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }

    if(pcap_datalink(handle) != DLT_EN10MB)
    {
        printf("\nThis program works only on Ethernet networks.\n");
        /* Free the device list */
        pcap_freealldevs(alldevs);
        return -1;
    }


    /*
	pcap_t *handle;
	char *device;
	char error_buffer[PCAP_ERRBUF_SIZE];

	device = pcap_lookupdev(error_buffer);
	handle = pcap_open_live(device, 65536, 1, 1000, error_buffer);*/
	generate_crc32_table();

	pcap_loop(handle, NULL, ethernet_protocol_packet_callback, NULL);

	pcap_close(handle);
	return 0;
}
