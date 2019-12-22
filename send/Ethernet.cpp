#include "Ethernet.h"
#include "Resource.h"
#include "IP.h"
u_int32_t crc32_table[256] = { 0 };
u_int32_t size_of_packet = 0;


void generate_crc32_table()
{
	int i, j;
	u_int32_t crc;
	for (i = 0; i < 256; i++)
	{
		crc = i;
		for (j = 0; j < 8; j++)
		{
			if (crc & 1)
				crc = (crc >> 1) ^ 0xEDB88320;
			else
				crc >>= 1;
		}
		crc32_table[i] = crc;
	}
}

u_int32_t calculate_crc(u_int8_t *buffer, int len)
{
	int i;
	u_int32_t crc;
	crc = 0xffffffff;
	for (i = 0; i < len; i++)
	{
		crc = (crc >> 8) ^ crc32_table[(crc & 0xFF) ^ buffer[i]];
	}
	crc ^= 0xffffffff;
	return crc;
}


void load_ethernet_header(u_int8_t *buffer)
{
	struct ethernet_header *hdr = (struct ethernet_header*)buffer;
	//size_of_packet = 0;
	// add destination mac address
    hdr->destination_mac[0] = 0x58;
	hdr->destination_mac[1] = 0xFB;
	hdr->destination_mac[2] = 0x84;
	hdr->destination_mac[3] = 0xFE;
	hdr->destination_mac[4] = 0x0D;
	hdr->destination_mac[5] = 0xC1;
    //C8:5B:76:3E:B1:4D
    //58:FB:84:FE:0D:C1//guxinrui
	//add source mac address
	hdr->source_mac[0] = 0x80;
	hdr->source_mac[1] = 0xA5;
	hdr->source_mac[2] = 0x89;
	hdr->source_mac[3] = 0x78;
	hdr->source_mac[4] = 0x41;
	hdr->source_mac[5] = 0xE5;
    //D0:17:C2:08:3A:86
    //80:A5:89:78:41:E5
	// add source typy
	hdr->ethernet_type = htons(ETHERNET_IP);
	printf("ethenet header: ");
	for(int i=0;i<(int)sizeof(ethernet_header);i++) printf("%02X",buffer[i]);
	printf("\n");

	// caculate the size of packet now
	size_of_packet += sizeof(ethernet_header);
}
extern int size_of_IP_data;
int load_ethernet_data(u_int8_t *buffer)
{
	int size_of_eth_data = size_of_IP_data + sizeof(IP_header);
	printf("size_of_eth_data: %d\n",size_of_eth_data);

	//problem: < 46, ADD 0s+1byte;  >1500 LOST

	u_int32_t crc = calculate_crc((u_int8_t*)buffer, size_of_eth_data);
	//printf("%d\n", crc);

	*(u_int32_t*)(buffer + size_of_eth_data) = crc;
	size_of_packet += size_of_eth_data + 4;
	printf("CRC: %08X\n",crc);
	return size_of_eth_data;
}

int fragment = 0;
extern u_int16_t DF;
extern u_int16_t MF;
extern u_int16_t offset;
extern char ch;
int ethernet_send_packet(u_int8_t *buffer, FILE *fp, pcap_t *handle)
{
    generate_crc32_table();
	fseek(fp, 0, SEEK_SET);
    fragment = 0;
    DF = MF = -1;
    offset = 0;
	int ret = 0;
	ch = fgetc(fp);
	while(1)
    {
        fragment ++;
        printf("----------------------%dºÅ·Ö×é------------------------\n",fragment);
        ret = load_IP_data(buffer + sizeof(ethernet_header) + sizeof(IP_header), fp);
        if(ret == -2) break;
        if(ret == -1)//eof
        {
            if(fragment == 1) DF = 1;
            else DF = 0;

            MF = 0;
        }
        else
        {
            DF = 0;

            MF = 1;
        }
        offset = (fragment-1)*MAX_IP_PACKET_SIZE/8;

        load_IP_header(buffer + sizeof(ethernet_header));

        load_ethernet_data(buffer + sizeof(ethernet_header));
        //printf("%d\n",sizeof(ethernet_header));

        load_ethernet_header(buffer);



        //struct IP_header *hdr = (struct IP_header *)(buffer + sizeof(ethernet_header));
        //printf("%X\n",hdr->sourceIP);
        //printf("%X\n",hdr->destinationIP);
        if (pcap_sendpacket(handle, (const u_char *)buffer, size_of_packet) != 0)
        {
            printf("Sending failed..\n");
            //while(1) pcap_sendpacket(handle, (const u_char *)buffer, size_of_packet);
            return -1;
        }
        else
        {
            //printf("%s\n",(u_char *)buffer);
            printf("Sending Succeed..\n");
            //return 1;
        }

        printf("-----------------------------------------------------\n\n");
        if(ret == -1) break;
    }
    return 1;
}
