#include "IP.h"
#include "Resource.h"

u_int32_t IPtoInt(const char *IPaddress)
{
    int len = strlen(IPaddress);
    int x = 0;
    u_int32_t ret = 0;
    for(int i = 0 ; i < len ; i++){
        if(IPaddress[i] == '.'){
            ret *= 256;
            ret += x;
            x = 0;
        }
        else{
            x *= 10;
            x += IPaddress[i] - '0';
        }
    }
    ret *= 256;
    ret += x;
    return ret;
}

u_int16_t checkSum(u_int8_t *buffer)
{
    u_int16_t *tmp = (u_int16_t *)buffer;
    u_int32_t sum = 0;
    for(int i = 0; i < 10; i++){
        sum += htons(tmp[i]);
        //printf("%d: %04X\n",i,htons(tmp[i]));
    }
    sum = (sum>>16) + (sum&0xffff);
    sum += (sum>>16);
    u_int16_t ret = (u_int16_t)(~sum);
    return ret;
}

void myswap(u_int8_t *x, u_int8_t *y)
{
    u_int8_t z;
    z = *x;
    *x = *y;
    *y = z;
}

int size_of_IP_data;
char ch;
int load_IP_data(u_int8_t *buffer, FILE *fp)
{
    size_of_IP_data = 0;
	char tmp[MAX_SIZE];
	int ret = 0;
	printf("IP data: ");
	//ch = fgetc(fp);
	/*tmp[0] = 0;
	tmp[1] = 80;
	tmp[2] = 0;
	tmp[3] = 80;
	tmp[4] = 0;
	tmp[5] = 80;
	size_of_IP_data += 6;*/
	while (1)
	{

		tmp[size_of_IP_data] = ch;
		size_of_IP_data++;
		//printf("%d: ",size_of_IP_data);
		printf("%c",ch);

	    ch = fgetc(fp);
	    if(ch == EOF)
        {
            ret = -1;
            break;
        }

		if(size_of_IP_data>=MAX_IP_PACKET_SIZE)
        {
            ret = 1;
            break;
        }
	}
	printf("\n");
	printf("size_of_IP_data: %d\n",size_of_IP_data);
	if (size_of_IP_data>MAX_IP_PACKET_SIZE)
	{
		printf("Size of data is not satisfied with condition!!!\n");
		//  return -1;
	}

	int i;
	for (i = 0; i < size_of_IP_data; i++)
	{
		*(buffer + i) = tmp[i];
	}
	return ret;
}

u_int16_t DF;
u_int16_t MF;
u_int16_t offset;
void load_IP_header(u_int8_t *buffer)
{
    struct IP_header *hdr = (struct IP_header *)buffer;

    hdr->versionAndHeaderLen = 0x40 + sizeof(IP_header)*8/32;
    hdr->typeOfService = 0x00;
    //printf("%d\n",size_of_IP_data + sizeof(IP_header));
    hdr->totalLen = htons(size_of_IP_data + sizeof(IP_header)); //

    printf("hdr->totalLen: %d\n",hdr->totalLen);
    hdr->ID = htons(0x1234);
    hdr->flagsAndOffset = htons((DF<<14) + (MF<<13) + offset);

    hdr->TTL = 0xff;
    hdr->protocal = 6; // 6   17
    hdr->checkSum = 0;

    hdr->sourceIP = htonl(IPtoInt("192.168.50.234"));
    //printf("%X\n",hdr->sourceIP);
    hdr->destinationIP = htonl(IPtoInt("192.168.50.209"));
    //printf("%X\n",hdr->destinationIP);

    hdr->checkSum = htons(checkSum(buffer)); //
    printf("IP header: ");
    for(int i=0;i<20;i++) printf("%02X",buffer[i]);
    printf("\n");
    printf("check send: %04X\n",hdr->checkSum);
    printf("check recv: %04X\n",checkSum(buffer));

}
