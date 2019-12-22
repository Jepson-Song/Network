#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<math.h>
#include<time.h>

//#define HAVE_REMOTE
//#define WPCAP
#include<pcap.h>
#include<WinSock2.h>
//#pragma warning(disable:4996)

//ethernet header
struct IP_header
{
	u_int8_t versionAndHeaderLen;
	u_int8_t typeOfService;
	u_int16_t totalLen;

	u_int16_t ID;
	u_int16_t flagsAndOffset;

	u_int8_t TTL;
	u_int8_t protocal;
	u_int16_t checkSum;

	u_int32_t sourceIP;

	u_int32_t destinationIP;
};


int load_IP_data(u_int8_t *buffer, FILE *fp);
void load_IP_header(u_int8_t *buffer);


