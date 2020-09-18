#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <strings.h>
#include <errno.h>
#include <sys/time.h>    // for gettimeofday()

#define IPPROTO_SEADP 153
#define DATA buff_1300

typedef uint8_t u8;
typedef uint16_t u16;
typedef	uint32_t u32;

typedef struct seanet_hdr_t
{
	//eid
	u8 next_header;
	u8 header_len;
	u16 attribute;
	char src_eid[20];
	char dst_eid[20]; 
	//seadp
	u16 src_port;
	u16 dst_port;
	u8 packet_mark;
	u8 cache_mark;
	u8 transport_mark;
	u8 reserve; 
	u32 chunk_len;
	u32 offset;
	u16 seq;
	u16 seadp_csum;
} seanet_hdr;



char buff[] = "liuyifengliuyifeng";
char buff_1300[1300];

char rcv_buff[30000];

extern int errno;


int main(int argc,char** argv)
{
	int i;
	int no_print = 1;
	struct timeval start, end;
	unsigned int times=0;
	int sockfd;
	struct sockaddr_in localaddr;
	ssize_t num, sum=0;	
	struct sockaddr_in serveraddr;

	if(argc!=3)
	{
	printf("Usage:%s bind_port rcv_buff_size\n",argv[0]);
	return -1;
	}

	localaddr.sin_family = AF_INET;
	localaddr.sin_port = htons(atoi(argv[1]));
	//localaddr.sin_addr.s_addr = inet_addr("172.17.0.1");
	localaddr.sin_addr.s_addr = inet_addr("192.168.1.100");
	
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(8081);
	//serveraddr.sin_addr.s_addr = inet_addr("172.17.0.2");
	serveraddr.sin_addr.s_addr = inet_addr("192.168.1.101");
	

	sockfd = socket(AF_INET,SOCK_DGRAM,153);
	if(sockfd < 0)
	{
		printf("socket error!\n");
		return -1;
	}

	if ( bind(sockfd, (struct sockaddr*)&localaddr, sizeof(localaddr))<0 )
	{
		printf("bind error\n");
		return -1;
	}

	//sleep(15);
	printf("wake up\n");

	if(   connect(sockfd, (struct sockaddr*)&serveraddr,sizeof(serveraddr)) <0 )
	{
		printf("connect error\n");
		printf("errno:%d\n", errno);
		printf("err:%s\n", strerror(errno));
		perror("connect error");
		return -1;
	}

/*
	for(i=0;i<1;i++)
	{
		//if ( (num = sendto(sockfd, DATA, sizeof(DATA), 0, (struct sockaddr*)&serveraddr, sizeof(serveraddr)))  < 0     )
		if ( (num = sendto(sockfd, DATA, sizeof(DATA), 0, NULL, 0))  < 0     )
		{		
			printf("sendto error!\n");
			return -1;	
		}	
		printf("num: %d\n", num);
	}

*/

	while(1)
	{
		bzero(rcv_buff,30000);
		num = recvfrom(sockfd, rcv_buff, atoi(argv[2]),0, NULL,NULL);
		if(num < 0 )
		{
			printf("%s error!\n",__func__);
			return -1;
		}
		if(sum == 0)
		{
			gettimeofday( &start, NULL );
			//printf("start : %d.%d\n", start.tv_sec, start.tv_usec);
		}
		sum += num;
		times++;
		if(sum >= 14000000*10*4 && no_print)
		{
			no_print = 0;
			gettimeofday( &end, NULL );
			printf("start : %d.%d\n", start.tv_sec, start.tv_usec);
   			printf("end   : %d.%d\n", end.tv_sec, end.tv_usec);
			break;
		}
		//printf("------------\n");
		/////printf("num:%d, times:%d\n", num,times);
		
		//printf("%s\n",((char *)rcv_buff));
		//for(i=0;i<num;i++) printf("%d ", rcv_buff[i]);
		//printf("\n");

		//printf("------------\n");
	}


	//sleep(10);
	printf("create a seadp socket! sockfd: %d\n", sockfd);
	//while (1);
	return 0;
}
