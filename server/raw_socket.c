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
#include <sys/time.h>    // for gettimeofday()


#define IPPROTO_SEADP 153
#define MSG msg1

#define SEADP_MSS 1400

#define SEADP_DATA 	0x01
#define SEADP_REQUEST 	0x02

#define seadp_packet_mark_byte(sh) (((u_int8_t *)sh)[48])

typedef uint8_t u8;
typedef uint16_t u16;
typedef	uint32_t u32;
typedef uint64_t u64;

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
	u8 dat :1,	//packet_mark
	   req :1,
	   ret :1,
	   ack :1,
	   fin :1,
	   saved :3;	
	u8 cache_mark;
	u8 transport_mark;
	u8 reserve; 
	u32 chunk_len;
	u32 offset;
	u16 seq;
	u16 seadp_csum;
} seanet_hdr;

seanet_hdr packet_header;

char src_eid[20]={0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff\
,0xff,0xff,0xff,0xff,0xff};

char dst_eid[20]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20};

char msg[] = "liuyifeng1234";
char msg1[1000];
char msg_order[600000000]= {0};	//保序消息

char rcv_buff[2000];	//接收消息缓冲区

void create_packet();


int test_if(int a)
{
	printf("1\n");
	return 1;
}
/*
void send_ofo(u32 seq, int size,seanet_hdr* ptr, struct sockaddr* address,int sockfd)
{
	int num;
	int index = seq -size;
	if(index< 0) return;
	ptr->offset   = htonl(seq);
	memcpy((char*)ptr + sizeof(seanet_hdr), (const void *)&(msg_order[index]),size);

	if((num=sendto(sockfd, (const void*)ptr, size+sizeof(seanet_hdr), 0, address, sizeof(struct sockaddr))) < 0)
	{
		printf("sendto error!!\n");
		free((void *)ptr);
		return ;	
	}

}
*/
void send_ofo(u64 seq, u64 size,seanet_hdr* ptr, struct sockaddr* address,int sockfd)
{
	u64 num;
	u64 index = seq -size;
	if(index< 0) return;

	ptr->offset   = htonl(seq);
	memcpy((char*)ptr + sizeof(seanet_hdr), (const void *)&(msg_order[index]),size);

	if((num=sendto(sockfd, (const void*)ptr, size+sizeof(seanet_hdr), 0, address, sizeof(struct sockaddr))) < 0)
	{
		printf("sendto error!!\n");
		//free((void *)ptr);
		return ;	
	}

}

int main(int argc,char** argv)
{
	 struct timeval start, end;
	struct sockaddr_in target;
	int sockfd, sockfd_snd;
	seanet_hdr *ptr, *ptr1;
	size_t size = sizeof(seanet_hdr) + SEADP_MSS;	
	ssize_t num;
	int i;
	int times;
	int segs;
	u8 packet_mark;
	char aac =0x08;
	int cca = (int)aac;

	unsigned int client_addr_len = sizeof(struct sockaddr_in);
	struct sockaddr_in clientaddr;

	if(argc!=5)
	{
	printf("Usage:%s dst_ip dst_port src_port times\n",argv[0]);
	return -1;
	}

	times = atoi(argv[4]);
	if(times == 0)
	{
		printf("times is invalid!!\n");
		return -1;
	}

	for(i=0;i<60000000;i++) msg_order[i]=i+1;

	bzero(&target,sizeof(struct sockaddr_in));
	target.sin_family=AF_INET;
        target.sin_port=htons(atoi(argv[2]));	
	if(inet_aton(argv[1], &(target.sin_addr)) == 0)
	{
		printf("dst_ip invalid fomat!\n");
		return -1;
	}
	
	sockfd = socket(AF_INET,SOCK_RAW,IPPROTO_SEADP);

	//sockfd_snd = socket(AF_INET,SOCK_RAW,IPPROTO_SEADP);
	if(sockfd < 0)
	{
		printf("socket error!\n");
		return -1;
	}

	ptr = (seanet_hdr*)malloc(size);
	//printf("ptr: %p\n", ptr);
	if(ptr == NULL)
	{
		printf("malloc error!\n");
		return -1;
	}
	
	bzero(ptr,size);
	ptr->next_header = 17;
	ptr->header_len  = 44;
	
	memcpy(&(ptr->src_eid), (const void *)src_eid,20);
	memcpy(&(ptr->dst_eid), (const void *)dst_eid,20);
	//seadp
	ptr->src_port = htons(atoi(argv[3]));
	ptr->dst_port = htons(atoi(argv[2]));
	ptr->offset   = htonl(14);
	ptr->saved      = 0b111;
	//ptr->req      = 1;
	//ptr->ack      = 1;
	//ptr->dat      = 1;
	//ptr->fin      = 1;
	//ptr->ret      = 1;
	memcpy((char*)ptr + sizeof(seanet_hdr), (const void *)MSG,sizeof(MSG));


/*
	for(i=0;i<times;i++)		
	{
	
		//if((num=sendto(sockfd, (const void*)ptr, size, 0, (struct sockaddr*)&target, sizeof(target))) < 0)
		//{
	//		printf("sendto error!!\n");
		//	free((void *)ptr);
	//		return -1;	
	//	}
	//	printf("send %d bytes\n", (int)num-sizeof(seanet_hdr));
	
		send_ofo(100, 3, ptr, (struct sockaddr*) &target, sockfd);
		send_ofo(100, 9, ptr, (struct sockaddr*) &target, sockfd);
		send_ofo(6, 6, ptr, (struct sockaddr*) &target, sockfd);
		send_ofo(11, 4, ptr, (struct sockaddr*) &target, sockfd);
		send_ofo(7, 2, ptr, (struct sockaddr*) &target, sockfd);
		send_ofo(95, 10, ptr, (struct sockaddr*) &target, sockfd);
		send_ofo(97, 8, ptr, (struct sockaddr*) &target, sockfd);
		send_ofo(90, 20, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(80, 7, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(75, 10, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(9, 9, ptr, (struct sockaddr*) &target, sockfd);
	send_ofo(60, 6, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(65, 9, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(60, 20, ptr, (struct sockaddr*) &target, sockfd);
//send_ofo(70, 15, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(77, 18, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(70, 15, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(6, 6, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(57, 3, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(58, 6, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(55, 17, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(50, 11, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(15, 12, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(80, 19, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(47, 8, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(43, 4, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(85, 7, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(40, 1, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(39, 5, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(42, 12, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(31, 9, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(25, 2, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(24, 3, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(26, 6, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(60, 13, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(20, 8, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(19, 7, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(70, 20, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(12, 5, ptr, (struct sockaddr*) &target, sockfd);
send_ofo(10, 10, ptr, (struct sockaddr*) &target, sockfd);
	}
*/

	if(1 && test_if(1))
	{
		printf("2\n");
	}
printf("aac: %02x\n", (int)cca);
//下面是一个请求-应答数据的服务端

///*
//请求服务器
while(1)
{
	num = recvfrom(sockfd, rcv_buff, 2000, 0, (struct sockaddr*) &clientaddr, &client_addr_len);
	///printf("num: %d\n", num);
	
	//gettimeofday( &start, NULL );
   
	//sleep(5);

	ptr1 = (seanet_hdr *)((char*)rcv_buff + 20);
	packet_mark = seadp_packet_mark_byte( ptr1 );
	
	ptr->dst_port = ptr1->src_port;

	if(packet_mark & SEADP_REQUEST)
	{
		//printf("request!!\n");
		segs = ntohl(ptr1->chunk_len) / SEADP_MSS;
		printf("offset: %d, segs: %d\n", ntohl(ptr1->offset), segs);
		//send_ofo(ntohl(ptr1->offset)+ntohl(ptr1->chunk_len), ntohl(ptr1->chunk_len),ptr, (struct sockaddr*) &target, sockfd_snd);
		for(i=0;i<segs;i++)	
		{
			///send_ofo(ntohl(ptr1->offset)+SEADP_MSS*(i+1), SEADP_MSS,ptr, (struct sockaddr*) &target, sockfd);
			send_ofo(ntohl(ptr1->offset)+SEADP_MSS*(i+1), SEADP_MSS,ptr, (struct sockaddr*) &clientaddr, sockfd);
		}
	}
	
	//gettimeofday( &end, NULL );
	//printf("start : %d.%d\n", start.tv_sec, start.tv_usec);
    //printf("end   : %d.%d\n", end.tv_sec, end.tv_usec);

	//break;
}
//*/
/*
//手动发送
	for(i=0;i<1000;i++)	
	{
		send_ofo(SEADP_MSS*(i+1), SEADP_MSS,ptr, (struct sockaddr*) &target, sockfd_snd);
	}
*/
	//printf("ptr: %p\n", ptr);

	free((void *)ptr);	
	close(sockfd);
	//printf("123\n");
	close(sockfd_snd);
	return 0;
}

