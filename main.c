#include <linux/init.h>
#include <linux/module.h>
#include <net/protocol.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/icmp.h>
#include <linux/sched/signal.h>
#include <linux/kallsyms.h>
#include <net/ip.h>
#include <net/flow.h>
#include <net/route.h>
#include <linux/refcount.h>
#include <net/xfrm.h>
#include <linux/rbtree.h>
#include <linux/timer.h>
#include <linux/win_minmax.h>
#include "congestion.h"
#include "main.h"

#define DEBUG_T 1



#define IPPROTO_SEADP 153

#define HASH_LEN 1024
#define REQUEST_HASH_LEN 512 

#define FEEDBACK_PAYLOAD_LEN 5

#define SEADP_MEM_0 90327
#define SEADP_MEM_1 120436
#define SEADP_MEM_2 180654
#define SEADP_RMEM_MIN 4096
#define SEADP_WMEM_MIN 4096

#define SEADP_SKB_CB(__skb)	((struct seadp_skb_cb *)&((__skb)->cb[0]))
#define seadp_packet_mark_byte(sh) (((u_int8_t *)sh)[48])


#define MAX_SEADP_HEADER 96
//skb->cb中 seadp报文反馈种类信息宏
#define SEADPHDR_DATA_REQUEST 0x01	
#define SEADPHDR_RE_REQUEST 0x02

//MODULE_LICENSE("GPLv2");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("664013067@qq.com");


DEFINE_PER_CPU(struct pacing_tasklet, pacing_tasklet);
DEFINE_PER_CPU(int, cpu_number);    //测试用，弄一个CPU编号！！！！

static int packet_count =0;

extern struct seadp_congestion_ops seadp_bbr_cong_ops;

enum seadp_feedback_kind {
	IMMEDIATE_FEEDBACK,
	DELAY_FEEDBACK,
	REQUEST_FEEDBACK,
};



atomic_long_t seadp_memory_allocated = ATOMIC_LONG_INIT(0);   //所有seadp传输控制块分配的内存
long sysctl_seadp_mem[3];
int sysctl_seadp_wmem_min;
int sysctl_seadp_rmem_min;


bool (*MEM_CGROUP_CHARGE_SKMEM)(struct mem_cgroup *memcg, unsigned int nr_pages);
int (*INET_RECV_ERROR)(struct sock *sk, struct msghdr *msg, int len, int *addr_len);
struct sk_buff* (*IP_MAKE_SKB)(struct sock *sk, struct flowi4 *fl4,
			    int getfrag(void *from, char *to, int offset,
					int len, int odd, struct sk_buff *skb),
			    void *from, int length, int transhdrlen,
			    struct ipcm_cookie *ipc, struct rtable **rtp,
			    unsigned int flags);

int (*IP_SEND_SKB)(struct net *net, struct sk_buff *skb);

u32 (*MINMAX_RUNNING_MIN)(struct minmax *m, u32 win, u32 t, u32 meas);

struct seadp_table seadptable;      //全局唯一！！

struct seadp_hslot hash_array[HASH_LEN];



/**
 *	skb_rbtree_purge_by_us - empty a skb rbtree
 *	@root: root of the rbtree to empty
 *	Return value: the sum of truesizes of all purged skbs.
 *
 *	Delete all buffers on an &sk_buff rbtree. Each buffer is removed from
 *	the list and one reference dropped. This function does not take
 *	any lock. Synchronization should be handled by the caller (e.g., TCP
 *	out-of-order queue is protected by the socket lock).
 */
static unsigned int skb_rbtree_purge_by_us(struct rb_root *root)
{
	struct rb_node *p = rb_first(root);
	unsigned int sum = 0;

	while (p) {
		struct sk_buff *skb = rb_entry(p, struct sk_buff, rbnode);

		p = rb_next(p);
		rb_erase(&skb->rbnode, root);
		sum += skb->truesize;
		kfree_skb(skb);
	}
	return sum;
}
static inline  seanet_hdr* seadp_hdr(const struct sk_buff *skb)
{
	return ( seanet_hdr *)skb_transport_header(skb);
}

/*
* 在这里对反馈报文的首部进行填充，不同的反馈报文种类需要计算统计并填充的首部信息也不一样！！
* 例如：1、快速反馈(ret置位)可能需要统计丢失的报文段，以重新请求这一段数据，这个应借鉴TCP快速重传的思想，但是seadp缺少sack机制，需对快速重传进行改进！！！！
* 	2、延迟反馈(ret置位)可能会大大减少乱序带来的反馈频率，但需小心设计，传递信息
*	3、正常的chunk请求反馈(req置位)，这个涉及拥塞控制，在接收端对网络带宽估计，估计拥塞窗口来最终确定需要请求的数目！！！
*	以上几个还都需要加入流控机制，来防止请求过多数据，超过接收端处理速度！！！！！
*/
static int __pad_and_send_feedback(struct sk_buff *skb, struct flowi4 *fl4, enum seadp_feedback_kind type)	
{
	struct sock *sk = skb->sk;
	seanet_hdr *sh;
	int offset = skb_transport_offset(skb);
	int len = skb->len - offset;
	int err = 0;
	struct inet_sock *inet = inet_sk(sk);

	sh = seadp_hdr(skb);
	sh->src_port = (u16)inet->inet_sport;
	sh->dst_port = fl4->fl4_dport;
	sh->chunk_len = htonl(len);
	sh->seadp_csum = 0;

send:
	err = IP_SEND_SKB(sock_net(sk), skb);

	return err;

}
/*
void seadp_send_feedback(struct sock *sk)	//立即发送seadp反馈！！对端地址应该从inet_sk中获取，因为还是面向连接的
{
	struct flowi4 *fl4;
	struct flowi4 fl4_stack;
	struct rtable *rt = NULL;
	__be32 daddr, faddr, saddr;
	__be16 dport;
	int connected = 0;
	int err;
	int ulen = FEEDBACK_PAYLOAD_LEN;
	struct ipcm_cookie ipc;
	int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);
	struct net *net = sock_net(sk);
	struct inet_sock *inet = inet_sk(sk);
	u8  tos;
	__u8 flow_flags = inet_sk_flowi_flags(sk);
	struct sk_buff *skb;
	struct msghdr msg1;
	struct msghdr *msg = &msg1;
	
	memset((void*)msg, 0,sizeof(msg1));
	ipc.opt = NULL;
	ipc.tx_flags = 0;
	ipc.ttl = 0;
	ipc.tos = -1;


	getfrag = ip_generic_getfrag;	//决定用什么分片函数，必不可少。这里用ip层的分片功能！！！！


	ulen += sizeof( seanet_hdr);	//!!!
	fl4 = &inet->cork.fl.u.ip4;	//??
	
	if (sk->sk_state != TCP_ESTABLISHED)	return -EDESTADDRREQ;
	daddr = inet->inet_daddr;
	dport = inet->inet_dport;
	
	connected = 1;		//**
	
	ipc.sockc.tsflags = sk->sk_tsflags;
	ipc.addr = inet->inet_saddr;
	ipc.oif = sk->sk_bound_dev_if;


	saddr = ipc.addr;
	ipc.addr = faddr = daddr;
	
	tos = get_rttos(&ipc, inet);
	
	if (connected)	rt = (struct rtable *)sk_dst_check(sk, 0);

	if(!rt)
	{
		fl4 = &fl4_stack;			//???
		flowi4_init_output(fl4, ipc.oif, sk->sk_mark, tos,
				   RT_SCOPE_UNIVERSE, sk->sk_protocol,
				   flow_flags,
				   faddr, saddr, dport, inet->inet_sport,
				   sk->sk_uid);				//???
		security_sk_classify_flow(sk, flowi4_to_flowi(fl4));   //??
		rt = ip_route_output_flow(net, fl4, sk);
		
		if (IS_ERR(rt)) 
		{
			err = PTR_ERR(rt);
			rt = NULL;
			if (err == -ENETUNREACH)	IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
			goto out;
		}
		err = -EACCES;
		if ((rt->rt_flags & RTCF_BROADCAST) && !sock_flag(sk, SOCK_BROADCAST))	goto out;
		if (connected)	sk_dst_set(sk, dst_clone(&rt->dst));
	}
	
	
	saddr = fl4->saddr;
	
	if (!ipc.addr)	daddr = ipc.addr = fl4->daddr;
	
	skb = IP_MAKE_SKB(sk, fl4, getfrag, msg, ulen, sizeof( seanet_hdr), &ipc, &rt, msg->msg_flags);
	
	err = PTR_ERR(skb);
	if (!IS_ERR_OR_NULL(skb))
		
		err = __pad_and_send_feedback(skb, fl4,IMMEDIATE_FEEDBACK);
	goto out;
		
out:
	ip_rt_put(rt);	//释放对路由缓存的引用

	if (!err)
		return err;

	return err;
	
}

*/


//rate sample!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
void seadp_rate_request_sent(struct sock *sk,  struct request_sk *rsk)
{
	struct seadp_sock *sh = seadp_sk(sk);
	
	if (!sh->packets_out) 
	{
		sh->first_tx_mstamp  = rsk->request_mstamp;
		sh->delivered_mstamp = rsk->request_mstamp;
	}
	
	rsk->delivered		= sh -> delivered;
	rsk->delivered_mstamp	= sh -> delivered_mstamp;
	rsk->first_tx_mstamp	= sh ->	first_tx_mstamp;
	rsk->is_app_limited	= sh -> app_limited ? 1 : 0;
	
}


/* Congestion state accounting after a packet has been sent. */
static void seadp_event_data_sent(struct seadp_sock *sh, struct sock *sk)
{
	const u32 now = ((u32)jiffies);

	if (seadp_packets_in_flight(sh) == 0)
	{
		printk("%s: !!!\n", __func__);	
		//seadp_ca_event(sk, CA_EVENT_TX_START);
	}
	sh->lsndtime = now;

	
}
//低层次的seadp发包封装,对seadp首部只进行了部分封装（源、目的端口号）
static int seadp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask, struct seanet_head_info *head_info, struct request_sk *rsk)
{
	struct inet_sock *inet;
	struct seadp_sock *sh;
	struct seadp_skb_cb *scb;

	struct rtable *rt;

	seanet_hdr *shdr;
	int err;

	BUG_ON(!skb );
	sh = seadp_sk(sk);

	
	//seadp_mstamp_refresh(sh);
	//skb->skb_mstamp = sh->seadp_mstamp;	//应该是在上层每次发送会更新记录整个套接字的时间戳，这一段时间内发送的所有skb都是在skb_mstamp记录第一次发送的时间戳用于测量RTT

	inet = inet_sk(sk);
	scb = SEADP_SKB_CB(skb);

	skb->pfmemalloc = 0;
	skb_push(skb, sizeof(seanet_hdr));	//加入seanet首部
	skb_reset_transport_header(skb);	//重置传输层指针
/*
	skb_orphan(skb);
	skb->sk = sk;	
	
	//skb->destructor = skb_is_tcp_pure_ack(skb) ? __sock_wfree : tcp_wfree;	//TCP将纯的ACK报文的skb->truesize设置为2！！这里与	
	skb->destructor =  __sock_wfree;	//待改进
	
	//skb_set_hash_from_sk(skb, sk);	//待改进
	refcount_add(skb->truesize, &sk->sk_wmem_alloc);
*/
	//skb_set_owner_w(skb, sk);

	skb_orphan(skb);
	skb->sk = sk;
	skb_set_hash_from_sk(skb, sk);
	skb_set_dst_pending_confirm(skb, sk->sk_dst_pending_confirm);	//待改进
	
	/* Build SEADP header and checksum it. */
	
	shdr = (seanet_hdr *)skb->data;
	shdr->src_port		= inet->inet_sport;
	shdr->dst_port		= inet->inet_dport;
	shdr->chunk_len		= htonl(head_info->len);	
	shdr->offset		= htonl(head_info->seq);	
	shdr->req		= 1;		//置位！！！
	/*

	*/
	skb_shinfo(skb)->gso_type = sk->sk_gso_type;
//有关pacing！！！很重要！	
	//1//printk("%s: before pacing: %X\n", __func__, seadp_clock_us());
	if (likely(scb->seadp_flags & SEADPHDR_DATA_REQUEST))	//首部带有反馈信息，做一些处理！！
	{
		seadp_event_data_sent(sh, sk);
		seadp_internal_pacing(sk, rsk);
		
	}
	rt = (struct rtable *)__sk_dst_check(sk, 0);
	skb_dst_set_noref(skb, &rt->dst);
	////rt = skb_rtable(skb);
	////if(!rt)	printk("%s: no rt cache from skb\n", __func__);
	//rt = (struct rtable *)__sk_dst_check(sk, 0);
	//if(!rt)	printk("%s: no rt cache from sk\n", __func__);

	//1//printk("%s: after pacing: %X\n", __func__, seadp_clock_us());
	
	if (skb->len != sizeof(seanet_hdr))	//长度不等于首部长度，说明是seanet报文有数据载荷！！ 
	{
		//if (seadp_packets_in_flight(sh) == 0)	seadp_ca_event(sk, CA_EVENT_TX_START);//****************
		//tcp_event_data_sent(tp, sk);
		//tp->data_segs_out += tcp_skb_pcount(skb);
		//tcp_internal_pacing(sk, skb);
	}
	////printk("%s: us: %X\n", __func__, seadp_clock_us());
	skb->tstamp = 0;
	/* Cleanup our debris for IP stacks */
	memset(skb->cb, 0, max(sizeof(struct inet_skb_parm), sizeof(struct inet6_skb_parm)));
	
	//////printk("%s: before send us: %X\n", __func__, seadp_clock_us());
	err =	ip_queue_xmit(sk, skb, &inet->cork.fl);	//ip_queue_xmit面向已连接的套接字
	////("err:%d\n",err);
	
	/////printk("%s: after send us: %X\n", __func__, seadp_clock_us());
	if(!err)		//未出错，做rate sample准备!!
	{
		rsk->request_mstamp = sh->seadp_mstamp;	//时间戳批赋值，在发送数据请求前会更新seadp套接字上的seadp_mstamp时间戳，然后在这里赋值给这批发送的所有数据请求对应的请求块
		///seadp_rate_request_sent(sk,  rsk);
	}
	else
	{
		printk("%s: ip_queue_xmit err\n", __func__);
	}
	return err;
}

//高层次的seadp发包函数，最终调用seadp_transmit_skb
//static bool seadp_write_xmit(struct sock *sk, unsigned int mss_now, int nonagle, int push_one, gfp_t gfp)
//{
//
//	return true;
//}


int __seadp_send_ack(struct sock *sk, u8 feedback_type, struct seanet_head_info *head_info,struct request_sk* rsk)	//发送反馈的函数！！！！！所有反馈皆从这里发出！！！！
{
	struct sk_buff *buff; 

	/////buff = alloc_skb(MAX_SEADP_HEADER, sk_gfp_mask(sk, GFP_ATOMIC | __GFP_NOWARN ));
	/////skb_reserve(buff, MAX_SEADP_HEADER);

	//buff->ip_summed = CHECKSUM_PARTIAL;
	//buff->csum = 0;
	/////sk->sk_no_check_tx = 1;
	/////buff->truesize = 2;
	/////SEADP_SKB_CB(buff)->seadp_flags = feedback_type;

	//1//printk("%s: before skb_clone: %X\n", __func__, seadp_clock_us());
	buff = skb_clone(seadp_sk(sk)->request_skb, sk_gfp_mask(sk, GFP_ATOMIC | __GFP_NOWARN ));
	//1//printk("%s: after skb_clone: %X\n", __func__, seadp_clock_us());
	if (unlikely(!buff))
	{
		printk("%s: skb_clone err\n", __func__);
		return 1;
	}

/*
	switch(feedback_type)
	{
		case SEADPHDR_DATA_REQUEST:
			//数据请求报文，做一些操作！！			
						

			break;		
			
		default:
			break;

	}
*/
	
	return seadp_transmit_skb(sk, buff, 0, (__force gfp_t)0, head_info,rsk);	
}

static bool seadp_pacing_check(const struct sock *sk)
{
	return seadp_needs_internal_pacing(sk) && hrtimer_active(&seadp_sk(sk)->pacing_timer);
}

static void seadp_internal_pacing(struct sock *sk, const struct request_sk *rsk)
{
	struct seadp_sock *sh = seadp_sk(sk);
	u64 len_ns;
	u32 rate;
	s64 trigger_time;
	int pack_num, payload_len;
	//if (!seadp_needs_internal_pacing(sk))
	//	return;
	rate = sk->sk_pacing_rate;
	if (!rate || rate == ~0U)
	{
		printk("%s: pacing rate err\n", __func__);	
		return;
	}
	/* Should account for header sizes as sch_fq does,
	 * but lets make things simple.
	 */
	//len_ns = (u64)skb->len * NSEC_PER_SEC;
	pack_num = (rsk->len / SEADP_MSS);
	payload_len = (SEADP_MSS + sizeof(seanet_hdr) + sizeof(struct iphdr));
	//payload_len = (SEADP_MSS + sizeof(seanet_hdr) );
	len_ns = (u64)((u64)pack_num * (u64)payload_len * NSEC_PER_SEC);
	
	do_div(len_ns, rate);
	//311//printk("%s: %X\n", __func__, seadp_clock_us());
	//printk("%s: ns time: %ld\n", __func__, ktime_get());
	trigger_time = ktime_add_ns(ktime_get(), len_ns);
	sh->trigger_time = trigger_time;
	////debian//////printk("sk->sk_pacing_rate: %ld, rsk->len: %d, len_ns: %llu, us %X\n, ns: %llu, trigger: %llu\n", sk->sk_pacing_rate, rsk->len, len_ns, seadp_clock_us(), ktime_get(),trigger_time);
	//printk("%s: start hrtime, internal_ns: %X\n",__func__, len_ns);
	hrtimer_start(&seadp_sk(sk)->pacing_timer, trigger_time , HRTIMER_MODE_ABS_PINNED);
	
}
/*
static bool seadp_request_data(struct sock *sk,struct seanet_head_info *head_info)	//构造请求块（做RTT估计用），并发送数据请求反馈报文
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct request_sk *p;
	u32 hash_key;
	//1//struct request_sk test_sk;
	
	//1//p = &test_sk;
	//1//p->len = SEADP_MSS;
	//no //////("%s\n", __func__);
		
	p = (struct request_sk*)kmalloc(sizeof(struct request_sk), GFP_ATOMIC | __GFP_NOWARN |  __GFP_ZERO);	//分配请求块！！
	if(!p)
	{
		printk("%s error!\n", __func__);
		return false;
	}
	
	hash_key = head_info->seq % REQUEST_HASH_LEN;	//这里没有用jhash或者jhash_2words(% REQUEST_HASH_LEN)等复杂的离散方式
	
	
	hlist_add_head(&(p->node), &((sh->request_hash_array)[hash_key]) );	//哈希链首部插入
	
	//加入双向链表尾部
	list_add_tail(&p->list_node, &sh->lhead);
	///////////////if(sh->expect == NULL) sh->expect = list_first_entry(&sh->lhead, struct request_sk, list_node);
	//设置数据部分
	p->seq = head_info->seq;
	p->len = head_info->len;
	//no //////("%s: seq:%d, len:%d\n", __func__, p->seq, p->len);
	sh->request_count++;
	//p->request_mstamp = sh->seadp_mstamp;	//时间戳批赋值，在发送数据请求前会更新seadp套接字上的seadp_mstamp时间戳，然后在这里赋值给这批发送的所有数据请求对应的请求块
	//sh->packets_out++;
	//生成数据请求报文，并发送


	__seadp_send_ack(sk, SEADPHDR_DATA_REQUEST,head_info, p);


	return true;
}
*/

static bool seadp_request_data(struct sock *sk,struct seanet_head_info *head_info)	//构造请求块（做RTT估计用），并发送数据请求反馈报文
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct request_sk *p;
	u32 hash_key;
	
		
	p = (struct request_sk*)kmalloc(sizeof(struct request_sk), GFP_ATOMIC | __GFP_NOWARN |  __GFP_ZERO);	//分配请求块！！
	if(!p)
	{
		printk("%s error!\n", __func__);
		return false;
	}
	
	hash_key = head_info->seq % REQUEST_HASH_LEN;	//这里没有用jhash或者jhash_2words(% REQUEST_HASH_LEN)等复杂的离散方式
	
	
	hlist_add_head(&(p->node), &((sh->request_hash_array)[hash_key]) );	//哈希链首部插入
	
	//加入双向链表尾部
	list_add_tail(&p->list_node, &sh->lhead);
	///////////////if(sh->expect == NULL) sh->expect = list_first_entry(&sh->lhead, struct request_sk, list_node);
	//设置数据部分
	p->seq = head_info->seq;
	p->len = head_info->len;
	//no //////("%s: seq:%d, len:%d\n", __func__, p->seq, p->len);
	sh->request_count++;
	//p->request_mstamp = sh->seadp_mstamp;	//时间戳批赋值，在发送数据请求前会更新seadp套接字上的seadp_mstamp时间戳，然后在这里赋值给这批发送的所有数据请求对应的请求块
	//sh->packets_out++;
	//生成数据请求报文，并发送
	p->request_mstamp = sh->seadp_mstamp;	//时间戳批赋值，在发送数据请求前会更新seadp套接字上的seadp_mstamp时间戳，然后在这里赋值给这批发送的所有数据请求对应的请求块
	seadp_rate_request_sent(sk,  p);	//必须在这里设置

	//__seadp_send_ack(sk, SEADPHDR_DATA_REQUEST,head_info, p);


	return true;
}

void show_skb(struct sk_buff* skb)
{
	//("===============================================\n");
	//("align size of struct sk_buff: %d\n", SKB_DATA_ALIGN(sizeof(struct sk_buff)));
	//("align size of struct skb_shared_info: %d\n", SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));
	//("skb->protocol: %X\n",skb->protocol);
	//("skb->pkt_type: %d\n",skb->pkt_type);	
	//("skb->users: %d\n",(skb->users).refs.counter);	
	//("skb->len: %d\n", skb->len);
	//("skb->data_len: %d\n", skb->data_len);
	//("skb->truesize: %d\n", skb->truesize);
	//("skb->hdr_len: %d\n", skb->hdr_len);	
	//("skb->transport_header: %d\n", skb->transport_header);
	//("skb->network_header: %d\n", skb->network_header);
	//("skb->mac_header: %d\n", skb->mac_header);
		
	//("skb->head: %X\n", skb->head);
	//("skb->data: %X\n", skb->data);
	//("skb->tail: %X\n", skb->tail);
	//("skb->end : %X\n", skb->end);
	//("===============================================\n");
}

void skb_condense(struct sk_buff *skb)
{
	if (skb->data_len) 
	{
		if (skb->data_len > skb->end - skb->tail || skb_cloned(skb))
			return;

		/* Nice, we can free page frag(s) right now */
		__pskb_pull_tail(skb, skb->data_len);
	}
	/* At this point, skb->truesize might be over estimated,
	 * because skb had a fragment, and fragments do not tell
	 * their truesize.
	 * When we pulled its content into skb->head, fragment
	 * was freed, but __pskb_pull_tail() could not possibly
	 * adjust skb->truesize, not knowing the frag truesize.
	 */
	skb->truesize = SKB_TRUESIZE(skb_end_offset(skb));
}

/**************注册传输层协议（对下层）*********/
int seadp_early_demux(struct sk_buff *skb)
{
	return 0;
}
static inline int seadp_check_csum(void) //检验校验和函数，待定～～～
{

	return 0;
}
//获得一个符合条件的seadp套接字
static inline struct sock *__seadp4_lib_lookup_skb(struct sk_buff *skb, \
						__be16 sport, __be16 dport, \
						struct seadp_table *seadptable)
{
//软中断环境禁止抢占，其实不必显式调用rcu_read_lock～～～～?????
	struct sock *sk_ptr;	
	u16 index = dport % HASH_LEN;
	const struct iphdr *iph = ip_hdr(skb);

//inet_rcv_saddr已经是网络字节序
	rcu_read_lock();
	hlist_for_each_entry_rcu(sk_ptr, &(hash_array[index].head), sk_node)	//哈希桶遍历！！！！
	{
		////("inet_sk->inet_sport:%X\n", inet_sk(sk_ptr)->inet_sport);
		////("inet_sk->inet_rcv_saddr:%X\n", inet_sk(sk_ptr)->inet_rcv_saddr);
		if (   inet_sk(sk_ptr)->inet_sport == dport  &&  (inet_sk(sk_ptr)->inet_rcv_saddr ==htonl(INADDR_ANY)  ||inet_sk(sk_ptr)->inet_rcv_saddr==iph->daddr)   )
		{
			rcu_read_unlock();
			return sk_ptr;
		}
	}
	rcu_read_unlock();
	return NULL;   //待定～～～
}

void sk_forced_mem_schedule(struct sock *sk, int size)
{
	int amt;

	if (size <= sk->sk_forward_alloc)
		return;
	amt = sk_mem_pages(size);
	sk->sk_forward_alloc += amt * SK_MEM_QUANTUM;
	sk_memory_allocated_add(sk, amt);

	if (mem_cgroup_sockets_enabled && sk->sk_memcg)
		//mem_cgroup_charge_skmem(sk->sk_memcg, amt);
		MEM_CGROUP_CHARGE_SKMEM(sk->sk_memcg,amt);
}
//丢包大部分情况发生下在下面函数之中,尤其是atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf（通过函数中两个注释的打印可以印证这一点！），意味着应用层处理慢于协议栈收包速度，
//所以receive队列(sk->sk_rmem_alloc)淤积了太多skb，而超过了单个传输控制块接收队列内存限制(sk->rcvbuff)，这个sk->sk_rcvbuf这里默认为sysctl_rmem_default系统参数值，
//存储于/proc/sys/net/core/rmem_default，此机器上是212992。   
//对于sk->sk_prot->memory_allocated超出套接字层面的压力限制在系统套接字数量较少时不太可能，因为3个压力阈值存于/proc/sys/net/ipv4/udp_mem或者/proc/sys/net/ipv4/tcp_mem，
//其中数值以物理页(4096B)为单位！！！这里seadp借鉴了udp的3个阈值，即90324，120435，180648

static int seadp_try_rmem_schedule(struct sock *sk, struct sk_buff *skb, unsigned int size)
{
	if(atomic_read(&sk->sk_rmem_alloc) > sk->sk_rcvbuf || !sk_rmem_schedule(sk, skb, size))
	{
		if(atomic_read(&sk->sk_rmem_alloc) <= sk->sk_rcvbuf) printk("1\n");
		printk("sk->sk_rmem_alloc: %d\n", atomic_read(&sk->sk_rmem_alloc));
		////("memory schedule error!\n");
		return -1;
	}
	return 0;
}

static inline u32 seadp_receive_window(const struct seadp_sock *sh)
{
	s32 win = sh->rcv_wup + sh->rcv_wnd - sh->rcv_nxt;

	if (win < 0)
		win = 0;
	return (u32) win;
}

static void seadp_rcv_nxt_update(struct seadp_sock *sh, u32 seq)	//更新rcv_nxt
{
	u32 delta = seq - sh->rcv_nxt;

	sh->bytes_received += delta;
	sh->rcv_nxt = seq;
}


void seadp_rate_skb_delivered(struct sock *sk, struct sk_buff *skb, struct seadp_rate_sample *rs)	//对比tcp_rate_skb_delivered
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct request_sk *target = SEADP_SKB_CB(skb)->target;
	//struct seadp_skb_cb *scb = SEADP_SKB_CB(skb);
	
	if (!target->delivered_mstamp)	return;
	
	if(!rs->prior_delivered || after(target->delivered, rs->prior_delivered))////可能不必要判断，因为一个ack可能会出发tcp_rate_skb_delivered多次调用，但这里seadp不存在这种情况
	{
		rs->prior_delivered  = target->delivered;	//这些参数参见BBR论文
		rs->prior_mstamp     = target->delivered_mstamp;
		rs->is_app_limited   = target->is_app_limited;	//bbr
		rs->is_retrans	     = target-> requested & SEADP_RETRANS;		//这点很重要，需要标记！！！！

		rs->interval_us	= seadp_stamp_us_delta(target->request_mstamp, target->first_tx_mstamp);	//?????????????

		/* Record send time of most recently ACKed packet: */
		sh->first_tx_mstamp  = target->request_mstamp;


	}	

	//if (scb->sacked & TCPCB_SACKED_ACKED)
		//scb->tx.delivered_mstamp = 0;
	
}

static void seadp_update_rtt_min(struct sock *sk, u32 rtt_us)
{
	struct seadp_sock *sh = seadp_sk(sk);
	u32 wlen = SYSCTL_SEADP_MIN_RTT_WLEN * HZ;

	MINMAX_RUNNING_MIN(&sh->rtt_min, wlen, (u32)jiffies, rtt_us ? : jiffies_to_usecs(1));
}

static void seadp_rtt_estimator(struct sock *sk, long mrtt_us)
{
	struct seadp_sock *sh = seadp_sk(sk);
	long m = mrtt_us; // RTT 
	u32 srtt = sh->srtt_us;
	
	if (srtt != 0) 
	{
		m -= (srtt >> 3);	//srtt is the old measurement value
		srtt += m;		// rtt = 7/8 rtt + 1/8 new 
		if (m < 0) //new rtt changes to small 
		{
			m = -m;		// m is now abs(error) 
			m -= (sh->mdev_us >> 2);   // similar update on mdev 
			
			if (m > 0)
				m >>= 3;	

		}
		else	//new rtt changes to big,  m>=0 case
		{
			m -= (sh->mdev_us >> 2);   // similar update on mdev 
		}

		sh->mdev_us += m;		// mdev = 3/4 mdev + 1/4 new 
		if (sh->mdev_us > sh->mdev_max_us)
		{
			sh->mdev_max_us = sh->mdev_us;
			if (sh->mdev_max_us > sh->rttvar_us)
				sh->rttvar_us = sh->mdev_max_us;
		}
		if (after(sh->snd_una, sh->rtt_seq)) 
		{
			//("%s: after RTT window\n", __func__);
			if (sh->mdev_max_us < sh->rttvar_us)
				sh->rttvar_us -= (sh->rttvar_us - sh->mdev_max_us) >> 2;
			sh->rtt_seq = sh->snd_nxt;
			sh->mdev_max_us = seadp_rto_min_us(sk);
		}
		
	}
	else 
	{
		// no previous measure. 
		srtt = m << 3;		// take the measured time to be rtt 
		sh->mdev_us = m << 1;	// make sure rto = 3*rtt, look seadp_set_rto()
		sh->rttvar_us = max(sh->mdev_us, seadp_rto_min_us(sk)); 
		sh->mdev_max_us = sh->rttvar_us;
		sh->rtt_seq = sh->snd_nxt;	//!!!!!!!!!!  This is to initialize rtt_seq
	}

	sh->srtt_us = max(1U, srtt);
}

static void seadp_set_rto(struct sock *sk)
{
	struct seadp_sock *sh = seadp_sk(sk);

	sh->spsk_rto	= __seadp_set_rto(sh);

	if (sh->spsk_rto > SEADP_RTO_MAX)	
		sh->spsk_rto = SEADP_RTO_MAX;
}

static bool seadp_ack_update_rtt(struct sock *sk, const int flag, long seq_rtt_us,  long ca_rtt_us, struct seadp_rate_sample *rs)
{
	struct seadp_sock *sh = seadp_sk(sk);

	rs->rtt_us = ca_rtt_us + MIN_RTT_ADD;
	//("seq_rtt_us: %d, ca_rtt_us: %d\n", seq_rtt_us, ca_rtt_us);
	if (seq_rtt_us < 0)	return false;	//a retransmitted-requested data is not used to update RTT inorder to eliminate ambiguity of retransmission

	seadp_update_rtt_min(sk, ca_rtt_us);
	seadp_rtt_estimator(sk, seq_rtt_us);
	seadp_set_rto(sk);

//below is test

	if(sh->rtt_sample_times < 20)
	{
		printk("seq_rtt_us: %d, RTT: %d , RTO: %d, RTO from 3*RTT: %d, RTT from RTO: %d\n", seq_rtt_us, (sh->srtt_us >>3), sh->spsk_rto, usecs_to_jiffies(3*(sh->srtt_us >>3)),jiffies_to_usecs(sh->spsk_rto));
		
	}
	sh->rtt_sample_times++;	
////////////////
	sh->spsk_backoff = 0;
	//sh->spsk_retransmits = 0;
	return true;
}
static int seadp_clean_rreq_queue(struct sock *sk, struct sk_buff *skb, struct seadp_rate_sample *rs)
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct request_sk *ptr;
	struct request_sk *target = SEADP_SKB_CB(skb)->target;
	u8 requested = target->requested;	//记录请求块request_sk是不是重传过
	u64 first_request = 0, last_request;
	u32 acked_len = target->len;
	long seq_rtt_us = -1L;
	long ca_rtt_us = -1L;
	int flag = 0;
	bool rtt_update;
	
	if(unlikely(requested & SEADP_RETRANS))	//这个skb数据对应的请求是重传过的
	{
		//进入特殊的处理逻辑
		//no //////("A retansmited-requested data arrive!\n");
		sh->retrans_out -= 1;
		flag |= FLAG_RETRANS_DATA_ACKED;		
	}
	else  
	{	//此skb回应了首次发送的请求request_sk，进入正常处理逻辑
		last_request = 	target->request_mstamp;	//获取上一次请求数据时的时间戳
			
		if (!first_request)	first_request = last_request;	//??????
		
		
	}
	
	sh->delivered += 1;		//交付数据包字节数统计更新

	if (requested & SEADP_LOST)
	{
		sh->lost_out -= 1; 
		/*
		if(target == sh->last_lost)
		{
			if(sh->last_lost->list_node.prev != &sh->lhead)
			{
				sh->last_lost = list_prev_entry(sh->last_lost, list_node);
			}		
			else
			{
				sh->last_lost = NULL;		
			}					
		}

		if(sh->has_fast_retrans && sh->lost_out == 0)	sh->has_fast_retrans = false;
		*/	
	}
	

	seadp_rate_skb_delivered(sk, skb, rs);

	list_del(&(target->list_node));	//从链表中删除
	hlist_del(&(target->node));		//从哈希表中删除
	kfree(target);
	//更新packets_out
	sh->packets_out -= 1;

	
	if (likely(first_request) && !(flag & FLAG_RETRANS_DATA_ACKED)) 
	{
		//no //////("delta compute\n");
		seq_rtt_us = seadp_stamp_us_delta(sh->seadp_mstamp, first_request);
		ca_rtt_us = seadp_stamp_us_delta(sh->seadp_mstamp, last_request);
	}
	//no //////("sh->packets_out: %d\n", sh->packets_out);
	//printk("request time: %X, receive time: %X, delta: %d\n", target->request_mstamp, sh->seadp_mstamp, sh->seadp_mstamp- target->request_mstamp);
	rtt_update = seadp_ack_update_rtt(sk, flag, seq_rtt_us,  ca_rtt_us, rs);

}

//思考：在软中断路径上频繁做kfree合适吗？？
static bool match_get_request_sk(struct sock *sk, struct sk_buff *skb)
{
	struct seadp_sock *sh = seadp_sk(sk);
	u32 skb_seq = SEADP_SKB_CB(skb)->seq;
	struct request_sk  *request_sk_ptr;
	
	/*这里可以加一些简单的判断逻辑，来快速防止恶意攻击，比如end_seq与snd_nxt和snd_una等的比较，来快速过滤一些违法数据包
	*
	*list_first_entry(&sh->lhead, struct request_sk, list_node)
	*/
	////////if(!sh->expect)	//到头了，后面没有了
	if(list_empty(&sh->lhead))	
	{
		return false;
	}
	//no //////("skb_seq:%d, skb->len:%d\n", skb_seq, skb->len);
	request_sk_ptr = list_first_entry(&sh->lhead, struct request_sk, list_node);
	////////if(  (skb_seq ==sh->expect->seq) && (skb->len == sh->expect->len) )
	
	if((skb_seq ==request_sk_ptr->seq) && (skb->len == request_sk_ptr->len))	
	{
		////////SEADP_SKB_CB(skb)->target = sh->expect;
		SEADP_SKB_CB(skb)->target =request_sk_ptr;
		////////sh->expect = (  (sh->expect)->list_node.next != &sh->lhead )?list_next_entry(sh->expect,list_node) : NULL;
		
		//no //////("list get\n");
		return true;
	}
	else//遍历哈希表寻找
	{
		hlist_for_each_entry(request_sk_ptr, &(sh->request_hash_array[skb_seq % REQUEST_HASH_LEN]), node)
		{
			if(   (SEADP_SKB_CB(skb)->seq ==request_sk_ptr->seq) && (skb->len == request_sk_ptr->len)     )
			{
				SEADP_SKB_CB(skb)->target =  request_sk_ptr;
				
				//no //////("hash get!!!!!!!!!\n");
				return true;

			}			
		}
	}

	//no //////("data was not requested\n");
	return false;
}

void detach_free_request_sk_in_skb(struct sk_buff *skb)
{
	struct request_sk *target = SEADP_SKB_CB(skb)->target;
	
	list_del(&(target->list_node));	//从链表中删除
	hlist_del(&(target->node));		//从哈希表中删除

	kfree(target);

}

static int seadp_update_window(struct sock *sk, struct sk_buff *skb, u32 end_seq)
{
	
}


// Update the connection delivery information and generate a rate sample. 
//delivered是新交付的数据包数，lost是新增丢失的数据包数，两者均累计增长
void seadp_rate_gen(struct sock *sk, u32 delivered, u32 lost, struct seadp_rate_sample *rs)	//获取时间间隔，以及更新时间戳！！！例如delivered_mstamp等
{
	struct seadp_sock *sh = seadp_sk(sk);
	u32 snd_us, ack_us;

	/* Clear app limited if bubble is acked and gone. */
	if (sh->app_limited && after(sh->delivered, sh->app_limited))	//dddddddddddddddddd
		sh->app_limited = 0;

	if (delivered)	sh->delivered_mstamp = sh->seadp_mstamp;	//获取当前时间current time, delivery_mstamp为解说到
	
	rs->acked_sacked = delivered;	// freshly ACKed or SACKed 
	rs->losses = lost;		// freshly marked lost 

	if (!rs->prior_mstamp) 
	{
		rs->delivered = -1;
		rs->interval_us = -1;
		return;
	}

	rs->delivered   = sh->delivered - rs->prior_delivered;	//获取新交付的数据包个数！！！！！
	

	/* Model sending data and receiving ACKs as separate pipeline phases
	 * for a window. Usually the ACK phase is longer, but with ACK
	 * compression the send phase can be longer. To be safe we use the
	 * longer phase.
	 *///关于snd_us ack_us在tcp_rate.c最开始注释已经说明了原因 bw =  min (send_rate, ack_rate)
	snd_us = rs->interval_us;				// send phase 在 seadp_rate_skb_delivered中已经设置好了
	ack_us = seadp_stamp_us_delta(sh->seadp_mstamp, rs->prior_mstamp); // ack phase 
	
	rs->interval_us = max(snd_us, ack_us);	//bw取小，则interval要取大
	
	if (unlikely(rs->interval_us < seadp_min_rtt(sh))) 	//ddddddddddddddddddddddddd
	{
		if (!rs->is_retrans)	//("%s\n", __func__);
		rs->interval_us = -1;
		return;
	}

	// Record the last non-app-limited or the highest app-limited bw 
/*	if (!rs->is_app_limited ||
	    ((u64)rs->delivered * tp->rate_interval_us >=
	     (u64)tp->rate_delivered * rs->interval_us)) {
		tp->rate_delivered = rs->delivered;
		tp->rate_interval_us = rs->interval_us;
		tp->rate_app_limited = rs->is_app_limited;
	}
*/


}

static void seadp_cong_control(struct sock *sk, const struct seadp_rate_sample *rs)
{
	struct seadp_sock *sh = seadp_sk(sk);

	if (sh->seadp_ca_ops->cong_control)	//拥塞控制逻辑进行接管！！！ 
	{
		sh->seadp_ca_ops->cong_control(sk, rs);
		return;
	}

	/*后面先省略
	*
	*
	*/
}

/* Restart timer after forward progress on connection.
 * RFC2988 recommends to restart timer to now+rto.
 */
static void seadp_set_xmit_timer(struct sock *sk)
{
	struct seadp_sock *sh = seadp_sk(sk);
	u32 rto;
	s64 delta_us;

//timer mark earlies sent request_sk!!!!!!!!!!!!!!!!!!!!!
	//sh->timer_target = (sh->lhead.next != &sh->lhead)?list_first_entry(&sh->lhead, struct request_sk, list_node):(struct request_sk *)NULL;

	if (!sh->packets_out)	//there are not in flight packets, stop RTO timer!! 
	{
		///printk("%s: clear xmit timer! sh->snd_nxt: %d, sh->packets_out: %d\n", __func__, sh->snd_nxt, sh->packets_out);
		seadp_clear_xmit_timer(sk, SPSK_TIME_RETRANS);
	} 
	else //sh->lhead is not empty!!
	{
		////printk("%s: reset xmit timer!\n", __func__);
//timer mark earlies sent request_sk!!!!!!!!!!!!!!!!!!!!!
		sh->start_seq = sh->snd_una;		
		sh->timer_target = list_first_entry(&sh->lhead, struct request_sk, list_node);

		u32 rto = sh->spsk_rto;
		/* Offset the time elapsed after installing regular RTO */
		//if (icsk->icsk_pending == ICSK_TIME_REO_TIMEOUT ||
		//    icsk->icsk_pending == ICSK_TIME_LOSS_PROBE) {
		
		//////1.25/////s64 delta_us = seadp_rto_delta_us(sk);	//too frequent retranstimer results in too high compete overhead!!!
			/* delta_us may not be positive if the socket is locked
			 * when the retrans timer fires and is rescheduled.
			 */
		//////1.25/////rto = usecs_to_jiffies(max_t(int, delta_us, 1));
		//}
		////printk("%s: rto: %X\n", __func__, sh->spsk_rto);
		seadp_reset_xmit_timer(sk, SPSK_TIME_RETRANS, rto, SEADP_RTO_MAX);	//now+rto.
	}

}

int seadp_retransmit_request(struct sock *sk, struct request_sk *target)	//compared with tcp_retransmit_skb()!!!!
{
	struct seadp_sock *sh = seadp_sk(sk); 
	int err;
	struct seanet_head_info head_info;	

	head_info.seq = target->seq;
	head_info.len = target->len;
	printk("%s\n", __func__);
	err = __seadp_send_ack(sk, SEADPHDR_DATA_REQUEST,&head_info, target);

	target->requested |= SEADP_RETRANS;	//mark this request_sk is retransmitted !!!!(fast retrans or RTO time out retrans!!)
	sh->retrans_out += seadp_request_pcount(target);	//record

	return err;

}

int seadp_fast_retrans(struct sock *sk, int rexmit)	//我们来按顺序遍历请求队列，来标记要重传的请求块request_sk
{
	struct seadp_sock *sh = seadp_sk(sk); 
	struct request_sk *target;
	struct sk_buff *skb = rb_to_skb(rb_first(&sh->out_of_order_queue));
	u32 max_seq_to_fast_retrans = SEADP_SKB_CB(skb)->seq;
	int retrans_num = 0;
	//		
	list_for_each_entry(target, &sh->lhead, list_node)	//iteration requesk_sk list to fast retransmit satisfied request_sk
	{
		if(target->seq >= max_seq_to_fast_retrans) break;

		target->requested |= SEADP_LOST;		//mark lost state!!!!
		printk("%s\n", __func__);
		seadp_retransmit_request(sk, target);	//retransmit request_sk
		
		retrans_num += seadp_request_pcount(target);	//get number of packet fast retranmitted this time!!!!
	}

	sh->lost_out 	+= retrans_num;
	sh->lost 	+= retrans_num;
	
	
	//no //////("fast retransmission: %s: %d re-request\n", __func__, retrans_num);
	///sh->has_fast_retrans = true;

	return 0;
}

int retrans_request_segs(struct sock *sk, int segs, int mss_num, struct request_sk *target_start, struct seanet_head_info *head_info)
{
	struct seadp_sock *sh = seadp_sk(sk); 
	struct request_sk p;
	int err;
	int i;

	p.seq = head_info->seq;
	p.len = head_info->len;
	//printk("%s: retrans start seq: %d, len: %d\n", __func__, p.seq, p.len);
	if(    likely(  (err = __seadp_send_ack(sk, SEADPHDR_DATA_REQUEST, head_info, &p)) == 0  )         )	//发送成功
	{
		//retrans//printk("%s: retrans from %lu, len: %d\n", __func__, p.seq, p.len);
		for(i=0;i<segs;i++)	//我们需要给此连续聚合段中的每个request_sk都用seadp_rate_request_sent记录参数
		{
			seadp_rate_request_sent(sk,  target_start);//////
			target_start -> requested |= SEADP_RETRANS;	//标记此包为重传！！！！
			target_start = list_next_entry(target_start, list_node);
		}
		sh->retrans_out += mss_num;
		//更新下定时器！！！！但只有发送包括request_sk队列队首request_sk在内的请求聚合时才重置定时器！！！！！
		if( target_start == list_first_entry(&sh->lhead, struct request_sk, list_node)    )
		{
			//sh->timer_target = list_first_entry(&sh->lhead, struct request_sk, list_node);	//!!!!!
			seadp_reset_xmit_timer(sk, SPSK_TIME_RETRANS, sh->spsk_rto, SEADP_RTO_MAX);
		}
	}
	return err;

}


void seadp_xmit_retransmit_queue(struct sock *sk)	//去重传一些已经标记丢失的数据包！！！！
{
	struct seadp_sock *sh = seadp_sk(sk); 
	struct sk_buff *skb = rb_to_skb(rb_first(&sh->out_of_order_queue));
	u32 max_seq_to_fast_retrans = SEADP_SKB_CB(skb)->seq;
	struct request_sk *target;
	struct request_sk *target_start ;	//记录下连续聚合段的起始request_sk！！！

	struct seanet_head_info head_info;
	struct request_sk p;
	int segs=0, mss_num=0;
	int quota;
	u8 flags;
	int i;
	int pace =0;
	int all_retrans = 1;

	if (!sh->packets_out)	return;

	//初始查找状态！！
	head_info.seq = 0;
	head_info.len = 1;		//必须！！！
	target_start = NULL;
	
	//retrans//printk("%s\n", __func__);
	list_for_each_entry(target, &sh->lhead, list_node)	//开始遍历请求队列
	{
		if (seadp_pacing_check(sk))		//重传逻辑同样需要pacing，只有重新发送一个连续聚合的请求之后pacing才会开始。初始遍历开始时，要么不满足pacing直接break，要么则需要等到一个聚合请求发送之后pacing hrtimer才会启动！！！  这里放在循环最开始是否合适？？？
		{
			//no //////("%s: hrtimer is active\n", __func__);
			pace= 1;		
			break;
		}
		if (test_bit(SEADP_PACING_DEFERRED_BIT, &sh->pacing_flags))
			clear_bit(SEADP_PACING_DEFERRED_BIT, &sh->pacing_flags);
/*
		if(target->seq >= max_seq_to_fast_retrans)	//已经遍历超过到ofo队列之后的request_sk，结束遍历重传		
		{
			if(mss_num)	//mss_num不为0,把当前聚合的请求发送了，结束！
			{
				printk("%s: iterate over retrans\n", __func__);
				retrans_request_segs(sk,  segs,  mss_num, target_start, &head_info);
			}	
			printk("%s: arrive ofo\n",__func__);		
			break;
		}

*/						
		quota = sh->snd_cwnd - seadp_packets_in_flight(sh);

		//no //////("%s: quota: %d\n", __func__, quota);		
		
		if(quota <= mss_num)	//拥塞窗口已经没有配额了，别遍历聚合了，赶紧发送！！！！
		{
			//no //////("%s: return due to no quota\n", __func__);
			if(mss_num)	//mss_num不为0,把当前聚合的请求发送了，结束！
			{
			
				retrans_request_segs(sk,  segs,  mss_num, target_start, &head_info);
				mss_num = 0;	//必不可少
			}
			//retrans//printk("%s: no cwnd retrans\n", __func__);
			return;
		}
		
		flags = target->requested;


		if(sh->retrans_out >= sh->lost_out)		//retrans_out不会大于lost_out的
		{
			if(mss_num)	//mss_num不为0,把当前聚合的请求发送了，结束！
			{
				
				retrans_request_segs(sk,  segs,  mss_num, target_start, &head_info);
				mss_num = 0;
			}
			//retrans//printk("%s: no lost retrans\n", __func__);
			break;
		}
		else if( !(flags & SEADP_LOST) )
		{
			continue;
		}

		if(flags & SEADP_RETRANS)	//已经标记重传了！！！！这里我们不会再次重传！！！
		{
			
			continue;
		}

		all_retrans = 0;
		//找到满足条件的target了
		if(target->seq != head_info.seq + head_info.len)	//开始一个新的连续聚合段，记录其开始的seq，以及初始化len长度为0！！！
		{
			if(head_info.len != 1 && target_start != NULL)	//且不是初始化寻找连续聚合度的请况，则应该将现有的连续聚合段重新发送出去！！！
			{
				//retrans//printk("%s: not sequential retrans\n", __func__);
				retrans_request_segs(sk,  segs,  mss_num, target_start, &head_info);
				
			}
			target_start = target;	//记录连续聚合段第一个request_sk，其目的是为了发送成功后遍历这些连续聚合段，每个用seadp_rate_request_sent记录参数
			head_info.seq = target->seq;
			head_info.len  = target->len;
			segs = 1;		//此连续聚合段聚合request_sk数！！
			mss_num = seadp_request_pcount(target);		//SEADP_MSS个数
			continue;	//继续下一次遍历
		}
		//不是连续聚合段起始，只需要累加len即可
		head_info.len += target->len;		
		segs++;
		mss_num += seadp_request_pcount(target);
		if(mss_num >= MAX_RETRANS_NUM)	//此连续聚合段的SEADP_MSS数目超过到达最大值MAX_RETRANS_NUM！！！
		{
			//发送一波
			//retrans//printk("%s: MAX retrans\n", __func__);
			retrans_request_segs(sk,  segs,  mss_num, target_start, &head_info);

		//初始化，为寻找下一个连续聚合段做准备！！！
			head_info.seq = 0;
			head_info.len = 1;		//必须！！！
			target_start = NULL;	
			segs = 0;		//此连续聚合段聚合数！！
			mss_num = 0;		
		}

	}

	if(mss_num)	//mss_num不为0,把当前聚合的请求发送了，结束！
	{
				
		retrans_request_segs(sk,  segs,  mss_num, target_start, &head_info);
	}


	//retrans//if(pace) printk("%s: pacing return\n", __func__);
	//retrans//if(all_retrans) printk("%s: all_retrans\n", __func__);
}

/* Congestion control has updated the cwnd already. So if we're in
 * loss recovery then now we do any new sends (for FRTO) or
 * retransmits (for CA_Loss or CA_recovery) that make sense.
 */
int seadp_xmit_recovery(struct sock *sk, int rexmit)
{
	struct seadp_sock *sh = seadp_sk(sk); 
	struct request_sk *target;


	if (sh->lost_out > sh->retrans_out && sh->snd_cwnd > seadp_packets_in_flight(sh)) //(fast) retransmission is also taken into pacing!!! 
	{
	
		seadp_xmit_retransmit_queue(sk);
	}
}

//决定是否触发快速重传逻辑！！！！！！
//小于ofo队首skb->seq的所有request_sk队列中的seq一定是连续的！！！
static void seadp_fastretrans_alert(struct sock *sk, int *rexmit)
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct request_sk *target, *target_next;
	struct sk_buff *skb = rb_to_skb(rb_first(&sh->out_of_order_queue));
	u32 max_seq_to_fast_retrans = SEADP_SKB_CB(skb)->seq;
	u8 flags;
	//int retrans_num = 0;
	int iterate_num = 0;
	int num;
	if( !sh->has_mark_lost && sh->packets_num_in_ofo >= DISORDER_TIMES ) //进入快速重传逻辑，也就是recovery状态，但是bbr不会管这种状态，不管重传，cwnd的设定完全由bbr控制
	{
		//printk("%s: snd_una: %d, rcv_snd: %d\n",__func__, sh->snd_una, sh->rcv_nxt);
		if(sh->sead_ca_state == SEADP_CA_Open)	//正常状态下转入recovery状态，开始快速重传
		{
			list_for_each_entry(target, &sh->lhead, list_node)
			{
				if( (iterate_num >= MAX_MARK_LOST_NUM) || target->seq >= max_seq_to_fast_retrans) break;	//一次性最多标记这么多lost，或者已经遍历到空隙末尾（ofo队首seq）
				
				flags = target->requested;	
				if(!(flags & SEADP_LOST) || ((flags & SEADP_LOST) && (flags & SEADP_RETRANS)))
				{
					sh->lost += seadp_request_pcount(target);	//记录下全局丢包统计
				}

				target->requested |= SEADP_LOST;		//标记SEADP_LOST
				sh->lost_out += seadp_request_pcount(target);
				iterate_num++;

				//retrans_num += seadp_request_pcount(target);	//get number of packet fast retranmitted this time!!!!
	
				//target_next = list_next_entry(target, list_node);
			
				//num = (target_next->seq - target->seq - target->len) / SEADP_MSS;
				//if(&target_next->list_node == &sh->lhead  ||  sh->packets_num_in_ofo - num < DISORDER_TIMES)	break;
			}
			sh->recovery_seq = target->seq;
			if(!iterate_num)  sh->has_mark_lost = true;	//当前成功标记了lost，只有当此段标记的lost序号被成功接收到，这个标记才会被关闭，即重新开启是否进入快速重传的检测！！
			seadp_set_ca_state(sk,SEADP_CA_Recovery); //暂时没用，BBR根本不管乱序快速重传的状态
			*rexmit = iterate_num; //此次共标记Lost的数据包数目
		}
		else	//主要处理SEADP_CA_Loss状态
		{

		}
		
	}

	
}


int seadp_data_info_process(struct sock *sk, struct sk_buff *skb, bool ordered)	//类比tcp_ack。此函数中，skb已经置入的接收缓冲区了，可以改变一些参数，如packets_out等。进入此函数skb信息应该不会改变
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct seadp_rate_sample rs = { .prior_delivered = 0 };
	struct request_sk *target = SEADP_SKB_CB(skb)->target;
	u32 skb_seq = SEADP_SKB_CB(skb)->seq;
	u32 skb_end_seq = SEADP_SKB_CB(skb)->end_seq;
	u32 prior_snd_una = sh->snd_una;	//snd_una是连续的
	int prior_packets = sh->packets_out;
	u32 delivered = sh->delivered;
	u32 lost = sh->lost;
	bool set_retrans_timer = false;
	int rexmit = 0;
	int i;

	////("skb->skb_mstamp:%X\n", skb->skb_mstamp);
 ///*
	seadp_mstamp_refresh(sh);	//更新下seadp套接字时间戳！！！接收时间戳！！！记录下当前Now的时间(current time)
	
	rs.prior_in_flight = seadp_packets_in_flight(sh);	//关键！！！！！！
	
	//if(likely( list_first_entry(&sh->lhead, struct request_sk, list_node) == target))	//能运行到这里，request_sk队列肯定不为空。如果匹配的是第一个request_sk则刷新下snd_una
	//if(likely(target->seq + target->len == sh->rcv_nxt))	//到达的数据包是保序的包！！！！
	if(likely(ordered))	//到达的数据包是保序的包！！！！
	{
		//no //////("%s: match the first request_sk\n", __func__);
		//no //////("%s: sh->rcv_nxt: %d, target->seq: %d, target->len: %d\n", __func__, sh->rcv_nxt, target->seq, target->len);
		//sh->snd_una = target->seq + target->len;	//更新，移向下一个request_sk开始序号seq!!!!!!因为request_sk都是按seq保序排列的
		//sh->snd_una = (  target->list_node.next != &sh->lhead )?list_next_entry(target, list_node)->seq:(prior_snd_una + target->len);	//冒号后面这个应该就等于snd_nxt	
		sh->rcv_tstamp = (u32)jiffies;	//rcv_tstamp is the timestamp of last receiving successive-requested data!!!!!!
		set_retrans_timer = true;	//important!!!!!
		sh->snd_una = sh->rcv_nxt;	
		
		
		sh->spsk_retransmits = 0;	//如果到来的是保序数据包，则设置重传次数为0
		
		//sh->spsk_rto	= __seadp_set_rto(sh);	
#if  FAST_RETRANS_SET
		if(!before(sh->snd_una, sh->recovery_seq) && sh->has_mark_lost)		//恢复至open状态，重新开启快速重传（标记Lost）逻辑
		{
			sh->has_mark_lost = false;
			seadp_set_ca_state(sk,SEADP_CA_Open);
			
		}
#endif	

	}
	
	
	//no //////("%s: sh->snd_una = %d, sh->snd_nxt = %d \n", __func__, sh->snd_una, sh->snd_nxt);
	//tcp_in_ack_event(sk, CA_ACK_WIN_UPDATE);

	

	//if (!prior_packets)	goto no_queue;

	seadp_clean_rreq_queue(sk,skb, &rs);

#if TIMEOUT_RETRANS_SET	
	if(set_retrans_timer)
	{
		//printk("%s: set timer, rto: %d\n", __func__, sh->spsk_rto);
		seadp_set_xmit_timer(sk);	//reset RTO timer
	}
#endif

/*
	if(sh->rtt_sample_times < 10)
	{
		printk("RTT: %d , RTO: %d\n", (sh->srtt_us >>3), sh->spsk_rto);
		sh->rtt_sample_times++;	
	}	
*/
	
#if FAST_RETRANS_SET
	seadp_fastretrans_alert(sk, &rexmit);	

#endif
	delivered = sh->delivered - delivered;	// freshly ACKed or SACKed 
	lost = sh->lost - lost;			// freshly marked lost 


	seadp_rate_gen(sk, delivered, lost, &rs);		////获取时间间隔，以及更新时间戳！！！例如delivered_mstamp等,并生成rate_sample，bbr需要用！！

//test
	if(sh->rtt_sample_times <20)
	{
		printk("congestion sample: rs.delivered: %lu, rs.interval_us: %ld, rs.prior_delivered: %lu, rs.losses: %d, rs.rtt_us: %d, rs.is_app_limited: %d, rs.is_retrans: %d, rs.acked_sacked: %d\n", rs.delivered, rs.interval_us, rs.prior_delivered, rs.losses, rs.rtt_us, (rs.is_app_limited)?(int)1:(int)0 , (rs.is_retrans)?(int)1:(int)0, rs.acked_sacked);

	}

//

#if CONGESTION_SET
	seadp_cong_control(sk, &rs);
#endif

	///sh->snd_cwnd = CWND;
#if FIX_CWND_AND_PACING
	sh->snd_cwnd = CWND; // test    暂时不要让拥塞模块来控制cwnd
	sk->sk_pacing_rate = TEST_PACING_RATE; //test  暂时不要让拥塞模块来控制pacing_rate
#endif

#if FAST_RETRANS_SET	
	seadp_xmit_recovery(sk, rexmit);
#endif	


 //*/
no_queue:

	//("%s\n",__func__);
	return 0;
}

/**
 * seadp_try_coalesce - try to merge skb to prior one
 * @sk: socket
 * @to: prior buffer
 * @from: buffer to add in queue
 * @fragstolen: pointer to boolean
 *
 * Before queueing skb @from after @to, try to merge them
 * to reduce overall memory use and queue lengths, if cost is small.
 * Packets in ofo or receive queues can stay a long time.
 * Better try to coalesce them right now to avoid future collapses.
 * Returns true if caller should free @from instead of queueing it
 */
static bool seadp_try_coalesce(struct sock *sk, struct sk_buff *to, struct sk_buff *from, bool *fragstolen)
{
	int delta;
	*fragstolen = false;
	
	/* Its possible this segment overlaps with prior segment in queue */
	if (SEADP_SKB_CB(from)->seq != SEADP_SKB_CB(to)->end_seq)
		return false;
	if (!skb_try_coalesce(to, from, fragstolen, &delta))	//合并
		return false;
	atomic_add(delta, &sk->sk_rmem_alloc);	//	合并成功后需更新内存记账
	sk_mem_charge(sk, delta);

	SEADP_SKB_CB(to)->end_seq = SEADP_SKB_CB(from)->end_seq;
	return true;
}

static bool seadp_ooo_try_coalesce(struct sock *sk, struct sk_buff *to, struct sk_buff *from, bool *fragstolen)
{
	bool res = seadp_try_coalesce(sk, to, from, fragstolen);
	if (res) 
	{
		u32 gso_segs = max_t(u16, 1, skb_shinfo(to)->gso_segs) + max_t(u16, 1, skb_shinfo(from)->gso_segs);	//?
		skb_shinfo(to)->gso_segs = min_t(u32, gso_segs, 0xFFFF);	//?
	}
	return res;
}
static int  seadp_queue_rcv(struct sock *sk, struct sk_buff *skb, int hdrlen, bool *fragstolen)
{
	int eaten;
	struct sk_buff *tail = skb_peek_tail(&sk->sk_receive_queue);
	eaten = (tail && seadp_try_coalesce(sk,  tail, skb, fragstolen)) ? 1 : 0;
	
	seadp_rcv_nxt_update(seadp_sk(sk), SEADP_SKB_CB(skb)->end_seq);
	if (!eaten) {
		__skb_queue_tail(&sk->sk_receive_queue, skb);
		skb_set_owner_r(skb, sk);
	}
	return eaten;

}

/* This one checks to see if we can put data from the
 * out_of_order queue into the receive_queue.
 */
static void seadp_ofo_queue(struct sock *sk)	//乱序包从ofo队列出列处理！！
{
	struct seadp_sock *sh = seadp_sk(sk);
	__u32 dsack_high = sh->rcv_nxt;
	bool  fragstolen, eaten;
	struct sk_buff *skb, *tail;
	struct rb_node *p;

	p = rb_first(&sh->out_of_order_queue);
	while (p)
	{
		skb = rb_to_skb(p);

		if (after(SEADP_SKB_CB(skb)->seq, sh->rcv_nxt))	break;	//ofo中第一个skb与receive队列最后的end_seq中间有序号间隙，直接退出，不处理ofo
	
//2020.1.26
//certain to take out one (the first) packet in ofo.Here we add a record for fast retransmission in seadp_data_info_process()
		sh->packets_num_in_ofo -= skb->len / SEADP_MSS;
		//////sh->has_fast_retrans = false;	//first skb in ofo being taken out means that the gap is eliminated. This gap is where we do fast retrans!!
////////////////////////////////////////////////////			
		if (before(SEADP_SKB_CB(skb)->seq, dsack_high)) 
		{
			//("%s: overlap skb in receive queue\n", __func__);
		}

		p = rb_next(p);	//准备下一次循环
		//对选中的skb进行处理：从rbtree删除、对错误包释放、更新tail指针、将skb并入receive队列，等待用户进程接收
		rb_erase(&skb->rbnode, &sh->out_of_order_queue);

		if (unlikely(!after(SEADP_SKB_CB(skb)->end_seq, sh->rcv_nxt))) 
		{
			sk_drops_add(sk, skb);
			__kfree_skb(skb);
			continue;
		}
		
		tail = skb_peek_tail(&sk->sk_receive_queue);
		eaten = tail && seadp_try_coalesce(sk, tail, skb, &fragstolen);
		seadp_rcv_nxt_update(sh, SEADP_SKB_CB(skb)->end_seq);
		
		if (!eaten)	__skb_queue_tail(&sk->sk_receive_queue, skb);
		else	kfree_skb_partial(skb, fragstolen);
	}
	
	
}
static void seadp_data_queue_ofo(struct sock *sk, struct sk_buff *skb)	//	乱序包入out_of_order_queue
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct rb_node **p, *parent;
	struct sk_buff *skb1;
	u32 seq, end_seq;
	bool fragstolen;
	
	if (unlikely(seadp_try_rmem_schedule(sk, skb, skb->truesize))) 	//out_of_order_queue和receive队列一同参与内存记账！！
	{
		//NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPOFODROP);
		sk_drops_add(sk, skb);
		__kfree_skb(skb);
		return;
	}
		
/*2020.1.26
certain to add to out_of_queue. Here we add a record of the number of packets in out_of_order_queue to help fast retransmission in  seadp_data_info_process
*/	
	sh->packets_num_in_ofo++;	
////////////////////////////////////////////////////////////////////
	seq = SEADP_SKB_CB(skb)->seq;
	end_seq = SEADP_SKB_CB(skb)->end_seq;

	p = &sh->out_of_order_queue.rb_node;
	if (RB_EMPTY_ROOT(&sh->out_of_order_queue))	//乱序队列为空，第一次插入Skb
	{
		rb_link_node(&skb->rbnode, NULL, p);
		rb_insert_color(&skb->rbnode, &sh->out_of_order_queue);
		sh->ooo_last_skb = skb;

		seadp_data_info_process(sk,skb, false);			//处理入列数据包信息，做RTT/RTO估计！！！必须再skb释放前%%%%%
		goto end;
	}

	
	/* In the typical case, we are adding an skb to the end of the list.
	 * Use of ooo_last_skb avoids the O(Log(N)) rbtree lookup.
	 */
	
	if (seadp_ooo_try_coalesce(sk, sh->ooo_last_skb, skb, &fragstolen))
	{
coalesce_done:
		//("ofo try coalesce\n");

		seadp_data_info_process(sk,skb, false);			//处理入列数据包信息，做RTT/RTO估计！！！必须再skb释放前%%%%%
		kfree_skb_partial(skb, fragstolen);
		skb = NULL;
		goto add_sack;
	}

	/* Can avoid an rbtree lookup if we are adding skb after ooo_last_skb */
	if (!before(seq, SEADP_SKB_CB(sh->ooo_last_skb)->end_seq)) //接收的skb序号在红黑数最大结束序号skb之后，直接添加在红黑树最最右叶子节点上
	{
		parent = &sh->ooo_last_skb->rbnode;
		p = &parent->rb_right;
		goto insert;
	}

	/* Find place to insert this segment. Handle overlaps on the way. 最后只能遍历红黑树寻找插入点（按序）*/
	parent = NULL;
	
	while (*p)
	{
		parent = *p;
		skb1 = rb_to_skb(parent);	//	container_of的变种
		if (before(seq, SEADP_SKB_CB(skb1)->seq)) 
		{
			p = &parent->rb_left;
			continue;		
		}
		if (before(seq, SEADP_SKB_CB(skb1)->end_seq)) 
		{
			if (!after(end_seq, SEADP_SKB_CB(skb1)->end_seq)) 
			{		
				/* All the bits are present. Drop. */
				sk_drops_add(sk, skb);
				__kfree_skb(skb);
				skb = NULL;
				////("1\n");
				goto add_sack;
			}
			if (after(seq, SEADP_SKB_CB(skb1)->seq))
			{
				/* Partial overlap. 部分重叠,插入的skb序号段在ofo中已有部分重叠 不会影响skb的插入，会在用户态接收时进行冗余判断*/
				//("partial overlap\n");							
			}
			else
			{
				/* skb's seq == skb1's seq and skb covers skb1.
				 * Replace skb1 with skb.
				 */
				rb_replace_node(&skb1->rbnode, &skb->rbnode, &sh->out_of_order_queue);
				sk_drops_add(sk, skb1);
				__kfree_skb(skb1);
				goto merge_right;
			}
		}
		else if (seadp_ooo_try_coalesce(sk, skb1, skb, &fragstolen)) 
		{
			goto coalesce_done;
		}
		p = &parent->rb_right;
	}

insert:
	/* Insert segment into RB tree. */
	rb_link_node(&skb->rbnode, parent, p);
	rb_insert_color(&skb->rbnode, &sh->out_of_order_queue);

merge_right:	//	当前选中的Skb向右合并处理！！
	/* Remove other segments covered by skb. */
	while ((skb1 = skb_rb_next(skb)) != NULL) 	//skb_rb_next是找到此按skb由小到达排列的红黑树中此skb下一个skb!!
	{
		if (!after(end_seq, SEADP_SKB_CB(skb1)->seq))	break;	//	符合条件，直接退出。合并后的skb end_seq不在后面一个skb1的seq之前
		if (before(end_seq, SEADP_SKB_CB(skb1)->end_seq)) 	//	合并后的skb end_seq在后面连续的skb1的seq之后，但在skb1的end_seq之前
		{
			//("merge_right: two skbs in ofo is overlap\n");	//插入的skb序号段在ofo中已有部分重叠 不会影响skb的插入，会在用户态接收时进行冗余判断
			break;
		}
		//插入的skb已经完完全全包含了后面连续的一个skb（skb1），直接从ofo擦除skb1，并释放skb1
		rb_erase(&skb1->rbnode, &sh->out_of_order_queue);
		
		sk_drops_add(sk, skb1);
		__kfree_skb(skb1);
	}
	/* If there is no skb after us, we are the last_skb ! */
	if (!skb1)	sh->ooo_last_skb = skb;

	seadp_data_info_process(sk,skb, false);			//处理入列数据包信息，做RTT/RTO估计！！！必须再skb释放在%%%%%
add_sack:

end:
	if (skb) 
	{
		//tcp_grow_window(sk, skb);
		skb_condense(skb);
		skb_set_owner_r(skb, sk);
	}
	
}

void send_immediate_ack(void)
{
	//("%s\n", __func__);
}




static int seadp_data_queue(struct sock *sk, struct sk_buff *skb) //将sk_backlog队列数据处理后放入sk_receive_queue队列！！
{
	struct seadp_sock *sh = seadp_sk(sk);
	bool fragstolen;
	int eaten;

	if (SEADP_SKB_CB(skb)->seq == SEADP_SKB_CB(skb)->end_seq) //不正常的包，丢弃
	{
		__kfree_skb(skb);
		return 1;
	}

	skb_dst_drop(skb);	//?
	__skb_pull(skb, sizeof(seanet_hdr));	//skb->data指针跳过传输层seanet首部


	if(!match_get_request_sk(sk,skb))
	{
		__kfree_skb(skb);
		return 1;
	}

	/*  Queue data for delivery to the user.
	 *  Packets in sequence go to the receive queue.
	 *  Out of sequence packets to the out_of_order_queue.
	 */

	//("SEADP_SKB_CB(skb)->seq:%d, sh->rcv_nxt:%d\n", SEADP_SKB_CB(skb)->seq, sh->rcv_nxt);
	if (SEADP_SKB_CB(skb)->seq == sh->rcv_nxt) 
	{
		//if (seadp_receive_window(sh) == 0)	goto out_of_window;
		
		/* Ok. In sequence. In window. */
queue_and_out:		

		if(skb_queue_len(&sk->sk_receive_queue) == 0)	sk_forced_mem_schedule(sk, skb->truesize);	
		else if(seadp_try_rmem_schedule(sk, skb, skb->truesize))	
		{
			printk("%s: no memory, ofo's packets num: %d, skb->truesize: %d\n", __func__, sh->packets_num_in_ofo, skb->truesize);
			
			goto drop;//内存记账,包过快过来会在这里卡住，因为说明机器来不及处理，防止内核堆积过多skb，迟迟得不到释放！！！！
		}
		///__skb_queue_tail(&sk->sk_receive_queue, skb);	//加入sk_receive_queue队列，不用skb_queue_tail,因为已经时临界区，不需要再加一层锁！！
		///skb_set_owner_r(skb, sk);	//将skb与sk关联，sk_rmem_alloc和sk_forawrd_alloc分别增加和减少skb->truesize大小！！这里设置了skb->destructor =sock_rfree！！！			
		eaten = seadp_queue_rcv(sk, skb, 0, &fragstolen);	//接收skb
		
		seadp_rcv_nxt_update(sh, SEADP_SKB_CB(skb)->end_seq);	

		
		////////seadp_data_info_process(sk,skb, true);			//处理入列数据包信息，做RTT/RTO估计！！！！！！！！！！！！！

		////("%s: sk->sk_forward_alloc: %d, sk->sk_rmem_alloc:%d\n",__func__, sk->sk_forward_alloc, atomic_read(&sk->sk_rmem_alloc));
		
		

		if (!RB_EMPTY_ROOT(&sh->out_of_order_queue))	//乱序队列不为空，处理乱序队列 
		{
			seadp_ofo_queue(sk);

			/* RFC2581. 4.2. SHOULD send immediate ACK, when
			 * gap in queue is filled.
			 */

			if (RB_EMPTY_ROOT(&sh->out_of_order_queue)) send_immediate_ack();
		}	
		
		seadp_data_info_process(sk,skb, true);			//处理入列数据包信息，做RTT/RTO估计！！！！！！！！！！！！！
		
		if (eaten > 0)
			kfree_skb_partial(skb, fragstolen);
		
		if (!sock_flag(sk, SOCK_DEAD))  //****重要！！
			sk->sk_data_ready(sk);
	
		return 0;
	}

	if(!after(SEADP_SKB_CB(skb)->end_seq, sh->rcv_nxt))
	{
out_of_window:	//重复包，丢弃
		printk("out of window!\n");

drop:
		printk("%s: drop!!\n", __func__);
		sk_drops_add(sk, skb);
		__kfree_skb(skb);
	
		return 1;
	}
	
	if (before(SEADP_SKB_CB(skb)->seq, sh->rcv_nxt))	//skb部分已经接收了,重复部分依旧会进入 
	{
		//("SEADP_SKB_CB(skb)->seq:%d, sh->rcv_nxt:%d\n", SEADP_SKB_CB(skb)->seq, sh->rcv_nxt);
		//("partial duplicate\n");
		goto queue_and_out;
	}

	seadp_data_queue_ofo(sk, skb);	//乱序包入out_of_order队列
	return 0;
}


static int seadp_feedback(struct sock *sk, const struct sk_buff *skb)	//接收路径上对数据请求报文的处理，继而转向发送路径发送相应的包，而对数据报文直接放行,只做一些控制判断
{
	struct seadp_sock *sh 	   = seadp_sk(sk);
	seanet_hdr        *sheader = (seanet_hdr *)skb_transport_header(skb);
	u8 packet_mark =  SEADP_SKB_CB(skb)->packet_mark;
	int acceptable = 0;
//请求报文只能是req置位，po指示从哪开始请求，chunk长度指示请求多少，这个chunk值的考量其实包含了拥塞和流控
//数据报文dat置位，po指示最后一个字节序，chunk长度可以用来捎带反向路径上的ACK序号（ACK标志置位）
//
	if(packet_mark &SEADP_DATA )	//数据报文
	{
		acceptable = 1;	//接收路径继续接收至相应用户进程
				
		//("data packet!!\n");

		return acceptable;
	}
		acceptable = 1;	//暂时先放行！！！！test


	if(packet_mark &SEADP_REQUEST)	//请求报文
	{
		//("request packet!!\n");
		//sh->snd_una = sheader->offset;
		//sh->snd_wnd = sheader->chunk_len;
	
	}

	if(sheader->ret)	//重传反馈

out:	

	return acceptable;
}
/*
//	successful!!!! old    
static void seadp_data_snd_check(struct sock *sk)
{
	struct seadp_sock *sh 	   = seadp_sk(sk);
	unsigned int prior_packets = sh->packets_out;

	if(sh->snd_nxt == 50000) return;
	sh->snd_nxt += 1000;

	seadp_mstamp_refresh(seadp_sk(sk));	//this is must!
	test_request_sk(sk,sh->snd_nxt,1000);

	sh->packets_out++;
	//("%s: packets_out: %d\n", __func__, sh->packets_out);
	if(!prior_packets)
	{
		seadp_set_xmit_timer(sk);
		
	}
}
*/


static bool seadp_should_defer(struct sock *sk, int quota, u32 aggregation_segs)//决定是否推迟发送，以获得更大的聚合度，减少控制帧的开销！！！！
{
	struct seadp_sock *sh 	   = seadp_sk(sk);
	struct request_sk *target;
	u32 age;
	if(sh->sead_ca_state >= SEADP_CA_Recovery)	//处于recovery阶段或者loss阶段，我们不延迟请求，为的是快速从异常状态下恢复置正常的open状态！！！
	{
		goto send_now;
	}

	if(((s32)jiffies) - sh->lsndtime > 0 ) //距离最近一次发送已经过去了一个时间滴答，这被认为已经经过了很长时间!!!
	{
		goto send_now;	
	}	

	if(quota >= aggregation_segs)	//cwnd空额超过了一次发送的最大请求聚合数，立即请求！！
	{
		goto send_now;
	}
	
	if(quota >= sh->snd_cwnd / 4)
	{
		goto send_now;
	}
	
	if(list_empty(&sh->lhead))	
	{
		return true;
	}

	target = list_first_entry(&sh->lhead, struct request_sk, list_node);
		
	age = seadp_stamp_us_delta(sh->seadp_mstamp, target->request_mstamp);
	
	//printk("%s: sh->seadp_mstamp: %llu, target->request_mstamp: %llu, age: %u, sh->srtt_us >> 4: %u\n", __func__, sh->seadp_mstamp, target->request_mstamp, age, (sh->srtt_us >> 4));
	if(age < (sh->srtt_us >> 4))	//发送行为是由接收到的数据驱动的！！！如果现在的时间戳与请求队列头时间戳相差很小很小，说明请求的数据已经快速到达了请求端，换言之，inflight包很小了，我们不应该再延迟请求，而应该立即发送来填补满管道
	{
		printk("111\n");
		goto send_now;
	}
//下面是推迟发送逻辑
	return true;


send_now:
	return false;
}


static u32 seadp_aggregation_segs(struct sock *sk)
{
	struct seadp_sock *sh 	   = seadp_sk(sk);
	u32 aggregation_segs = 0;
	if (sh->seadp_ca_ops->tso_segs_goal)
	{
		aggregation_segs = sh->seadp_ca_ops->tso_segs_goal(sk);
	}
	if(!aggregation_segs)
	{
		printk("%s: aggreggation_segs err\n", __func__);
		aggregation_segs = 2;
	}
	return aggregation_segs;
	
}

//newer than before 20202.2.13
static void seadp_data_snd_check(struct sock *sk)	//对比于tcp_write_xmit
{
	struct seadp_sock *sh 	   = seadp_sk(sk);
	unsigned int prior_packets = sh->packets_out;
	int cwnd_quota;
	static int times = 0;
	static int times2 = 0;
	static int serial_times = 0;
	static int func_times = 0;
	bool a = false;
	u32 aggregation_segs;
	int aggregation_num;
	int m = 0;	

	func_times++;
	seadp_mstamp_refresh(seadp_sk(sk));	//this is must!
	//311//printk("%s: before request: %X\n", __func__, seadp_clock_us());

	if(sh->rcv_nxt == SEADP_MSS)	printk("%s: begin receive: %X\n", __func__, seadp_clock_us());
	if(sh->rcv_nxt == DATA_SIZE)	printk("%s: complete us: %X\n", __func__, seadp_clock_us());


	aggregation_segs = seadp_aggregation_segs(sk);
	if(aggregation_segs > MAX_AGGREGATION_COUNT)
	{
		printk("%s: aggregation_segs: %u\n", aggregation_segs);
	}
	if(!aggregation_segs)
	{
		//printk("%s: aggreggation_segs err\n", __func__);
		return 0;
	}

	while(1)	//loop to request data!!
	{
		//printk("%s: sh->rcv_nxt: %d, sh->snd_nxt: %d, us: %X\n", __func__,  sh->rcv_nxt, sh->snd_nxt,seadp_clock_us());
		//if(sh->rcv_nxt == 1000)	printk("1000: %X\n", seadp_clock_us());
		/////if(sh->rcv_nxt == SEADP_MSS)	printk("%s: begin receive: %X\n", __func__, seadp_clock_us());
		/////if(sh->rcv_nxt == DATA_SIZE)	printk("%s: complete us: %X\n", __func__, seadp_clock_us());
		//if(sh->rcv_nxt >= DATA_SIZE)	printk("%s: complete us: %X\n", __func__, seadp_clock_us());
		if(sh->snd_nxt >= DATA_SIZE) 
		{
		/*
			printk("%s: ns time: %ld\n", __func__, ktime_get());	
			printk("%s: jiffies: %X\n", __func__, jiffies);	
			printk("%s: us: %X\n", __func__, seadp_clock_us());
			show_usec();		
		*/		
			///printk("times: %d, times2: %d, serial_times: %d, func_times: %d\n", times, times2, serial_times, func_times);
			//printk("%s: sh->rcv_nxt: %d, sh->snd_nxt: %d, us: %X\n", __func__,  sh->rcv_nxt, sh->snd_nxt,seadp_clock_us());
			//printk("%s: sh->rcv_nxt: %d, sh->snd_nxt: %d\n", __func__,  sh->rcv_nxt, sh->snd_nxt);
			////debian//printk("%s: arrive size, sh->rcv_nxt: %d, sh->snd_nxt: %d, us: %X\n", __func__, sh->rcv_nxt, sh->snd_nxt,seadp_clock_us());
			//printk("%s: arrive size, sh->rcv_nxt: %d, sh->snd_nxt: %d\n", __func__, sh->rcv_nxt, sh->snd_nxt);
			return;	
			
		}
		if (seadp_pacing_check(sk))
		{	
			///if(a) times++;
			///else times2++;
			//printk("%s: hrtimer is active, sh->rcv_nxt: %d, sh->snd_nxt: %d, us: %X\n", __func__,sh->rcv_nxt, sh->snd_nxt,seadp_clock_us());
			//printk("%s: pacing!\n", __func__);
			//m = 1;		
			break;		//check pacing function!!!!!
		}
		
		/////printk("send one\n");
		//if(a) serial_times++;
		///a = true;
		cwnd_quota =  seadp_cwnd_test(sh);

		if(!cwnd_quota)	
		{
			///printk("no cwnd: sh->snd_cwnd: %d, in_flight: %d, sk->sk_pacing_rate: %d\n", sh->snd_cwnd, seadp_packets_in_flight(sh), sk->sk_pacing_rate);
			//("%s: out of cwnd. inflight:%d, cwnd:%d\n",__func__, seadp_packets_in_flight(sh), sh->snd_cwnd);			
			break;		//inflights >= cwnd 
		}
		
		if (test_bit(SEADP_PACING_DEFERRED_BIT, &sh->pacing_flags))
			clear_bit(SEADP_PACING_DEFERRED_BIT, &sh->pacing_flags);

		aggregation_num = aggregation_segs+30;
#if DEFER_REQUEST
		if(seadp_should_defer(sk, cwnd_quota, aggregation_segs))
		{
			//printk("%s: defer request, cwnd_quota: %d\n", __func__, cwnd_quota);
			break;

		}		
		
		//aggregation_num = (cwnd_quota > MAX_AGGREGATION_COUNT)? MAX_AGGREGATION_COUNT:cwnd_quota;
#endif

#if FIX_AGGREGATION_COUNT
		//aggregation_num = AGGREGATION_COUNT;
		aggregation_num = AGGREGATION_COUNT;
#endif
		sh->send_times++;
		sh->quota += cwnd_quota;
		sh->all_pacing_rate_sum += (u64)sk->sk_pacing_rate;

		test_request_sk(sk, aggregation_num);
		//printk("%s: after request: %X\n", __func__, seadp_clock_us());
		//////////sh->packets_out++;
		//("%s: packets_out: %d, sh->snd_nxt:%d\n", __func__, sh->packets_out, sh->snd_nxt);

#if TIMEOUT_RETRANS_SET		
		///printk("1\n");
		if(!prior_packets)
		{
			///printk("start timers111\n");
			seadp_set_xmit_timer(sk);
		
		}
#endif	
	}

	////if(m && !sh->packets_out) printk("%s: pacing\n", __func__);
}

int seadp_v4_do_rcv(struct sock *sk, struct sk_buff *skb)	//关键的逻辑！！！seadp所有处理逻辑均在这里实现！！加入sk_receive_queue队列！！
{	
	struct seadp_sock *sh 	   = seadp_sk(sk);
	int acceptable;
	int queued = 0;
	bool exist;

	//("%s\n",__func__);
	////("skb->truesize:%d\n", skb->truesize);
	//show_skb(skb);
	//311//printk("%s: start: %X\n", __func__, seadp_clock_us());
	acceptable = seadp_feedback(sk, (const struct sk_buff*) skb);	//acceptable==1说明是数据报文，==0说明是控制报文

	if(!acceptable)
	{
		//("not data frame\n");
		goto process_and_out;
		
	}
	
	if(seadp_data_queue(sk,skb))	//	这是数据报文入接收队列，在这之前应该还有对反馈控制报文的解析！！exist == true表示数据报文入接收队列成功，没有被释放，可以继续后续处理逻辑
	{
		return 0;
	}
	queued = 1;

	//("sh->delivered: %d\n", sh->delivered);
/*
	printk("%s: ns time: %ld\n", __func__, ktime_get());	
	printk("%s: jiffies: %X\n", __func__, jiffies);	
	printk("%s: us: %X\n", __func__, seadp_clock_us());
	show_usec();
*/
	//311//printk("%s: to data_snd: %X\n", __func__, seadp_clock_us());
process_and_out:	
	seadp_data_snd_check(sk);	//接收到数据包请求，发送数据（转向发送路径）
	//seadp_request_snd_check(sk);	//接收完数据包（请求反馈或者数据包）之后必要的发送


	if(!queued)
	{

		sk_drops_add(sk, skb);
		__kfree_skb(skb);
	}
	//("%s: end receive path\n", __func__);
	return 0;
}

bool seadp_add_backlog(struct sock *sk, struct sk_buff *skb)	//加入sk_backlog队列
{
	int err;
	u32 limit = sk->sk_rcvbuf + sk->sk_sndbuf;
	limit += 64*1024;
	skb_condense(skb);

	//("%s\n", __func__);
	////("%s: limit:%d, sk->sk_rmem_alloc:%d\n",__func__, limit,atomic_read(&sk->sk_rmem_alloc));
	if (unlikely(err=sk_add_backlog(sk, skb, limit))) 
	{
		
		//("err:%d\n",err);
		bh_unlock_sock(sk);
		__NET_INC_STATS(sock_net(sk), LINUX_MIB_TCPBACKLOGDROP);
		return true;
	}
	return false;
}
//static unsigned int times=0 ;

static void seadp_v4_fill_cb(struct sk_buff* skb, seanet_hdr* sh)
{
	SEADP_SKB_CB(skb)->offset 	= 0;	//读取偏移先归零！！
	SEADP_SKB_CB(skb)->end_seq	= ntohl(sh->offset);
	SEADP_SKB_CB(skb)->seq		= SEADP_SKB_CB(skb)->end_seq - skb->len + sizeof(seanet_hdr);
	SEADP_SKB_CB(skb)->pn		= ntohs(sh->seq);
	SEADP_SKB_CB(skb)->packet_mark	= seadp_packet_mark_byte(sh);
	SEADP_SKB_CB(skb)->target	= NULL;
}

int seadp_rcv(struct sk_buff *skb)  //软中断接收函数，返回0代表成功
{
#if DEBUG_T 
	int ret;
	int *cpu_num;
	struct sock *sk;	
	seanet_hdr *sh = (seanet_hdr*)skb_transport_header(skb); // seanet首部，包括44字节EID和seadp首部

	if (skb->pkt_type != PACKET_HOST)
		goto discard_it;

	if (!pskb_may_pull(skb, sizeof(seanet_hdr)))
		goto discard_it;
	
	if (unlikely(sh->header_len < sizeof(seanet_hdr) / 4))      //检查首部长度是否合法
	{
		//printk("skb's data len: %d, len: %d\n", skb->data_len, skb->len);
		goto bad_packet;
	}
	if (!pskb_may_pull(skb, sh->header_len ))
		goto discard_it;

	if(seadp_check_csum()) goto csum_error;   //检验seanet校验和  可以在软中断上下文检验吗
	
lookup:	
	////("dst_port:%X\n",sh->dst_port);
	////("daddr:%X\n", ip_hdr(skb)->daddr);
	
	//printk("receive time: %X\n", seadp_clock_us());
	//printk("receive time: %X\n",  seadp_clock_us());
	sk = __seadp4_lib_lookup_skb(skb, sh->src_port, sh->dst_port, &seadptable);
	
	if(!sk)	goto no_seadp_socket;
/*
	cpu_num = this_cpu_ptr(&cpu_number);
	printk("%s: cpu number: %d\n", __func__, *cpu_num);
*/
	if(seadp_sk(sk)->do_rcv_count == 0)	printk("%s: start receive: %X\n", __func__, seadp_clock_us());

	seadp_sk(sk)->do_rcv_count++;

	if(seadp_sk(sk)->do_rcv_count == 10000)	printk("%s: end receive: %X\n", __func__, seadp_clock_us());

	//SEADP_SKB_CB(skb)->offset = 0;	//读取偏移先归零！！
process:
	
	//times++;
	//if(times%100==0) //("times:%d\n",times);

	seadp_v4_fill_cb(skb, sh);	//填充skb的cb块！

	bh_lock_sock_nested(sk);

	ret = 0;
	if (!sock_owned_by_user(sk)) {
		ret = seadp_v4_do_rcv(sk, skb);	//处理后，排入sk_receive_queue
	} else if (seadp_add_backlog(sk, skb)) {
		goto discard_and_relse;
	}
	bh_unlock_sock(sk);
	
	
	return 0;

no_seadp_socket:
	icmp_send(skb, ICMP_DEST_UNREACH, ICMP_PORT_UNREACH, 0);
	//("no seadp socket!\n");
	goto discard_it;

csum_error:
	//("This packet's checksum is error!\n");
	goto discard_it;

bad_packet:
	//printk("This is a bad packet!\n");

discard_it:
	//printk("%s: Discard this packet\n", __func__);
	kfree_skb(skb);
	return 0;

discard_and_relse:
	//("1\n");
	sk_drops_add(sk, skb);
	
	goto discard_it;

#else 	//测试
	
	show_skb(skb);
	skb_condense(skb);
	show_skb(skb);
	kfree_skb(skb);   // must!
	packet_count++;
	//("received %d seanet packets\n", packet_count);
	
#endif
	return 0;
}


void seadp_err(struct sk_buff *icmp_skb, u32 info)
{

}
static struct net_protocol seadp_protocol = 
{
	.early_demux = seadp_early_demux,
	.early_demux_handler = seadp_early_demux,
	.handler = seadp_rcv,
	.err_handler = seadp_err,
	.no_policy = 1,
	.netns_ok = 1,
}; 
/**************注册传输层协议（对下层）*********/

/**************注册套接字（对上层）*************/

extern const struct proto_ops inet_dgram_ops;


void seadp_destruct_sock(struct sock *sk)
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct sk_buff *skb = sk->sk_backlog.head;
	struct request_sk *ptr, *ptr1;
	
	if (sock_flag(sk, SOCK_RCU_FREE)) //("SOCK_RCU_FREE\n");
/************在这里，释放backlog队列中的skb!!!!!***************/
	
	while(skb != NULL)
	{
		kfree_skb(skb);
		skb = skb->next;
	}
		
	if(!sh->request_skb) kfree_skb(sh->request_skb);
	skb_rbtree_purge_by_us(&sh->out_of_order_queue);	//清理乱序队列！！！由于内核没导出skb_rbtree_purge，因此自己定义一个功能完全一样的别名函数

	list_for_each_entry_safe(ptr,ptr1,&sh->lhead,list_node)	//清理request_sk队列
	{
		//("%s: free one request_sk\n", __func__);
		kfree(ptr);
	}
	kfree(sh->request_hash_array);
	
	inet_sock_destruct(sk);
	//("%s\n",__func__);

}



static inline void seadp_lib_close(struct sock *sk, long timeout)
{
	//sk_common_release(sk);
	struct seadp_sock *sh = seadp_sk(sk);
	
	lock_sock(sk);	//锁住 软中断不再访问receive队列！！
	sh->sock_will_close = 1;
	__skb_queue_purge(&sk->sk_receive_queue);	//先清理一波receive队列
	
	//("%s:1\n",__func__);

	

	printk("sh->send_times: %u, sh->quota: %u, all pacing rate: %llu\n", sh->send_times, sh->quota, sh->all_pacing_rate_sum);

	if (seadp_pacing_check(sk)) printk("%s: hrtimer is active\n", __func__);
	if (sk->sk_prot->destroy)	sk->sk_prot->destroy(sk);

	//("%s:2\n",__func__);
	sk->sk_prot->unhash(sk);	//sk从全局哈希表中去除

	
	sock_orphan(sk);

	xfrm_sk_free_policy(sk);

	sk_refcnt_debug_release(sk);

	release_sock(sk);

	sock_put(sk);
}

//Enter Loss state.进入丢包状态，进行一些处理！！！ very important!!!!
void seadp_enter_loss(struct sock *sk)
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct net *net = sock_net(sk);


	
	sh->prior_cwnd = sh->snd_cwnd;
	sh->snd_ssthresh = sh->seadp_ca_ops->ssthresh(sk);	//！！

	if (sh->seadp_ca_ops->cwnd_event)
		sh->seadp_ca_ops->cwnd_event(sk, CA_EVENT_LOSS);

	sh->snd_cwnd	   = CWND_ENTER_LOSS;		//!!!!!但拥塞窗口还是BBR来负责计算设置！！
	//tp->snd_cwnd_cnt   = 0;
	//tp->snd_cwnd_stamp = tcp_jiffies32;


//我们这里并未把retrans_out归0，意味着快速重传逻辑中的逻辑可以延续到了超时重传逻辑中，在超时重传逻辑中我们再次只重传请求队列最开始的请求，而后续的依旧按seadp_xmit_retransmit_queue
//我们把lost_out归零，并重新遍历请求队列来标记lost标志，目的是为了希望针对丢包来标记更多的请求，以至于后续seadp_xmit_retransmit_queue可以适时重传他们。
	//sh->retrans_out = 0;
	sh->lost_out = 0;
	
	seadp_set_ca_state(sk, SEADP_CA_Loss);		//拥塞状态转为loss
	
	sh->recovery_seq = sh->snd_nxt;
}


/**
 *  seadp_retransmit_timer() - The TCP retransmit timeout handler
 *  @sk:  Pointer to the current socket.
 *
 *  This function gets called when the kernel timer for a TCP packet
 *  of this socket expires.
 *
 *  It handles retransmission, timer adjustment and other necesarry measures.
 *
 *  Returns: Nothing (void)
 */
void seadp_retransmit_timer(struct sock *sk)
{
	int err;
	struct seadp_sock *sh = seadp_sk(sk);
	struct net *net = sock_net(sk);
	struct request_sk *target;	
	u32 retrans_num = 0;
	u32 seqq;
	u32 prior_lostout = sh->lost_out;	//记录下定时器超时前 被快速重传标记的Lost的个数,在定时器超时函数中，我们至少去重新标记这么多请求块为lost，而且我们对于
	u64 rto_in_usecs = jiffies_to_usecs(sh->spsk_rto);
	u32 rtt = (sh->srtt_us >> 3);				//!!!!!!!!!!!!!!!!!!!!
	struct seanet_head_info head_info;
	struct request_sk p;
	u8 flags;
	u32 lost_num = 0;
	u32 mss_counts = 0;
	
	//4.13bool all_success = true;
	printk("33333333333333333333333333333\n");
#if TIMEOUT_RETRANS_SET
	if (!sh->packets_out)	//sh->packets_out表示已请求发送但未收到的包数目
		goto out;

	if(list_empty(&sh->lhead))	
	{
		return ;
	}

	target = list_first_entry(&sh->lhead, struct request_sk, list_node);	

	if((u32)jiffies - sh->rcv_tstamp > SEADP_RTO_MAX)	//the interval of two successive-requested data 超过最大时间SEADP_RTO_MAX，出错！
	{
		//tcp_write_err(sk);	//tcp_write_err() - close socket and save error info
		printk("%s: timeout exceeds SEADP_RTO_MAX\n", __func__);
		goto out;
	}
	//临界的处理！！
	//retrans//printk("44444444444444444444444444444\n");
	//printk("%s: queue's start seq: %d, queue's end seq: %d, rb_first's skb seq: %d, sh->retrans_out: %d\n", __func__, target->seq, list_last_entry(&sh->lhead, struct request_sk, list_node)->seq,	SEADP_SKB_CB(rb_to_skb(rb_first(&sh->out_of_order_queue)))->seq, sh->retrans_out);
	if(target->seq != sh->start_seq)	//每当定时器重置reset后，sh->start_seq都等于的snd_una(=rcv_nxt)，其代表着此时定时器直接负责snd_una代表的序号字节！！！如果request_sk队首不是这个字节说明临界下其实包已经到了。但定时器超时函数还是自旋开始运行了
	{
		printk("%s: over! sh->start_seq: %d\n", __func__, sh->start_seq);
		seadp_reset_xmit_timer(sk, SPSK_TIME_RETRANS, min(sh->spsk_rto, SEADP_RESOURCE_PROBE_INTERVAL), SEADP_RTO_MAX);
		goto out;
		
	}
	//if (tcp_write_timeout(sk))		//ddddddddddddddddddddd
	//	goto out;
	
	seadp_enter_loss(sk);	//一些超时状态处理!!!进入SEADP_CA_Loss状态！！！！退出loss状态而转入open状态的时机：按序接受的字节seq已经超过是sh->recovery_seq

	//printk("%s: ooo_last_skb's seq: %d, len: %d\n", __func__, SEADP_SKB_CB(sh->ooo_last_skb)->seq, (sh->ooo_last_skb)->len);

	sh->has_mark_lost = true;	//不管是否之前已经进入了快速重传状态，我们都置位has_mark_lost，也就是说loss状态下不会再进入快速重传逻辑了，直到重新恢复至open状态
	seqq	= target -> seq;	//seqq先赋值为request_sk队列队首请求块的seq
	head_info.seq = target->seq;
	head_info.len = SEADP_MSS;

	printk("44444444444444444444444444444\n");
	list_for_each_entry(target, &sh->lhead, list_node)//这里还是遍历request_sk请求队列，标记lost并重传
	{
		//只有先标记了lost，才能去标记retrans，并组织重传	
		//激进的重传
		////printk("4.33333333333333333333333\n");
		if((retrans_num != 0) && ( (sh->lost_out > prior_lostout) && (sh->seadp_mstamp - target->request_mstamp <= rtt)   )) 
		{
			printk("%s: end mark lost seq: %d\n", __func__, target->seq);
			break;
		}		
		flags = target->requested;	
		if(!(flags & SEADP_LOST) || ((flags & SEADP_LOST) && (flags & SEADP_RETRANS)))
		{
			sh->lost += seadp_request_pcount(target);	//记录全局丢包数：未被标记lost的包，以及标记lost并标记retrans进行重传过的包，可以视作丢包了
		}
		////printk("4.44444444444444444\n");
		
		target->requested |= SEADP_LOST;	//不管是否被标记了lost，都再标记lost，然后重传！！！！
		sh->lost_out += seadp_request_pcount(target);
		
		lost_num++;		

		if(seqq == target->seq && mss_counts < MAX_RETRANS_NUM)	//保证了至少第一个request_sk会被标记LOST和RETRANS！！！！
		{
			////printk("4.55555555555555555\n");
			//target->requested |= SEADP_RETRANS;	//seadp_enter_loss里面将sh->retrans_out和sh->losts_out清零了！！！！！！不管是不是已经被标记了重传，都再次标记并组织重传！！
			//seadp_rate_request_sent(sk,  target);	//记录参数！！
			//sh->retrans_out += seadp_request_pcount(target);	//record
			mss_counts += seadp_request_pcount(target);	//record
			seqq += target->len;	//retrans标记只能连续按序标记！！！
			retrans_num++;
	
		}

	}

	//printk("%s: last marked seq: %ld\n", __func__, target->seq);

	
	head_info.len = mss_counts * SEADP_MSS;
	
	p.seq = head_info.seq;
	p.len = head_info.len;

	err = __seadp_send_ack(sk, SEADPHDR_DATA_REQUEST,&head_info, &p);

	////printk("55555555555555555555555555\n");
	if(likely(err == 0))	//发送成功！！！
	{
		printk("%s: retrans succeed! start seq: %d, len: %d, rcv_nxt: %d\n", __func__, p.seq, p.len, sh->rcv_nxt);
		
		//发送成功设置下标志位
		list_for_each_entry(target, &sh->lhead, list_node)
		{
		
			if(retrans_num == 0) break;			
			if(   !(target->requested & SEADP_RETRANS ))	//并未标记重传，那么我们来标记！！
			{
				target->requested |= SEADP_RETRANS;	//seadp_enter_loss里面将sh->retrans_out和sh->losts_out清零了！！！！！！不管是不是已经被标记了重传，都再次标记并组织重传！！
				sh->retrans_out += seadp_request_pcount(target);	//record
			}
			///target->requested |= SEADP_RETRANS;	//seadp_enter_loss里面将sh->retrans_out和sh->losts_out清零了！！！！！！不管是不是已经被标记了重传，都再次标记并组织重传！！
			seadp_rate_request_sent(sk,  target);	//记录参数！！
			retrans_num--;
			//target->requested &= ~SEADP_RETRANS;	//mark this request_sk is retransmitted !!!!(fast retrans or RTO time out retrans!!)
			////sh->retrans_out += seadp_request_pcount(target);	//record
		}
		//sh->retrans_out += mss_counts;	//record

		printk("%s: lost_num: %d, sh->lost_out: %d, sh->retrans_out: %d, sh->packets_out: %d\n", __func__, lost_num, sh->lost_out,  sh->retrans_out, sh->packets_out);
	}
	else	//发送出错
	{
		printk("%s: __seadp_send_ack err\n", __func__);
		if(!sh->spsk_retransmits)	sh->spsk_retransmits = 1;

		seadp_reset_xmit_timer(sk, SPSK_TIME_RETRANS, min(sh->spsk_rto, SEADP_RESOURCE_PROBE_INTERVAL), SEADP_RTO_MAX);
		goto out;

	}

	//__sk_dst_reset(sk);


	//("Number of retransmitted request_sk this time: %d\n", retrans_num);
	
/* 4.13	
	if(!all_success)//重传请求失败,不进行二进制退避
	{
		if(!sh->spsk_retransmits)	sh->spsk_retransmits = 1;

		seadp_reset_xmit_timer(sk, SPSK_TIME_RETRANS, min(sh->spsk_rto, SEADP_RESOURCE_PROBE_INTERVAL), SEADP_RTO_MAX);
		goto out;
	}
4.13 */	

	
	
	//sh->spsk_rto = min(__seadp_set_rto(sh), SEADP_RTO_MAX);
	if(!sh->spsk_retransmits)	//如果当前是0，之前没有重传，那么我们不二进制退避，继续重传
	{
		sh->spsk_rto = min(__seadp_set_rto(sh), SEADP_RTO_MAX);
	}
	else	//不为0,开始退避！！！
	{
		sh->spsk_rto = min(sh->spsk_rto << 1, SEADP_RTO_MAX);		//exponential backoff
	}

	sh->spsk_backoff++;
	sh->spsk_retransmits++;		//增加一次重传次数，如果接收到了一次保序数据，那么会将重传次数spsk_retransmits置0的！！！！如果不置0,那么下次进入重传定时器时会执行二进制退避！！！！！

	printk("%s: set retrans timer, sh->spsk_retransmits: %d, sh->spsk_backoff: %d, sh->spsk_rto (us): %lu\n", __func__, sh->spsk_retransmits, sh->spsk_backoff, sh->spsk_rto);
	seadp_reset_xmit_timer(sk, SPSK_TIME_RETRANS, sh->spsk_rto, SEADP_RTO_MAX);	//重置超时重传定时器

	
	//if (retransmits_timed_out(sk, net->ipv4.sysctl_tcp_retries1 + 1, 0))		//ddddddddddddddddddddd
	//	__sk_dst_reset(sk);

#endif

out:;
}




/* Called with bottom-half processing disabled.
   Called by seadp_write_timer() */
void seadp_write_timer_handler(struct sock *sk)
{
	struct seadp_sock *sh = seadp_sk(sk);
	int event;
	
	//retrans//printk("123333333333333333333\n");
	if (!sh->spsk_pending)
		goto out;
	
	
	if (time_after(sh->spsk_timeout, jiffies)) 
	{	//还未超时......
		mod_timer(&sh->seadp_retransmit_timer,  sh->spsk_timeout); 	//修正偏移的定时器？
		goto out;
	}
	//超时处理.....
	seadp_mstamp_refresh(seadp_sk(sk));	//更新seadp_mstamp，在seadp_sock上记录最新发送或者接收包的时间！！
	event = sh->spsk_pending;	
	//retrans//printk("2222222222222222222222\n");
	switch(event)
	{
		case SPSK_TIME_RETRANS:
			sh->spsk_pending = 0;
			seadp_retransmit_timer(sk);
			break; 
	}

out:
	sk_mem_reclaim(sk);
}


static void seadp_write_timer(struct timer_list * timer)	//发送端超时重传函数，这里在接收端做
{
	struct sock *sk = (struct sock*)container_of(timer,struct seadp_sock,  seadp_retransmit_timer);
	struct seadp_sock *sh = seadp_sk(sk);
	
	//static unsigned int times = 0; 	
		
	//times++;
	//("%s: %d\n",__func__, times);
	
	bh_lock_sock(sk);
	if(sh->sock_will_close) return;		//非常关键，用户太调用close之后，我们不应该再进入超时重传逻辑去重启定时器，否则再下一次定时到来之前，RCU会经过一次宽限期，从而释放掉sock，从而造成下一次定时器段错误

	if (!sock_owned_by_user(sk)) 
	{
		//("%s: proceess now\n", __func__);
		seadp_write_timer_handler(sk);
	} 
	else 
	{
		/* delegate our work to seadp_release_cb() */
		//if (!test_and_set_bit(SEADP_WRITE_TIMER_DEFERRED, &sk->sk_tsq_flags))
		//printk("%s: proceess delay\n", __func__);
		test_and_set_bit(SEADP_WRITE_TIMER_DEFERRED_BIT, &sh->pacing_flags);	
		//sock_hold(sk);
	}
	bh_unlock_sock(sk);
	//sock_put(sk);

}

static void seadp_delfeedback_timer_handler(struct timer_list * timer)
{
	//struct sock *sk = (struct sock *)data;

	//bh_lock_sock(sk);
	//if (!sock_owned_by_user(sk)) {
	//	tcp_delack_timer_handler(sk);
	//} else {
	//	inet_csk(sk)->icsk_ack.blocked = 1;
	//	__NET_INC_STATS(sock_net(sk), LINUX_MIB_DELAYEDACKLOCKED);
		/* deleguate our work to tcp_release_cb() */
	//	if (!test_and_set_bit(TCP_DELACK_TIMER_DEFERRED, &sk->sk_tsq_flags))
	//		sock_hold(sk);
	//}
	//bh_unlock_sock(sk);
	//sock_put(sk);
}

static void seadp_v4_destroy_sock(struct sock *sk)
{
	struct seadp_sock *sh = seadp_sk(sk);
	int err;
	//清理定时器  定时器也相当于一种软中断，可以附着于任意进程上下文，但自己没有current指针，定时器函数中不能睡眠调度！！！
	//sk_stop_timer(sk, &sh->seadp_retransmit_timer);
	//sk_stop_timer(sk, &sh->seadp_delfeedback_timer);
	err = del_timer(&sh->seadp_retransmit_timer);
	del_timer(&sh->seadp_delfeedback_timer);

	printk("%s: err of del_timer: %d\n", __func__, err);
	//("%s:1\n",__func__);
	//("%s:sh->request_count:%d\n", __func__, sh->request_count);
	hrtimer_cancel(&seadp_sk(sk)->pacing_timer);

	//if(sh->pacing_node.next != &sh->pacing_node)
		//list_del_init(&sh->pacing_node);

	//("%s:1.5\n",__func__);
//cleanup pacing-related stuffs!!!!!
	/////while(hrtimer_active(&seadp_sk(sk)->pacing_timer));	//这里不持有bh_sk锁，我们等待hrtimer不再有效！！！
	//("%s:1.6\n",__func__);
	/////while( (sh->pacing_flags & SEADP_PACING_QUEUED) );	//这里不持有bh_sk锁，我们等待sk被tasklet从tasklet_queue中删除，并将PACING_QUEUED置0，这也代表着tasklet已经开始执行了
		
	//("%s:2\n",__func__);
	seadp_cleanup_congestion_control(sk);	// 释放对拥塞控制块的引用
}
/*
enum hrtimer_restart seadp_pace_kick(struct hrtimer *timer)
{
	struct seadp_sock *sh = container_of(timer, struct seadp_sock, pacing_timer);
	struct sock *sk = (struct sock *)sh;
	struct pacing_tasklet *pac;
	unsigned long nval, oval, flags;
	bool empty;

	//////printk("%s\n", __func__);
	oval = READ_ONCE(sh->pacing_flags);

	if(!test_and_set_bit(SEADP_PACING_QUEUED_BIT, &sh->pacing_flags))
	{
		//("%s: not queued, queue now\n", __func__);
		////local_irq_save(flags);
		pac = this_cpu_ptr(&pacing_tasklet);
		empty = list_empty(&pac->head);
		list_add(&sh->pacing_node, &pac->head);		//这里操作pac->head链表不会与hrtimer软中断函数中list_add所冲突，因为，tasklet与hrtimer为不同类型软中断是不会互相抢占一个核的，而并列运行与不同核上所操作的数据又分别是per-cpu的，即不同区域的数据，故而不会有竞争冲突，所以这里是lock-free的操作！！！！！！！！！

		if (empty)	
		{
			/////printk("%s: schedule tasklet\n", __func__);	
			tasklet_schedule(&pac->tasklet);	//这里首先判断下当前CPU的tasklet队列是否为空，空时才调用此CPU的tasklet去做pacing的任务。目的在于，如果队列不为空，那么肯定有别的套接字的hrtimer软中断调度于当前CPU之上，将对应sk置于tasklet队列并执行tasklet_schedule唤醒了当前CPU对应的tasklet，而tasklet还未来得及调度于此CPU上（在哪个CPU首先调度唤醒的tasklet，则此tasklet会被调度到此CPU上来执行，目的是为了增加运行时cpu cache的命中率！），故而此时我们不必再次去用tasklet_schedule去唤醒调度tasklet了，虽然tasklet的特性是，未被执行前多次调度，也只会执行一次而已，但至少能减少调用次数！！！
		}
		////local_irq_restore(flags);
	}
	return HRTIMER_NORESTART;
}
*/

enum hrtimer_restart seadp_pace_kick(struct hrtimer *timer)
{
	struct seadp_sock *sh = container_of(timer, struct seadp_sock, pacing_timer);
	struct sock *sk = (struct sock *)sh;
	struct pacing_tasklet *pac;
	

	unsigned long nval, oval, flags;
	bool empty;

	//s64 now;
	//printk("%s\n", __func__);
	//now = ktime_get();
	//printk("%s: us: %X, ns time: %llu, delta: %d\n", __func__, seadp_clock_us(), now, now - sh->trigger_time);
	////printk("%s: us: %X,  delta: %lld\n", __func__, seadp_clock_us(),  now - sh->trigger_time);
	//printk("%s start: us: %X\n", __func__, seadp_clock_us());
	oval = READ_ONCE(sh->pacing_flags);
	
	if (oval & SEADP_PACING_QUEUED)	
	{
		//printk("%s: queued\n", __func__);
		return HRTIMER_NORESTART;
	}	
	nval = oval | SEADP_PACING_DEFERRED | SEADP_PACING_QUEUED;
	//printk("sk_tsq_flags: %d, oval: %d, nval: %d\n", sk->sk_tsq_flags, oval, nval);
	nval = cmpxchg(&sh->pacing_flags, oval, nval);
	//printk("sk_tsq_flags: %d, oval: %d, nval: %d\n", sk->sk_tsq_flags, oval, nval);
	//if(test_bit(SEADP_PACING_DEFERRED_BIT, &sk->sk_tsq_flags)) printk("%s: pacing deferred\n", __func__);
	pac = this_cpu_ptr(&pacing_tasklet);



	empty = list_empty(&pac->head);
	list_add(&sh->pacing_node, &pac->head);

	sock_hold(sk);	//8.8!!!!	

	if (empty)	
	{
		//printk("%s: schedule tasklet, cpu num: %d\n", __func__, pac->num);	
		tasklet_schedule(&pac->tasklet);
	}
	//311//printk("%s\n", __func__);
	//printk("%s end: us: %X\n", __func__, seadp_clock_us());
/*	
	if(!sh->packets_out) 
	{
		printk("%s: return from hrtimer\n", __func__);
	}	
*/
	return HRTIMER_NORESTART;
}


void seadp_init_xmit_timers(struct sock *sk)
{
	struct seadp_sock *sh = seadp_sk(sk);

	//inet_csk_init_xmit_timers(sk, &tcp_write_timer, &tcp_delack_timer, &tcp_keepalive_timer);

	timer_setup(&sh->seadp_retransmit_timer, &seadp_write_timer, 0);	//版本依赖严重！！
	
	
	timer_setup(&sh->seadp_delfeedback_timer, &seadp_delfeedback_timer_handler, 0); //版本依赖严重！！
	
	sh->spsk_pending = 0;
	
	hrtimer_init(&seadp_sk(sk)->pacing_timer, CLOCK_MONOTONIC, HRTIMER_MODE_ABS_PINNED);
	seadp_sk(sk)->pacing_timer.function = seadp_pace_kick;
}


void seadp_release_cb(struct sock *sk)
{
	struct seadp_sock *sh = seadp_sk(sk);
	unsigned long flags, nflags;

	/* perform an atomic operation only if at least one flag is set */
	//("%s: sh->pacing_flags: %d\n",__func__, sh->pacing_flags);
	do {
		flags = sh->pacing_flags;
		if (!(flags & SEADP_DEFERRED_ALL))
			return;
		////nflags = flags & (~SEADP_DEFERRED_ALL);
		nflags = flags & (~SEADP_WRITE_TIMER_DEFERRED);
			
		//("%s: flags:%d, nflags: %d, SEADP_DEFERRED_ALL: %d, ~SEADP_DEFERRED_ALL:%d\n", __func__, flags, nflags, SEADP_DEFERRED_ALL,~SEADP_DEFERRED_ALL);
	} while (cmpxchg(&sh->pacing_flags, flags, nflags) != flags);	//clear all DEFERRED mask!!!!!
	
	//("%s: sh->pacing_flags: %d\n",__func__, sh->pacing_flags);
	sock_release_ownership(sk);

	if (flags & SEADP_PACING_DEFERRED)
	{
		//printk("%s: SEADP_PACING_DEFERRED\n", __func__);	
		seadp_pacing_handler(sk);
	}

	/* Here begins the tricky part :
	 * We are called from release_sock() with :
	 * 1) BH disabled
	 * 2) sk_lock.slock spinlock held
	 * 3) socket owned by us (sk->sk_lock.owned == 1)
	 *
	 * But following code is meant to be called from BH handlers,
	 * so we should keep BH disabled, but early release socket ownership
	 */
	//sock_release_ownership(sk);	//?????seems do not make sense, because still has spin_lock_bh(&sk->sk_lock.slock);


	if (flags & SEADP_WRITE_TIMER_DEFERRED) 
	{
		//printk("%s:SEADP_WRITE_TIMER_DEFERRED\n", __func__);
		seadp_write_timer_handler(sk);
		
	}


}

int seadp_init_sock(struct sock *sk)
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct sk_buff *skb_ptr;
	u64 len_ns;
	//("sk->sk_rmem_alloc:%d\n",atomic_read(&sk->sk_rmem_alloc));
	//("sk->sk_rcvbuf:%d\n", sk->sk_rcvbuf);
	

	//4.19.97内核没这个函数了？//if (sk_check_csum_caps(sk))	printk("NIC supports calculate L4 checksum\n");
	

	sh->packets_num_in_ofo = 0;
	sh->bound = 0;
	sh->out_of_order_queue = RB_ROOT;

	sh->request_hash_array = (struct hlist_head* )kmalloc_array(REQUEST_HASH_LEN,sizeof(struct hlist_head), GFP_KERNEL  |__GFP_ZERO);//__GFP_ZERO初始化
	
	INIT_LIST_HEAD(&sh->lhead);	
	INIT_LIST_HEAD(&sh->pacing_node);
	//sh->head = NULL;
	//sh->tail = NULL;	
	seadp_init_xmit_timers(sk);	//初始化定时器

	sh->spsk_rto = SEADP_TIMEOUT_INIT;
	sh->mdev_us = jiffies_to_usecs(SEADP_TIMEOUT_INIT);
	minmax_reset(&sh->rtt_min, (u32)jiffies, ~0U);

	sh->snd_cwnd = SEADP_INIT_CWND;
	sh->snd_cwnd_clamp = ~0;
	//sh->app_limited = ~0U;
	sh->app_limited = 0;	//这里我们关闭app_limited功能
	
	seadp_assign_congestion_control_default(sk, &seadp_bbr_cong_ops);
//initialize congestion metrics
	
	sh->prior_ssthresh = 0;
	if (sh->seadp_ca_ops->init)
		sh->seadp_ca_ops->init(sk);
	
	
	seadp_set_ca_state(sk,SEADP_CA_Open);	//initialize congestion state!!!!
	sk->sk_destruct = seadp_destruct_sock;
	
	//sk->sk_sndbuf = sysctl_tcp_wmem[1];	//可以再做一次初始化
	//sk->sk_rcvbuf = sysctl_tcp_rmem[1];	//可以再做一次初始化

	sk->sk_rcvbuf = 48000000;
	
	sock_set_flag(sk, SOCK_RCU_FREE);


	skb_ptr = alloc_skb(MAX_SEADP_HEADER, sk_gfp_mask(sk, GFP_ATOMIC | __GFP_NOWARN ));
	if(!skb_ptr)
	{
		printk("%s: alloc request skb err\n", __func__);
		return;	
	}
	
	skb_reserve(skb_ptr, MAX_SEADP_HEADER);

	sk->sk_no_check_tx = 1;
	//skb_ptr->truesize = 2;
	SEADP_SKB_CB(skb_ptr)->seadp_flags = SEADPHDR_DATA_REQUEST;

	sh->request_skb = skb_ptr;
	
#if FIX_CWND_AND_PACING
	sk->sk_pacing_rate = TEST_PACING_RATE; //test
	sh->snd_cwnd = CWND; // test
#endif

	len_ns = (SEADP_MSS + sizeof(seanet_hdr) + sizeof(struct iphdr)) * NSEC_PER_SEC;
	do_div(len_ns, sk->sk_pacing_rate);
	printk("HZ: %d, SEADP_RTO_MIN: %d, SEADP_TIMEOUT_INIT: %d\n", HZ, SEADP_RTO_MIN, SEADP_TIMEOUT_INIT);
	printk("MTU: %d, sk->sk_pacing_rate: %ld, sh->snd_cwnd: %d, len_ns: %ld\n", seadp_mss_to_mtu_v4(sk), sk->sk_pacing_rate, sh->snd_cwnd, len_ns);

	printk("sk->sk_rmem_alloc:%d\n",atomic_read(&sk->sk_rmem_alloc));
	printk("sk->sk_rcvbuf:%d\n", sk->sk_rcvbuf);
	return 0;
}




static int seadp_send_skb(struct sk_buff *skb, struct flowi4 *fl4)
{
	struct sock *sk = skb->sk;
	seanet_hdr *sh;
	int offset = skb_transport_offset(skb);
	int len = skb->len - offset;
	int err = 0;
	struct inet_sock *inet = inet_sk(sk);

	sh = seadp_hdr(skb);
	sh->src_port = (u16)inet->inet_sport;
	sh->dst_port = fl4->fl4_dport;
	sh->chunk_len = htonl(len);
	sh->seadp_csum = 0;
	skb->ip_summed = CHECKSUM_NONE;
send:
	err = IP_SEND_SKB(sock_net(sk), skb);
/*	if (err) 			// ??????????????????????????????????????????
	{
		if (err == -ENOBUFS && !inet->recverr) 
		{
			UDP_INC_STATS(sock_net(sk), UDP_MIB_SNDBUFERRORS, is_udplite);
			err = 0;
		}
	} else
		UDP_INC_STATS(sock_net(sk),UDP_MIB_OUTDATAGRAMS, is_udplite);

*/
	return err;

}

//当sendmsg系统调用向内核传递了一个msg参数时，刚进入内核态的系统调用（seadp_sendmsg上级函数）会依据传递进来的参数，将用户态msg结构体，拷贝至内核态，生成一个内核态的msg结构
//并传递给下面的seadp_sendmsg！！！！！seadp_rcvmsg也是类似的做法！！！
//同时实现了套接字connect和非connect的情况，connect回调通用的内核函数来绑定对端默认服务器地址在sk上，这样sendto可以不指定对端服务器目的地址发送，加快效率，见apn UDP connect！
int seadp_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)	//先实现一个简单的，不考虑复杂的套接字选项.
{
	struct flowi4 *fl4;
	struct flowi4 fl4_stack;
	struct rtable *rt = NULL;
	__be32 daddr, faddr, saddr;
	__be16 dport;
	int connected = 0;
	int err;
	int ulen = len;
	struct ipcm_cookie ipc;
	int (*getfrag)(void *, char *, int, int, int, struct sk_buff *);
	struct net *net = sock_net(sk);
	struct inet_sock *inet = inet_sk(sk);
	u8  tos;
	__u8 flow_flags = inet_sk_flowi_flags(sk);
	struct sk_buff *skb;
	struct ip_options_data opt_copy;


	////("seadp_sendmsg\n");	//test~~


	//lock_sock(sk);	//类似UDP的套接字，没有复杂的流控、重传貌似不需要加锁！！！
	printk("%s: us: %X\n", __func__, seadp_clock_us());
	if(len > 0xFFFFFFFF) //seadp首部 长度字段有32Bit,数据包长度不能超过0xffffffff
		return -EMSGSIZE;

	ipc.opt = NULL;
	//4.19.97内核这个数据结构变了？//ipc.tx_flags = 0;
	ipc.ttl = 0;
	ipc.tos = -1;


	getfrag = ip_generic_getfrag;	//决定用什么分片函数，必不可少。这里用ip层的分片功能！！！！

	fl4 = &inet->cork.fl.u.ip4;
	ulen += sizeof( seanet_hdr);	//!!!

	if (msg->msg_name)
	{
		DECLARE_SOCKADDR(struct sockaddr_in *, usin, msg->msg_name);
		if (msg->msg_namelen < sizeof(*usin))	return -EINVAL;
		if (usin->sin_family != AF_INET)	return -EAFNOSUPPORT;

		daddr = usin->sin_addr.s_addr;
		dport = usin->sin_port;

		if (dport == 0)		return -EINVAL;
				
			
	}
	else
	{
		printk("%s: before connected\n", __func__);
		if (sk->sk_state != TCP_ESTABLISHED)	return -EDESTADDRREQ;
		daddr = inet->inet_daddr;
		dport = inet->inet_dport;
		connected = 1;
		printk("%s: connected\n", __func__);
		printk("-1\n");
	}

	printk("%s: 0\n",__func__);	
	ipc.sockc.tsflags = sk->sk_tsflags;
	printk("%s: 0.1\n",__func__);	
	ipc.addr = inet->inet_saddr;
	printk("%s: 0.2\n", __func__);
	ipc.oif = sk->sk_bound_dev_if;
	printk("%s: 0.3\n", __func__);
//支持对ipv4选项！！（最大40字节）暂时不加
/*	if (!ipc.opt) 
	{
		struct ip_options_rcu *inet_opt;

		rcu_read_lock();
		inet_opt = rcu_dereference(inet->inet_opt);
		if (inet_opt) 
		{
			memcpy(&opt_copy, inet_opt,
			       sizeof(*inet_opt) + inet_opt->opt.optlen);
			ipc.opt = &opt_copy.opt;
		}
		rcu_read_unlock();
	}

*/
	printk("%s: 1\n", __func__);
	saddr = ipc.addr;
	ipc.addr = faddr = daddr;
	
	tos = get_rttos(&ipc, inet);
	
	//printk("%s: before lookup route: %X\n", __func__, seadp_clock_us());
	if (connected)	rt = (struct rtable *)sk_dst_check(sk, 0);
	
	printk("%s: 2\n", __func__);
	if(!rt)
	{
		//printk("123\n");
		fl4 = &fl4_stack;			//???
		flowi4_init_output(fl4, ipc.oif, sk->sk_mark, tos,
				   RT_SCOPE_UNIVERSE, sk->sk_protocol,
				   flow_flags,
				   faddr, saddr, dport, inet->inet_sport,
				   sk->sk_uid);				//???
		security_sk_classify_flow(sk, flowi4_to_flowi(fl4));   //??
		rt = ip_route_output_flow(net, fl4, sk);
		
		if (IS_ERR(rt)) 
		{
			err = PTR_ERR(rt);
			rt = NULL;
			if (err == -ENETUNREACH)	IP_INC_STATS(net, IPSTATS_MIB_OUTNOROUTES);
			goto out;
		}
		err = -EACCES;
		if ((rt->rt_flags & RTCF_BROADCAST) && !sock_flag(sk, SOCK_BROADCAST))	goto out;
		if (connected)	sk_dst_set(sk, dst_clone(&rt->dst));
		
	}
	//printk("%s: after lookup route: %X\n", __func__, seadp_clock_us());
	
	saddr = fl4->saddr;
	
	if (!ipc.addr)	daddr = ipc.addr = fl4->daddr;
	//printk("%s: us: %X\n", __func__, seadp_clock_us());
	printk("%s: 3\n", __func__);
	skb = IP_MAKE_SKB(sk, fl4, getfrag, msg, ulen, sizeof( seanet_hdr), &ipc, &rt, msg->msg_flags);
	//printk("%s: us: %X\n", __func__, seadp_clock_us());
	err = PTR_ERR(skb);
	printk("%s: 4\n", __func__);
	if (!IS_ERR_OR_NULL(skb))
		
		err = seadp_send_skb(skb, fl4);
	
	//printk("all: us: %X\n", seadp_clock_us());
	goto out;
		
out:
	ip_rt_put(rt);	//释放对路由缓存的引用
	printk("%s: us: %X\n", __func__, seadp_clock_us());
	if (!err)
		return len;
/*	
	if (err == -ENOBUFS || test_bit(SOCK_NOSPACE, &sk->sk_socket->flags))	//???????? 
	{
		UDP_INC_STATS(sock_net(sk), UDP_MIB_SNDBUFERRORS, is_udplite);
	}
*/
	
	return err;
	//release_sock(sk);
	
	
}

struct sk_buff *__skb_recv_seadp(struct sock *sk, unsigned int flags, int noblock, int *peeked, int *off, int *err)
{
	struct sk_buff_head *sk_queue = &sk->sk_receive_queue;
	long timeo;	//设置套接字发送和接收超时时间，仅在套接字阻塞时才起作用

	flags |= noblock ? MSG_DONTWAIT : 0;
	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);  //超时时间为sk->sk_rcvtimeo,由setsockopt设置！！
	
	lock_sock(sk);		//临界区开始，虽是自选锁，但对进程上下文之间具有互斥锁语义

	release_sock(sk);	//临界区结束

}

int seadp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int noblock, int flags, int *addr_len)
{
//注意！：
//1.非连接的套接字，这里并未使用msg来向用户态传递接收包的地址，对于连接的套接字来说用不着msg_name来传递发送者地址，毕竟连接时端到段地址已经确认！！！
//2.receive队列中依旧有重复的字节，应该小心处理
#if DEBUG_T
	struct sk_buff *skb, *last;
	int peeked, off;
	int err;
	u32 *seq;	//	用于小心处理receive队列中接收到的重复字节！！
	unsigned long used;
	struct seadp_sock *sh = seadp_sk(sk);
	int copied = 0;		//copied就是已经向用户空间拷贝的字节数
	long timeo;		//设置套接字发送和接收超时时间，仅在套接字阻塞时才起作用
	int target;		/* Read at least this many bytes */
	
	////////////u32 *offset;	//my_protocol
	DECLARE_SOCKADDR(struct sockaddr_in *, sin, msg->msg_name);	//借鉴UDP，因为TCP是面向连接的，对端地址已经知道了，收取数据时无需再次上传地址

	//skb = __skb_recv_seadp(sk, flags, noblock, &peeked, &off, &err);


	if (unlikely(flags & MSG_ERRQUEUE))
		//return inet_recv_error(sk, msg, len, addr_len);
		return INET_RECV_ERROR(sk, msg, len, addr_len);
	
	lock_sock(sk);		//临界区开始，虽是自选锁，但对进程上下文之间具有互斥锁语义
	//no //////("%s: recvmsg start lock\n", __func__);
	err = -ENOTCONN;	
	timeo = sock_rcvtimeo(sk, noblock);  //超时时间为sk->sk_rcvtimeo,由setsockopt设置！！

	seq = &sh->copied_seq;	//用于小心处理receive队列中接收到的重复字节！！sh->copied_seq初始化应该是0

	target = sock_rcvlowat(sk, flags & MSG_WAITALL, len);
	
		
	//no //////("%s: 1\n", __func__);
	do
	{
		u32 offset;

		last = skb_peek_tail(&sk->sk_receive_queue);
		skb_queue_walk(&sk->sk_receive_queue, skb)	//遍历sk->sk_receive_queue队列！！
		{
			last = skb;
			/* my_protocol
			offset = &(SEADP_SKB_CB(skb)->offset);			
			if (*offset < skb->len)		//可能判断有点重复
				goto found_ok_skb;
			*/

			offset = *seq - SEADP_SKB_CB(skb)->seq; 
			if (offset < skb->len)	goto found_ok_skb;
			
		}
		//只有当receive队列全部释放完毕，才会运行到这里！！
		//no //////("%s: 2\n", __func__);
		if (copied >= target && !sk->sk_backlog.tail)	break;		//receive队列已为空，复制已超过target目标且sk->sk_backlog队列没有新的数据，可以返回用户态！
		//接下来 当拷贝字节数少于target或者backlog依旧有数据
		//不管是不是已经复制了数据，套接字在非阻塞模式下，处理完receive队列的数据就会直接退出，而不会去再处理backlog队列上的数据，即使有的话！！！
		
		if(copied)	//TCP-based @@ 这里抄了TCP实现
		{
			if(!timeo || signal_pending(current))	break;
		}
		else
		{
			if (!timeo) 
			{
				copied = -EAGAIN;
				break;
			}

			if (signal_pending(current)) 
			{
				copied = sock_intr_errno(timeo);
				break;
			}
		}
		//recieve队列处理完毕，但是套接字阻塞，没复制至少target字节或者backlog中依旧有数据，注意，此时用户进程并未持有sk->sk_lock.slock锁！！
		if (copied >= target) //copied >= target && sk->sk_backlog.tail, 直接处理backlog中的数据
		{
			/* Do not sleep, just process backlog. */
			release_sock(sk);
			lock_sock(sk);
		} 
		else	//receive队列处理完了，但backlog有数据或者没拷贝到target个字节
		{
			//no //////("%s: 3\n", __func__);
			sk_wait_data(sk, &timeo, last);
		}
		//no //////("%s: 4\n", __func__);
		continue;	//阻塞完了，继续执行do while循环直到拷贝完len字节数据或者满足某些条件！！一定不能少！！
		
	found_ok_skb:
		/*used = skb->len - *offset;*///my_protocol

		used = skb->len - offset;//计算此skb可用字节数

		if (len < used)
			used = len;

		//no //////("%s: 5\n", __func__);
		if (!(flags & MSG_TRUNC)) //没有设置这个标志位时直接拷贝，MSG_TRUNC只对packet套接字有效！！
		{
			//err = skb_copy_datagram_msg(skb, *offset, msg, used);	//my_protocol
			err = skb_copy_datagram_msg(skb, offset, msg, used);			
			
			if (err) 	//失败！！
			{
				
				/* Exception. Bailout! */
				if (!copied)
					copied = -EFAULT;
				break;
			}
		}
		
		//*offset += used;  //重新设置该Skb字节读取偏移 my_protocol
		*seq += used;  
		len -= used;
		copied += used;
		

		//if (*offset < skb->len)	//该skb没有全部拷贝完 my_protocol
		if (used + offset < skb->len)	//该skb没有全部拷贝完
			continue;	//会判断一次while中的条件！！如果len还有剩余，则该skb不释放且继续下一轮循环，不剩余了则退出循环！！


		if (!(flags & MSG_PEEK))	//	如果offset == skb->len 且MSG_PEEK置位，那么可以将skb从receive队列中取出，并释放
		{			
			////("%s: sk->sk_forward_alloc: %d, sk->sk_rmem_alloc:%d\n",__func__, sk->sk_forward_alloc, atomic_read(&sk->sk_rmem_alloc));
			sk_eat_skb(sk, skb);
//不需要手动较少sk->sk_rmem_alloc和sk->sk_forward_alloc,因为free skb时会调用skb->destructor = sock_rfree！！！此在skb入receive队列时调用skb_set_owner_r设置的
			//atomic_sub(skb->truesize, &sk->sk_rmem_alloc);	//	！！
			//sk->sk_forward_alloc += skb->truesize;		//	！！
			////("%s: sk->sk_forward_alloc: %d, sk->sk_rmem_alloc:%d\n",__func__, sk->sk_forward_alloc, atomic_read(&sk->sk_rmem_alloc));
		}
	} while(len > 0);                   //当拷贝字节数少于用户请求字节数时，应一直循环拷贝！！

	
	/* Copy the address. *///借鉴UDP，因为TCP是面向连接的，对端地址已经知道了，收取数据时无需再次上传地址
	/* According to UNIX98, msg_name/msg_namelen are ignored
	 * on connected socket. I was just happy when found this 8) --ANK
	 */
//这个函数的msg应该是刚进内核态,系统调用开辟的，并记录下用户态rcvmsg传进来的msg参数。所以我们在这个函数中，只赋值内核态开辟的msg，当系统调用返回用户态前，
//会由此函数的上级函数将内核态msg指向的数据，拷贝至用户态msg指向的内存地区！！！seadp_sendmsg中也是如此！！！！
	if (sin) 
	{
		sin->sin_family = AF_INET;
		sin->sin_port = seadp_hdr(skb)->src_port;
		sin->sin_addr.s_addr = ip_hdr(skb)->saddr;
		memset(sin->sin_zero, 0, sizeof(sin->sin_zero));
		*addr_len = sizeof(*sin);
	}

	//no //////("%s: to release_sock\n", __func__);
	release_sock(sk);	//临界区结束
	//no //////("%s: has release_sock\n", __func__);
	return copied;


#else
	//("seadp_recvmsg\n");
	return 0;

#endif
}
int seadp_lib_hash(struct sock *sk)
{
	BUG();
	////("seadp_lib_hash\n");
	return 0;
}

void seadp_lib_unhash(struct sock *sk)	//	用户态close会调用
{
	u16 index;  
	if(!seadp_sk(sk)->bound) return;

	index = inet_sk(sk)->inet_num % HASH_LEN;

	spin_lock_bh(&(hash_array[index].lock));	//貌似spin_lock就行，没必要排除当前核的软中断
	
	hlist_del_rcu(&(sk->sk_node));	//从哈希桶中删除！
	seadp_sk(sk)->bound = 0;
	hash_array[index].count--;


	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, -1);//记账用，减少1个套接字，体现在/proc/net/protocols中sockets字段，表示此时创建了多少seadp套接字
	spin_unlock_bh(&(hash_array[index].lock));

	//("seadp_lib_unhash\n");

	
}
int seadp_v4_get_port(struct sock *sk, unsigned short snum)   //bind	snum是源端口16位,snum=0代表任意选择一个可用的端口	简单的求余hash
{
	unsigned short port = htons(snum);
	u16 index;	
	struct sock *sk_ptr;
	u32 random,random_port;
	int low, high;

	if(seadp_sk(sk)->bound)	return -1;	//	已经绑定过了~~
	//("bind addr:%X\n", inet_sk(sk)->inet_rcv_saddr);
	if(!snum)	//任意选择一个可用的端口号,最简单的算法～～～
	{
		
		/******************************************************************/


				
	}

	index = port % HASH_LEN;
	spin_lock_bh(&(hash_array[index].lock));	//禁止本核的下半部是为了考虑软中断对哈希链的修改！！！尤其是TCP，这里可能没必要加锁～～～～，因为在inet_bind中有上级锁了lock_sk

	hlist_for_each_entry(sk_ptr, &(hash_array[index].head), sk_node)	//检查是否已经有重复的绑定地址了（端口+源地址），可以允许不同IP同一端口
	{
		if( inet_sk(sk_ptr)->inet_num == snum )	
		{
			if(inet_sk(sk_ptr)->inet_rcv_saddr == inet_sk(sk)->inet_rcv_saddr || inet_sk(sk_ptr)->inet_rcv_saddr ==htonl(INADDR_ANY)) //端口地址都相同，失败返回
				//("address is in use!!\n");
				spin_unlock_bh(&(hash_array[index].lock));	//！！！
				return -1;
		}				
	}
	inet_sk(sk)->inet_num = snum;	//snum是用户用户空间传来的端口号的ntohs，是主机字节序，但是inet->inet_sport与snum字节序相反！！
	seadp_sk(sk)->bound = 1;				
	hlist_add_head_rcu(&(sk->sk_node),&(hash_array[index].head));	//增加至此哈希桶
	hash_array[index].count++;	//增加此哈希桶中套接字的个数
	sock_prot_inuse_add(sock_net(sk), sk->sk_prot, 1);//记账用，增加1个套接字，体现在/proc/net/protocols中sockets字段，表示此时创建了多少seadp套接字

	spin_unlock_bh(&(hash_array[index].lock));

	return 0;
}
/*
void test_request_sk(struct sock *sk, u32 end_seq, u32 len)
{
	struct seanet_head_info head_info;
	head_info.seq=end_seq-len;
	head_info.len=len;
	
	seadp_request_data(sk, &head_info);
}
*/
void test_request_sk(struct sock *sk, int quota)	//以snd_nxt为初始，请求quota个SEADP_MSS字节数，只发送一个聚合请求帧
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct seanet_head_info head_info;
	struct request_sk p;
	//LIST_HEAD(add_list);
	
	int i,num=0;

	for(i=0;i<quota;i++)
	{
		head_info.seq=sh->snd_nxt + i*SEADP_MSS;
		head_info.len=SEADP_MSS;

		if(!seadp_request_data(sk, &head_info))
		{
			printk("%s: seadp_request_data err\n", __func__);
			break;
		}
		num++;
	}
	if(num!=0)
	{
		head_info.seq = sh->snd_nxt;
		head_info.len = SEADP_MSS*num;
		p.seq	=	head_info.seq;
		p.len	=	head_info.len;
//放在判定发送是否失败的前面！！！！！！！
		sh->snd_nxt = sh->snd_nxt + head_info.len;	//成功发送，更新sh->snd_nxt
		sh->packets_out += num;

		if(unlikely(__seadp_send_ack(sk, SEADPHDR_DATA_REQUEST,&head_info, &p)) )
		{
			printk("%s: __seadp_send_ack err\n", __func__);
			//这里其实还需要将上述已经插入哈希表和链表中的request_sk删除！！！！！
			return;
		}
		//printk("%s: %X\n", __func__, seadp_clock_us());
		
		
	}	
	
}

int ip4_seadp_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct seadp_sock *sh = seadp_sk(sk);
	int err;
	struct seanet_head_info head_info;

	lock_sock(sk);
	head_info.seq=40;
	head_info.len=20;
	err = __ip4_datagram_connect(sk, uaddr, addr_len);
	
	printk("%s: before request: %X\n", __func__, seadp_clock_us());
	////seadp_mstamp_refresh(seadp_sk(sk));	//test
	////sh->packets_out++;	//test	
	////sh->snd_nxt = SEADP_MSS;
	////test_request_sk(sk,SEADP_MSS,SEADP_MSS);

	seadp_data_snd_check(sk);
	printk("%s: after request: %X\n", __func__, seadp_clock_us());
	//printk("%s: after request: %X\n", __func__, seadp_clock_us());
/*
	printk("%s: ns time: %ld\n", __func__, ktime_get());
	printk("%s: jiffies: %X\n", __func__, jiffies);
	printk("%s: us: %X\n", __func__, seadp_clock_us());
	show_usec();
*/
	//("2\n");
/*
	seadp_mstamp_refresh(seadp_sk(sk));	//test
	test_request_sk(sk,100,3);
	test_request_sk(sk,100,9);
test_request_sk(sk,6,6);
test_request_sk(sk,11,4);
test_request_sk(sk,7,2);
test_request_sk(sk,95,10);
test_request_sk(sk,97,8);
test_request_sk(sk,90,20);
test_request_sk(sk,80,7);
test_request_sk(sk,75,10);
test_request_sk(sk,9,9);
test_request_sk(sk,60,6);
test_request_sk(sk,65,9);
test_request_sk(sk,60,20);
test_request_sk(sk,70,15);
test_request_sk(sk,77,18);
test_request_sk(sk,6,6);
test_request_sk(sk,57,3);
test_request_sk(sk,58,6);
test_request_sk(sk,55,17);
test_request_sk(sk,50,11);
test_request_sk(sk,15,12);
test_request_sk(sk,80,19);
test_request_sk(sk,47,8);
test_request_sk(sk,43,4);
test_request_sk(sk,85,7);
test_request_sk(sk,40,1);
test_request_sk(sk,39,5);
test_request_sk(sk,42,12);
test_request_sk(sk,31,9);
test_request_sk(sk,25,2);
test_request_sk(sk,24,3);
test_request_sk(sk,26,6);
test_request_sk(sk,60,13);
test_request_sk(sk,20,8);
test_request_sk(sk,19,7);
test_request_sk(sk,70,20);
test_request_sk(sk,12,5);
test_request_sk(sk,10,10);	
*/
	release_sock(sk);
	//("%s: has release_sock\n", __func__);
	return err;
}

struct proto seadp_prot = 
{
	.name     	= "SEADP",
	.owner    	= THIS_MODULE,
	.close    	= seadp_lib_close,
	.connect	= ip4_seadp_connect,		//借用通用函数！！！！
	.init     	= seadp_init_sock,
	.destroy	= seadp_v4_destroy_sock,
	.sendmsg  	= seadp_sendmsg,
	.recvmsg  	= seadp_recvmsg,
	.release_cb	= seadp_release_cb,
	.hash     	= seadp_lib_hash, 
	.unhash     	= seadp_lib_unhash,
	.memory_allocated = &seadp_memory_allocated,
	.sysctl_mem	= sysctl_seadp_mem,
	.sysctl_wmem	= &sysctl_seadp_wmem_min,
	.sysctl_rmem	= &sysctl_seadp_rmem_min,
	.backlog_rcv	= seadp_v4_do_rcv,
	.get_port 	= seadp_v4_get_port,
	.obj_size 	= sizeof(struct seadp_sock),
};


struct inet_protosw seadp_socket=
{
	.type     =   SOCK_DGRAM,
	.protocol =   IPPROTO_SEADP,              //seadp协议 153
	.prot     =   &seadp_prot,
	.ops      =   &inet_dgram_ops,
	//.flags    =   INET_PROTOSW_PERMANENT,     //永久协议，非连接的套接字 不能是永久协议不然删除不了，而且重复注册会崩溃，不知道为啥？？****原因：因为这个seadp_socket数据结构是随着该模块注册进内核的，并插入的链表，rmmod模块后结构体会删除，但是由于时永久协议并不能取消注册，所以inetsw结构中还保留着链表的指针指向seadp_prot原地址，但是这个地址的保存着的seadp_prot结构体已经随着模块rmmod已经没了，所以造成的后果是下一次insmod注册套接字再次遍历inetsw时造成了内存泄漏等不可预知的问题最终导致系统崩溃！！！！

};
/**************注册套接字（对上层）*************/


static void seadp_pacing_handler(struct sock *sk)
{
	struct seadp_sock *sh = seadp_sk(sk);	

	//retrans//printk("%s\n", __func__);

//标记的丢失包比标记的重传包更多，说明还需重传，但需满足有cwnd空余
	////printk("%s: sh->snd_nxt: %d, sh->snd_una: %d, sh->lost_out: %d, sh->retrans_out: %d, sh->packets_out: %d, sh->snd_cwnd: %d, seadp_packets_in_flight: %d\n", __func__, sh->snd_nxt, sh->snd_una, sh->lost_out, sh->retrans_out, sh->packets_out, sh->snd_cwnd, seadp_packets_in_flight(sh));
#if (TIMEOUT_RETRANS_SET || FAST_RETRANS_SET)
	if (sh->lost_out > sh->retrans_out && sh->snd_cwnd > seadp_packets_in_flight(sh)) //(fast) retransmission is also taken into pacing!!! 
	{
		//if(sh->packets_num_in_ofo >= DISORDER_TIMES && !sh->has_fast_retrans)
		//{
			///printk("%s: to seadp_xmit_retransmit_queue\n", __func__);

			seadp_mstamp_refresh(sh);	//更新下时间戳
			////printk("%s: tasklet retrans\n", __func__);
			seadp_xmit_retransmit_queue(sk);		
		//}	
	}
	else
	{
		//retrans//printk("%s: sh->snd_nxt: %d, sh->snd_una: %d, sh->lost_out: %d, sh->retrans_out: %d, sh->packets_out: %d, sh->snd_cwnd: %d, seadp_packets_in_flight: %d\n", __func__, sh->snd_nxt, sh->snd_una, sh->lost_out, sh->retrans_out, sh->packets_out, sh->snd_cwnd, seadp_packets_in_flight(sh));
	}
#endif
	/////printk("%s: to seadp_data_snd_check\n", __func__);
	///seadp_mstamp_refresh(sh);
	
	seadp_data_snd_check(sk);

}


/*
static void seadp_tasklet_func(unsigned long data)
{
	struct pacing_tasklet *pac = (struct pacing_tasklet *)data;
	LIST_HEAD(list);
	unsigned long flags;
	struct list_head *q, *n;
	struct seadp_sock *sh;
	struct sock *sk;
	
	//("%s\n", __func__);
	local_irq_save(flags);
	list_splice_init(&pac->head, &list);	//这里操作pac->head链表不会与hrtimer软中断函数中list_add所冲突，因为，tasklet与hrtimer为不同类型软中断是不会互相抢占一个核的，而并列运行与不同核上所操作的数据又分别是per-cpu的，即不同区域的数据，故而不会有竞争冲突，所以这里是lock-free的操作！！！！！！！！！
	local_irq_restore(flags);

	list_for_each_safe(q, n, &list) 
	{
	
		sh = list_entry(q, struct seadp_sock, pacing_node);
		
		sk = (struct sock *)sh;		//特么的sh在这里才赋值，那么bh_lock_sock只能在这之后啊啊啊啊啊啊啊啊！！！！！	

		//("%s:sh->pacing_flags 1: %X\n", __func__, sh->pacing_flags);
		smp_mb__before_atomic();	//??????
		//("%s:sh->pacing_flags 2: %X\n", __func__, sh->pacing_flags);
		
		list_del(&sh->pacing_node);
		clear_bit(SEADP_PACING_QUEUED_BIT, &sh->pacing_flags);		//clear the mask of queued for tasklet for pacing!!!!!
		
		//if (!sk->sk_lock.owned && test_bit(SEADP_PACING_DEFERRED, &sk->sk_tsq_flags)) 
		//("%s: before lock\n", __func__);
		bh_lock_sock(sk);	//lock
		//("%s: lock\n", __func__);
		if (sock_owned_by_user(sk)) //socket owned by user, so delay doing pacing to seadp_release_cb()
		{
			//("%s: pacing defer\n", __func__);
			set_bit(SEADP_PACING_DEFERRED_BIT, &sh->pacing_flags);
			bh_unlock_sock(sk);	//unlock
			return;
			
		}
		seadp_pacing_handler(sk);	//do pacing now!!
	
		bh_unlock_sock(sk);	//unlock
	}
}
*/

static void seadp_tasklet_func(unsigned long data)
{
	struct pacing_tasklet *pac = (struct pacing_tasklet *)data;
	LIST_HEAD(list);
	unsigned long flags;
	struct list_head *q, *n;
	struct seadp_sock *sh;
	struct sock *sk;
	
	
	//printk("%s: us: %X\n", __func__, seadp_clock_us());
	local_irq_save(flags);
	list_splice_init(&pac->head, &list);	
	local_irq_restore(flags);

	

	list_for_each_safe(q, n, &list) 
	{

		sh = list_entry(q, struct seadp_sock, pacing_node);
		
		sk = (struct sock *)sh;	
		smp_mb__before_atomic();
		list_del_init(&sh->pacing_node);
		clear_bit(SEADP_PACING_QUEUED_BIT, &sh->pacing_flags);

		/////if(!sh->packets_out)	printk("%s: cpu num: %d\n", __func__, pac->num);

		//if(test_bit(SEADP_PACING_DEFERRED_BIT, &sh->pacing_flags)) printk("%s: pacing deferred\n", __func__);
		if (!sk->sk_lock.owned && test_bit(SEADP_PACING_DEFERRED_BIT, &sh->pacing_flags))
		{
			///printk("%s: try to hold lock\n",__func__);
			bh_lock_sock(sk);
			if (!sock_owned_by_user(sk) && !sh->sock_will_close) 
			{
				clear_bit(SEADP_PACING_DEFERRED_BIT, &sh->pacing_flags);
				////if(!sh->packets_out) printk("%s: to seadp_pacing_handler\n", __func__);
				seadp_pacing_handler(sk);
			}
			bh_unlock_sock(sk);
		}
		sock_put(sk); //8.8!!!!!

	}
}

void  seadp_tasklet_init(void)
{
	int i;

	for_each_possible_cpu(i) 
	{
		struct pacing_tasklet *pac = &per_cpu(pacing_tasklet, i);
		pac->num = i;
		INIT_LIST_HEAD(&pac->head);
		tasklet_init(&pac->tasklet, seadp_tasklet_func, (unsigned long)pac);
	}
}

static int __init init_fun(void)
{
	int ret; 
	int i;
	int *cpu_num_ptr;

	MEM_CGROUP_CHARGE_SKMEM =  ( typeof(MEM_CGROUP_CHARGE_SKMEM) )kallsyms_lookup_name("mem_cgroup_charge_skmem");
	INET_RECV_ERROR = (typeof(INET_RECV_ERROR)) kallsyms_lookup_name("inet_recv_error");
	MINMAX_RUNNING_MIN = (typeof(MINMAX_RUNNING_MIN)) kallsyms_lookup_name("minmax_running_min");
	IP_MAKE_SKB = (typeof(IP_MAKE_SKB))kallsyms_lookup_name("ip_make_skb");
	IP_SEND_SKB = (typeof(IP_SEND_SKB))kallsyms_lookup_name("ip_send_skb");
	
	
	if(!MEM_CGROUP_CHARGE_SKMEM || !INET_RECV_ERROR || !IP_MAKE_SKB || !IP_SEND_SKB) 
	{
		//("kallsyms_lookup_name error!!\n");
		return 0;
	}
	for(i=0;i<HASH_LEN;i++)	
	{
		spin_lock_init(&(hash_array[i].lock));	//初始化自旋锁！！
		hash_array[i].head.first = NULL;	//初始化哈希表头！！	
		hash_array[i].count = 0;
	}

	seadptable.hash = hash_array;

	
	atomic_set((atomic_t*)&seadp_memory_allocated,0);
	sysctl_seadp_mem[0]	= SEADP_MEM_0;
	sysctl_seadp_mem[1]	= SEADP_MEM_1;
	sysctl_seadp_mem[2]	= SEADP_MEM_2;
	sysctl_seadp_wmem_min	= SEADP_WMEM_MIN;
	sysctl_seadp_rmem_min	= SEADP_RMEM_MIN;


	seadp_tasklet_init();

	for_each_possible_cpu(i) 
	{
		cpu_num_ptr = 	&per_cpu(cpu_number, i);
		*cpu_num_ptr = i;
		printk("%s: i: %d\n", __func__, i);
	}
	for_each_possible_cpu(i)
	{
		cpu_num_ptr = per_cpu_ptr(&cpu_number, i);
		printk("%s: cpu number: %d\n", __func__, *cpu_num_ptr);
	}
	
	if(proto_register(&seadp_prot,1))	goto unregister_proto; 		//这一步具体没啥用，主要是向全局静态链表proto_list中注册这个协议，在协议本身上没有太大用途，它只用于在/proc/net/protocols文件中输出当前系统支持的协议。而且，如果不加的话，inet_create会打印warning日志，具体见WARN_ON(!answer_prot->slab); 处,它会给该种类的套接字分配一个索引号（assign_proto_idx(prot);），即prot->inuse_idx,不同种类套接字索引号不一样，套接字个数统计时根据此索引号将计数存储至一个相应的cpu变量之中，见sock_prot_inuse_add函数实现！！！

	
	ret = inet_add_protocol((const struct net_protocol*)&seadp_protocol, IPPROTO_SEADP);  	//注册传输层协议，对下层来说
	
	//("----------------------------\n");
	if(ret >= 0)	//("inet_add_protocol seadp successful!\n");

	inet_register_protosw(&seadp_socket);
	if(seadp_register_congestion_control(&seadp_bbr_cong_ops) == 0) //("register congestion successfully\n");

	//("register a seadp socket!\n");
	//("insmod successfully\n");
	//("----------------------------\n");
	return 0;

unregister_proto:
	proto_unregister(&seadp_prot);
	//("proto_register error!!\n");
	return 0;
}


static void __exit exit_fun(void)
{
	int ret; 

	proto_unregister(&seadp_prot);
	ret = inet_del_protocol((const struct net_protocol*)&seadp_protocol, IPPROTO_SEADP);
	
	//("----------------------------\n");
	if(ret >= 0) //("inet_del_protocol succeed!\n");
	inet_unregister_protosw(&seadp_socket);

	seadp_unregister_congestion_control(&seadp_bbr_cong_ops);	//可以不必unregister，因为在一个模块里面
	//("rmmod successfully\n");
	//("----------------------------\n");
}

module_init(init_fun);
module_exit(exit_fun);
