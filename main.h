#ifndef __MAIN_H__
#define __MAIN_H__

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
#include <linux/sched/clock.h>
#include <linux/win_minmax.h>
#include <linux/hrtimer.h>
#include "congestion.h"


#define DATA_SIZE 14000000*10*4
#define CWND	100000
#define TEST_PACING_RATE (13107200*10)

#define AGGREGATION_COUNT 20

#define MIN_RTT_ADD 0

//#define AGGREGATION_COUNT (sh->snd_cwnd / 2)

#define CWND_ENTER_LOSS 10000		//seadp_enter_loss之后cwnd设置的值
#define MAX_AGGREGATION_COUNT	64	//最大的请求聚合数

#define DEFER_REQUEST		1	//1代表加入延迟发送功能，以获得合理的聚合度
#define FIX_AGGREGATION_COUNT	0	//1表示我们固定聚合数目
#define FIX_CWND_AND_PACING	0	//1表示我们固定cwnd和pacing rate，不被拥塞控制模块控制
#define CONGESTION_SET		1	//拥塞控制代码宏
#define TIMEOUT_RETRANS_SET	1	//超时重传代码宏
#define	FAST_RETRANS_SET	1	//快速重传代码宏


#define SEADP_DEFAULT_CONGESTION "seadp_bbr"

#define SPSK_TIME_RETRANS 1	/* Retransmit timer */
#define SEADP_RTO_MAX	((unsigned)(120*HZ))
#define SEADP_RESOURCE_PROBE_INTERVAL ((unsigned)(HZ/2U)) // Maximal interval between probes for local resources.


#define SEADP_PACING_QUEUED_BIT 0		//seadp socket is queued into tasklet queue (per-cpu) by hrtimer
#define SEADP_WRITE_TIMER_DEFERRED_BIT 1
#define SEADP_PACING_DEFERRED_BIT 2


#define SEADP_PACING_QUEUED (1UL << SEADP_PACING_QUEUED_BIT)		//seadp socket is queued into tasklet queue (per-cpu) by hrtimer
#define SEADP_WRITE_TIMER_DEFERRED (1UL << SEADP_WRITE_TIMER_DEFERRED_BIT)
#define SEADP_PACING_DEFERRED (1UL << SEADP_PACING_DEFERRED_BIT)

#define SEADP_DEFERRED_ALL (SEADP_WRITE_TIMER_DEFERRED | SEADP_PACING_DEFERRED)	//一定要加括号！！！！！醉了


#define SEADP_DATA 	0x01
#define SEADP_REQUEST 	0x02

#define SEADP_RTO_MIN	((unsigned)(HZ/5))

#define SEADP_TIMEOUT_INIT ((unsigned)(1*HZ))	// RFC6298 2.1 initial RTO value

#define FLAG_RETRANS_DATA_ACKED	0x08 	// "" "" some of which was retransmitted.	

#define SEADP_MSS 1400			
#define MAX_TRAVERSE_NUM   64
#define MAX_MARK_LOST_NUM 64	//超时定时器中一次性所能标记的最多丢失包的数目
#define MAX_RETRANS_NUM	10	//超时定时器中一次性所能重新请求的最大包数目（seq连续的）
#define DISORDER_TIMES	4
#define MAX_FAST_RETRANS_PACK 10

#define SYSCTL_SEADP_MIN_RTT_WLEN 300		//  learn from /proc/sys/net/ipv4/sysctl_tcp_min_rtt_wlen

#define SEADP_INIT_CWND 10

//64B
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
	   saved : 3;		
	u8 cache_mark;
	u8 transport_mark;
	u8 reserve; 
	u32 chunk_len;
	u32 offset;
	u16 seq;
	u16 seadp_csum;
} seanet_hdr;

struct seanet_head_info	//以下都是主机字节序
{
	u32 seq;	//请求报文偏移
	u32 len;	//请求数据长度（字节）

};

struct seadp_skb_cb
{
	__u32 seq;	//字节序号
	__u32 offset;	//已读取字节的偏移地址
	__u16 pn;	//包序号！
	__u32 end_seq;	//尾字节，对应seanet_hdr offset;
	__u8 packet_mark;	//报文标志

	__u8 seadp_flags;	//SEADP header flags. (tcp[13])

	//u64 request_mstamp;	//该数据对应的请求报文第一次发送时的时间戳
	struct request_sk *target;
};

struct seadp_hslot
{
	struct hlist_head head;
	int count;
	spinlock_t lock;
}__attribute__((aligned(2 * sizeof(long))));

struct seadp_table   //seadp套接字管理结构体
{
	struct seadp_hslot *hash;
	unsigned int mask;
	
};

#define SEADP_RETRANS	0x01	//used to mark request_sk which is retransmitted by RTO timer!!!!
#define SEADP_LOST	0x02	//used to mark request_sk which is fast retransmitted!!!!
struct request_sk
{
	//struct request_sk *next;	//单链表
	struct list_head list_node;	//双向链表
	struct hlist_node node;		//哈希链 	
	u64 request_mstamp;		//请求反馈发送时的时间戳！！！用作RTT
	u64 delivered_mstamp;		//
	u32 seq;			//请求起始序号,记录的是发送段数据数组的偏移!!!!!
	u32 len;			//请求字节数
	u32 delivered;			//记录发送请求时，当前已经收到的数据包个数,为了bbr做带宽估计！！
	u64 first_tx_mstamp;	
	u8 requested;			//标志这个请求是否已经重传过（首次发送不算）
	bool is_app_limited;		// is sample from packet with bubble in pipe? 
	
};

//采用滑动窗口来管理复杂性！！
struct seadp_sock
{
	struct inet_sock inet;
	
	u32	bound;		//是否已经绑定至seadptable！！	


	u64	bytes_received;	//已接收的字节数
	u32	copied_seq;	// Head of yet unread data  已复制的字节序号，用于用户态进程从receive队列接收字节时小心处理重复的字节！！！

	u32	rcv_wup;	// rcv_nxt on last window update sent	接收通告窗口左边界
	u32	rcv_nxt;	// What we want to receive next 			
	u32	rcv_wnd;	//Current receiver window	接收通告窗口通告值

	
	u32	snd_una;	// First byte we want an ack for	
	u32	snd_nxt;	// Next sequence we send 下一个可发送但还未发送的字节序号	
	u32	snd_wnd;	// The window we expect to receive	发送窗口大小，在接收端估计！！

	u32	lsndtime;	/* timestamp of last sent data packet (for restart window) */
	struct 	list_head pacing_node; // anchor in tsq_tasklet.head list 

	u32	snd_ssthresh;	// Slow start size threshold		


	u32	rcv_tstamp;	// timestamp of last received ACK (for keepalives)这里记录最后一个接收数据的时间戳(for keepalives)

	u32	snd_cwnd;	// 发送的拥塞窗口大小，但这里和TCP不同的是，由接收者估计，并显示通告给发送者的！！	这里时接收路径上估计的发送者发送拥塞窗口大小	

	u32	snd_cwnd_clamp; // Do not allow snd_cwnd to grow above this 

	u32	prior_cwnd;	// cwnd right before starting loss recovery 
	
	u32	start_seq;	//定时器所负责的当前RTT窗口内的起始seq字节序号
	struct request_sk	*timer_target;

	struct timer_list	  seadp_retransmit_timer;	//超时重传定时器
 	struct timer_list	  seadp_delfeedback_timer;	//延迟反馈定时器
	__u32			  spsk_rto;			//Retransmit timeout
	__u8			  spsk_pending;			//Scheduled timer event
	unsigned long		  spsk_timeout;			//timeout

	unsigned long		  pacing_flags;
	/* RTT measurement */
	u64	seadp_mstamp;	// most recent packet received/sent 
	u32	srtt_us;	// smoothed round trip time << 3 in usecs 微秒
	u32	mdev_us;	// medium deviation	
	u32	mdev_max_us;	// maximal mdev for the last rtt period				
	u32	rttvar_us;	// smoothed mdev_max			
	u32	rtt_seq;	// sequence number to update rttvar	
	struct  minmax rtt_min;

	s64 trigger_time;	

	u32	packets_out;	// Packets which are "in flight"，包的个数！！
	u32	retrans_out;	// Retransmitted packets out	

	u8	spsk_backoff;
	u8	spsk_retransmits;	

	u64	first_tx_mstamp;  // start of window send phase		????? 
	u64	delivered_mstamp; // time we reached "delivered" 	?????

	u32	prior_ssthresh; // ssthresh saved at recovery start	
	
	u32	delivered;	// Total data packets delivered incl.(include) rexmits,套接字所交付包的个数，包括重传的个数 ,每次收到数据包会累计增加
	u32	lost;		// Total data packets lost incl. (include) rexmits 区别于下面的lost_out！！！

	u32	app_limited;	// limited until "delivered" reaches this val
	u32	lost_out;	// Lost packets	, is recorded by fast retransmission mechinism		

	const struct seadp_congestion_ops *seadp_ca_ops;
	u8	sead_ca_state;

	u32	request_count;			//the count of request_sk
	struct request_sk *expect;		//缓存期望的请求块，加速匹配
	struct request_sk *last_lost;
	struct list_head lhead;			//request_sk请求队列链表首部！！
	//struct request_sk *head;		//单向链表，指向第一个
	//struct request_sk *tail;		//指向单向链表最后一个
	struct hlist_head *request_hash_array;	//哈希数组

	struct hrtimer	pacing_timer;		//pacing function
	struct rb_root	out_of_order_queue;	//乱序队列！！
	u32 packets_num_in_ofo;
	bool has_fast_retrans;
	bool has_mark_lost;

	u8 sock_will_close;

	u32 recovery_seq;
	struct sk_buff  *request_skb;
	struct sk_buff	*ooo_last_skb;		///* cache rb_last(out_of_order_queue) */

	u64	seadp_ca_priv[88 / sizeof(u64)];

//below is test!!!
	unsigned int do_rcv_count;
	u32 rtt_sample_times;
	u32 sample_times;
	u32 send_times;
	u32 quota;
	u64 all_pacing_rate_sum;
};

struct pacing_tasklet 
{
	struct tasklet_struct	tasklet;
	struct list_head	head; /* queue of tcp sockets */
	int num;
};


void test_request_sk(struct sock *sk, int quota);

static int seadp_transmit_skb(struct sock *sk, struct sk_buff *skb, int clone_it, gfp_t gfp_mask, struct seanet_head_info *head_info, struct request_sk *rsk);
static bool seadp_pacing_check(const struct sock *sk);
static void seadp_internal_pacing(struct sock *sk, const struct request_sk *rsk);
static void seadp_pacing_handler(struct sock *sk);

static inline struct seadp_sock *seadp_sk(const struct sock *sk)
{
	return (struct seadp_sock *)sk;
}

static inline bool before(u32 seq1, u32 seq2)
{
        return (s32)(seq1 - seq2) < 0;
}

static inline bool after(u32 seq1, u32 seq2)
{
        return (s32)(seq1 - seq2) > 0;
}


static inline int seadp_request_pcount( struct request_sk *rs)
{
	return rs->len / SEADP_MSS;
}

static inline u64 seadp_clock_ns(void)
{
	return local_clock();
}

static inline u64 seadp_clock_us(void)
{
	return div_u64(seadp_clock_ns(), NSEC_PER_USEC);
}

static inline void seadp_mstamp_refresh(struct seadp_sock *sh)
{
	u64 val = seadp_clock_us();

	if (val > sh->seadp_mstamp)
		sh->seadp_mstamp = val;
}
static inline void seadp_clear_xmit_timer(struct sock *sk, const int what)
{
	struct seadp_sock *sh = seadp_sk(sk);
	
	if (what == SPSK_TIME_RETRANS)
	{
		sh->spsk_pending = 0;
		del_timer(&sh->seadp_retransmit_timer);
	}
	

}

static inline void seadp_reset_xmit_timer(struct sock *sk, const int what, unsigned long when, const unsigned long max_when)
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct request_sk *target = list_first_entry(&sh->lhead, struct request_sk, list_node);	
	if(when > max_when)
	{
		printk("error: exceed SEADP_RTO_MAX\n");
		when = max_when;	
	}

	if (what == SPSK_TIME_RETRANS)
	{
		sh->start_seq = sh->snd_una;		//记录下当期定时器所管理的RTT窗口最初seq序号！！！！！
		//sh->start_seq = target->seq;
		sh->spsk_pending = what;
		sh->spsk_timeout = jiffies + when;
		mod_timer(&sh->seadp_retransmit_timer,  sh->spsk_timeout);
	}

}


static inline u32 __seadp_set_rto(const struct seadp_sock *sh)	
{
	return usecs_to_jiffies((sh->srtt_us >> 3) + sh->rttvar_us);	//usecs_to_jiffies把微秒转换成jiffies时钟中断次数！！
}


static inline unsigned int seadp_packets_in_flight(const struct seadp_sock *sh)
{
	return sh->packets_out - sh->lost_out + sh->retrans_out;
}

static inline u32 seadp_stamp_us_delta(u64 t1, u64 t0)
{
	return max_t(s64, t1 - t0, 0);
}
static inline u32 seadp_rto_min(struct sock *sk)
{
	const struct dst_entry *dst = __sk_dst_get(sk);
	u32 rto_min = SEADP_RTO_MIN;

	if (dst && dst_metric_locked(dst, RTAX_RTO_MIN))
		rto_min = dst_metric_rtt(dst, RTAX_RTO_MIN);
	return rto_min;
}
static inline u32 seadp_rto_min_us(struct sock *sk)
{
	return jiffies_to_usecs(seadp_rto_min(sk));
}
static inline s64 seadp_rto_delta_us( struct sock *sk)
{
	struct seadp_sock *sh = seadp_sk(sk);
	u32 rto = sh->spsk_rto;	
	u64 rto_time_stamp_us;
	struct request_sk *target;

	if(sh->lhead.next != &sh->lhead)
	{
		printk("%s\n", __func__);
		target = container_of(sh->lhead.next, struct request_sk, list_node);	
		rto_time_stamp_us = target->request_mstamp + jiffies_to_usecs(rto);
		return rto_time_stamp_us - sh->seadp_mstamp;	//seadp_mstatmp is now!!
	}

	return rto;
}

static inline int seadp_mss_to_mtu_v4(struct sock *sk)	//just on IPV4 stack with ipv4 hasing not optional header!!!!
{
	return SEADP_MSS + sizeof(seanet_hdr) + sizeof(struct iphdr);
}

static inline u32 seadp_min_rtt( struct seadp_sock *sh)
{
	return minmax_get(&sh->rtt_min);
}

static bool seadp_needs_internal_pacing(const struct sock *sk)
{
	return smp_load_acquire(&sk->sk_pacing_status) == SK_PACING_NEEDED;
}


static inline unsigned int seadp_cwnd_test(struct seadp_sock *sh)
{
	u32 in_flight, cwnd, halfcwnd;
	
	in_flight = seadp_packets_in_flight(sh);
	cwnd = sh->snd_cwnd;
	
	if (in_flight >= cwnd)
		return 0;

	return cwnd-in_flight;
	
}

static inline void show_usec(void)
{
	struct timeval tstart; 
	do_gettimeofday(&tstart);//获取时间
	printk("utime: %ld us\n", tstart.tv_usec);

}


#endif
