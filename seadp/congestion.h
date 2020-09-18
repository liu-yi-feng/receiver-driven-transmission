#ifndef __CONGESTION_H__
#define __CONGESTION_H__

#include <net/sock.h>
#include <linux/module.h>
#include <linux/init.h>
#include "main.h"
#define SEADP_CA_NAME_MAX	16

/* BBR congestion control block */
struct seadp_bbr {
	u32	min_rtt_us;	        /* min RTT in min_rtt_win_sec window */
	u32	min_rtt_stamp;	        /* timestamp of min_rtt_us */
	u32	probe_rtt_done_stamp;   /* end time for BBR_PROBE_RTT mode */
	struct minmax bw;	/* Max recent delivery rate in pkts/uS << 24 */
	u32	rtt_cnt;	    /* count of packet-timed rounds elapsed */
	u32     next_rtt_delivered; /* scb->tx.delivered at end of round */
	u64	cycle_mstamp;	     /* time of this cycle phase start */
	u32     mode:3,		     /* current bbr_mode in state machine */
		prev_ca_state:3,     /* CA state on previous ACK */
		packet_conservation:1,  /* use packet conservation? */
		restore_cwnd:1,	     /* decided to revert cwnd to old value */
		round_start:1,	     /* start of packet-timed tx->ack round? */
		tso_segs_goal:7,     /* segments we want in each skb we send */
		idle_restart:1,	     /* restarting after idle? */
		probe_rtt_round_done:1,  /* a BBR_PROBE_RTT round at 4 pkts? */
		unused:5,
		lt_is_sampling:1,    /* taking long-term ("LT") samples now? */
		lt_rtt_cnt:7,	     /* round trips in long-term interval */
		lt_use_bw:1;	     /* use lt_bw as our bw estimate? */
	u32	lt_bw;		     /* LT est delivery rate in pkts/uS << 24 */
	u32	lt_last_delivered;   /* LT intvl start: tp->delivered */
	u32	lt_last_stamp;	     /* LT intvl start: tp->delivered_mstamp */
	u32	lt_last_lost;	     /* LT intvl start: tp->lost */
	u32	pacing_gain:10,	/* current gain for setting pacing rate */
		cwnd_gain:10,	/* current gain for setting cwnd */
		full_bw_reached:1,   /* reached full bw in Startup? */
		full_bw_cnt:2,	/* number of rounds without large bw gains */
		cycle_idx:3,	/* current index in pacing_gain cycle array */
		has_seen_rtt:1, /* have we seen an RTT sample yet? */
		unused_b:5;
	u32	prior_cwnd;	/* prior cwnd upon entering loss recovery */
	u32	full_bw;	/* recent bw, to estimate if pipe is full */


	u64	ack_epoch_mstamp;	/* start of ACK sampling epoch */
	u16	extra_acked[2];		/* max excess data ACKed in epoch */
	u32	ack_epoch_acked:20,	/* packets (S)ACKed in sampling epoch */
		extra_acked_win_rtts:5,	/* age of extra_acked, in round trips */
		extra_acked_win_idx:1,	/* current index in extra_acked array */
		unused1:2,
		startup_ecn_rounds:2,	/* consecutive hi ECN STARTUP rounds */
		loss_in_cycle:1,	/* packet loss in this cycle? */
		ecn_in_cycle:1;		/* ECN in this cycle? */
};


enum seadp_ca_event {
	CA_EVENT_TX_START,	/* first transmit when no packets in flight */
	CA_EVENT_CWND_RESTART,	/* congestion window restart */
	CA_EVENT_COMPLETE_CWR,	/* end of congestion recovery */
	CA_EVENT_LOSS,		/* loss timeout */
	CA_EVENT_ECN_NO_CE,	/* ECT set, but not CE marked */
	CA_EVENT_ECN_IS_CE,	/* received CE marked IP packet */
};


enum seadp_ca_state {
	SEADP_CA_Open = 0,
#define TCPF_CA_Open	(1<<TCP_CA_Open)
	SEADP_CA_Disorder = 1,
#define TCPF_CA_Disorder (1<<TCP_CA_Disorder)
	SEADP_CA_CWR = 2,
#define TCPF_CA_CWR	(1<<TCP_CA_CWR)
	SEADP_CA_Recovery = 3,
#define TCPF_CA_Recovery (1<<TCP_CA_Recovery)
	SEADP_CA_Loss = 4
#define TCPF_CA_Loss	(1<<TCP_CA_Loss)
};


struct seadp_rate_sample {
	u64  prior_mstamp; /* starting timestamp for interval */
	u32  prior_delivered;	/* tp->delivered at "prior_mstamp" */
	s32  delivered;		/* number of packets delivered over interval */
	long interval_us;	/* time for tp->delivered to incr "delivered" */
	long rtt_us;		/* RTT of last (S)ACKed packet (or -1) */
	int  losses;		/* number of packets marked lost upon ACK */
	u32  acked_sacked;	/* number of packets newly (S)ACKed upon ACK */
	u32  prior_in_flight;	/* in flight before this ACK */
	bool is_app_limited;	/* is sample from packet with bubble in pipe? */
	bool is_retrans;	/* is sample from retransmission? */
};

union seadp_cc_info {
	//struct seadpvegas_info	vegas;
	//struct seadp_dctcp_info	dctcp;
	//struct seadp_bbr_info	bbr;
};

struct seadp_congestion_ops
{
	struct list_head	list;
	u32 key;
	u32 flags;
	/* initialize private data (optional) */
	void (*init)(struct sock *sk);
	/* cleanup private data  (optional) */
	void (*release)(struct sock *sk);

	/* return slow start threshold (required) */
	u32 (*ssthresh)(struct sock *sk);
	/* do new cwnd calculation (required) */
	void (*cong_avoid)(struct sock *sk, u32 ack, u32 acked);
	/* call before changing ca_state (optional) */
	void (*set_state)(struct sock *sk, u8 new_state);
	/* call when cwnd event occurs (optional) */
	void (*cwnd_event)(struct sock *sk, enum seadp_ca_event ev);
	/* call when ack arrives (optional) */
	void (*in_ack_event)(struct sock *sk, u32 flags);
	/* new value of cwnd after loss (required) */
	u32  (*undo_cwnd)(struct sock *sk);
	/* hook for packet ack accounting (optional) */
	void (*pkts_acked)(struct sock *sk, const struct ack_sample *sample);
	/* suggest number of segments for each skb to transmit (optional) */
	u32 (*tso_segs_goal)(struct sock *sk);
	/* returns the multiplier used in tcp_sndbuf_expand (optional) */
	u32 (*sndbuf_expand)(struct sock *sk);
	/* call when packets are delivered to update cwnd and pacing rate,
	 * after all the ca_state processing. (optional)
	 */
	void (*cong_control)(struct sock *sk, const struct seadp_rate_sample *rs);
	/* get info for inet_diag (optional) */
	size_t (*get_info)(struct sock *sk, u32 ext, int *attr,
			   union seadp_cc_info *info);

	char 		name[SEADP_CA_NAME_MAX];
	struct module 	*owner;
};

struct seadp_congestion_ops *seadp_ca_find_key(u32 key);
int seadp_register_congestion_control(struct seadp_congestion_ops *ca);	//注册
void seadp_unregister_congestion_control(struct seadp_congestion_ops *ca);
void seadp_assign_congestion_control_default(struct sock *sk, struct seadp_congestion_ops *ca);
void seadp_cleanup_congestion_control(struct sock *sk); //释放对拥塞控制块的引用


static inline void seadp_ca_event(struct sock *sk, const enum seadp_ca_event event)
{
	const struct seadp_sock *sh = seadp_sk(sk);

	if (sh->seadp_ca_ops->cwnd_event)
		sh->seadp_ca_ops->cwnd_event(sk, event);
}

static inline void *seadp_csk_ca(const struct sock *sk)
{
	return (void *)seadp_sk(sk)->seadp_ca_priv;
}


static inline void seadp_set_ca_state(struct sock *sk, const u8 ca_state)
{
	struct seadp_sock *sh = seadp_sk(sk);

	if (sh->seadp_ca_ops->set_state)
		sh->seadp_ca_ops->set_state(sk, ca_state);
	sh->sead_ca_state = ca_state;
}

#endif
