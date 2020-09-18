#include <linux/list.h>
#include <linux/module.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include "congestion.h"
#include "main.h"

static DEFINE_SPINLOCK(seadp_cong_list_lock);
static LIST_HEAD(seadp_cong_list);

/* Scale factor for rate in pkt/uSec unit to avoid truncation in bandwidth
 * estimation. The rate unit ~= (1500 bytes / 1 usec / 2^24) ~= 715 bps.
 * This handles bandwidths from 0.06pps (715bps) to 256Mpps (3Tbps) in a u32.
 * Since the minimum window is >=4 packets, the lower bound isn't
 * an issue. The upper bound isn't an issue with existing technologies.
 */


#define BW_SCALE 24
#define BW_UNIT (1 << BW_SCALE)


#define BBR_SCALE 8	// scaling factor for fractions in BBR (e.g. gains)	??????
#define BBR_UNIT (1 << BBR_SCALE)

/* BBR has the following modes for deciding how fast to send: */
enum bbr_mode {
	BBR_STARTUP,	/* ramp up sending rate rapidly to fill pipe */
	BBR_DRAIN,	/* drain any queue created during startup */
	BBR_PROBE_BW,	/* discover, share bw: pace around estimated bw */
	BBR_PROBE_RTT,	/* cut inflight to min to probe min_rtt */
};


#define CYCLE_LEN	8	/* number of phases in a pacing gain cycle */

/* Window length of bw filter (in rounds): */
static const int bbr_bw_rtts = CYCLE_LEN + 2;	//125

/* Window length of min_rtt filter (in sec): */
static const u32 bbr_min_rtt_win_sec = 10;	//127

/* Minimum time (in ms) spent at bbr_cwnd_min_target in BBR_PROBE_RTT mode: */
static const u32 bbr_probe_rtt_mode_ms = 200;

/* Skip TSO below the following bandwidth (bits/sec): */
static const int bbr_min_tso_rate = 1200000;


/* We use a high_gain value of 2/ln(2) because it's the smallest pacing gain
 * that will allow a smoothly increasing pacing rate that will double each RTT
 * and send the same number of packets per RTT that an un-paced, slow-starting
 * Reno or CUBIC flow would:
 */
static const int bbr_high_gain  = BBR_UNIT * 2885 / 1000 + 1;	//138
/* The pacing gain of 1/high_gain in BBR_DRAIN is calculated to typically drain
 * the queue created in BBR_STARTUP in a single round:
 */
static const int bbr_drain_gain = BBR_UNIT * 1000 / 2885;	//142

/* The gain for deriving steady-state cwnd tolerates delayed/stretched ACKs: */
static const int bbr_cwnd_gain  = BBR_UNIT *2;	//144
/* The pacing_gain values for the PROBE_BW gain cycle, to discover/share bw: */
static const int bbr_pacing_gain[] =	//145 
{
	BBR_UNIT * 5 / 4,	/* probe for more available bw */
	BBR_UNIT * 3 / 4,	/* drain queue and/or yield bw to other flows */
	BBR_UNIT, BBR_UNIT, BBR_UNIT,	/* cruise at 1.0*bw to utilize pipe, */
	BBR_UNIT, BBR_UNIT, BBR_UNIT	/* without creating excess queue... */
};


/* Randomize the starting gain cycling phase over N phases: */
static const u32 bbr_cycle_rand = 7;	//153

/* Try to keep at least this many packets in flight, if things go smoothly. For
 * smooth functioning, a sliding window protocol ACKing every other packet
 * needs at least 4 packets in flight:
 */
static const u32 bbr_cwnd_min_target = 4;	//159


/* To estimate if BBR_STARTUP mode (i.e. high_gain) has filled pipe... */
/* If bw has increased significantly (1.25x), there may be more bw available: */
static const u32 bbr_full_bw_thresh = BBR_UNIT * 5 / 4;	//163

/* But after 3 rounds w/o significant bw growth, estimate pipe is full: */
static const u32 bbr_full_bw_cnt = 3;		//165

/* "long-term" ("LT") bandwidth estimator parameters... */
/* The minimum number of rounds in an LT bw sampling interval: */
static const u32 bbr_lt_intvl_min_rtts = 4;	//169

/* If lost/delivered ratio > 20%, interval is "lossy" and we may be policed: */
static const u32 bbr_lt_loss_thresh = 50;	//170
/* If 2 intervals have a bw ratio <= 1/8, their bw is "consistent": */
static const u32 bbr_lt_bw_ratio = BBR_UNIT / 8;	//173

/* If 2 intervals have a bw diff <= 4 Kbit/sec their bw is "consistent": */
static const u32 bbr_lt_bw_diff = 4000 / 8;	//175

/* If we estimate we're policed, use lt_bw for this many round trips: */
static const u32 bbr_lt_bw_max_rtts = 48;	//177


/* Gain factor for adding extra_acked to target cwnd: */
static const int bbr_extra_acked_gain = BBR_UNIT;
/* Window length of extra_acked window. Max allowed val is 31. */
static const u32 bbr_extra_acked_win_rtts = 10;
/* Max allowed val for ack_epoch_acked, after which sampling epoch is reset */
static const u32 bbr_ack_epoch_acked_reset_thresh = 1U << 20;
/* Time period for clamping cwnd increment due to ack aggregation */
static const u32 bbr_extra_acked_max_us = 100 * 1000;




/* Do we estimate that STARTUP filled the pipe? */
static bool bbr_full_bw_reached(const struct sock *sk)	//180
{
	const struct seadp_bbr *bbr = seadp_csk_ca(sk);

	return bbr->full_bw_reached;
}

/* Return the windowed max recent bandwidth sample, in pkts/uS << BW_SCALE. */
static u32 bbr_max_bw(const struct sock *sk)	//188
{
	struct seadp_bbr *bbr = seadp_csk_ca(sk);

	return minmax_get(&bbr->bw);
}

/* Return the estimated bandwidth of the path, in pkts/uS << BW_SCALE. */
static u32 bbr_bw(const struct sock *sk)	//196
{
	struct seadp_bbr *bbr = seadp_csk_ca(sk);

	return bbr->lt_use_bw ? bbr->lt_bw : bbr_max_bw(sk);
}



/* Return maximum extra acked in past k-2k round trips,
 * where k = bbr_extra_acked_win_rtts.
 */
static u16 bbr_extra_acked(const struct sock *sk)
{
	struct seadp_bbr *bbr = seadp_csk_ca(sk);

	return max(bbr->extra_acked[0], bbr->extra_acked[1]);
}




/* Return rate in bytes per second, optionally with a gain.
 * The order here is chosen carefully to avoid overflow of u64. This should
 * work for input rates of up to 2.9Tbit/sec and gain of 2.89x.
 */
static u64 bbr_rate_bytes_per_sec(struct sock *sk, u64 rate, int gain)		//207
{
	rate *= seadp_mss_to_mtu_v4(sk);	//just on IPV4 stack with ipv4 hasing not optional header!!!!
	rate *= gain;
	rate >>= BBR_SCALE;
	rate *= USEC_PER_SEC;
	return rate >> BW_SCALE;
}


/* Convert a BBR bw and gain factor to a pacing rate in bytes per second. */
static u32 bbr_bw_to_pacing_rate(struct sock *sk, u32 bw, int gain)	//217
{
	u64 rate = bw;

	rate = bbr_rate_bytes_per_sec(sk, rate, gain);
	rate = min_t(u64, rate, sk->sk_max_pacing_rate);
	return rate;
}

/* Initialize pacing rate to: high_gain * init_cwnd / RTT. */
static void bbr_init_pacing_rate_from_rtt(struct sock *sk)	//227
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct seadp_bbr *bbr = seadp_csk_ca(sk);
	u64 bw;
	u32 rtt_us;

	if (sh->srtt_us) {		/* any RTT sample yet? */
		rtt_us = max(sh->srtt_us >> 3, 1U);
		bbr->has_seen_rtt = 1;
	} else {			 /* no RTT sample yet */
		rtt_us = USEC_PER_MSEC;	 /* use nominal default RTT */
	}
	bw = (u64)sh->snd_cwnd * BW_UNIT;
	do_div(bw, rtt_us);
	sk->sk_pacing_rate = bbr_bw_to_pacing_rate(sk, bw, bbr_high_gain);
}

/* Pace using current bw estimate and a gain factor. In order to help drive the
 * network toward lower queues while maintaining high utilization and low
 * latency, the average pacing rate aims to be slightly (~1%) lower than the
 * estimated bandwidth. This is an important aspect of the design. In this
 * implementation this slightly lower pacing rate is achieved implicitly by not
 * including link-layer headers in the packet size used for the pacing rate.
 */
static void bbr_set_pacing_rate(struct sock *sk, u32 bw, int gain)	//252
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct seadp_bbr *bbr = seadp_csk_ca(sk);
	u32 rate = bbr_bw_to_pacing_rate(sk, bw, gain);

	if(sh->rtt_sample_times <20)
		{
			printk("%s: sk->sk_pacing_rate: %lu\n", __func__, rate);
		}


	if (unlikely(!bbr->has_seen_rtt && sh->srtt_us))
		bbr_init_pacing_rate_from_rtt(sk);
	if (bbr_full_bw_reached(sk) || rate > sk->sk_pacing_rate)
	{
		sk->sk_pacing_rate = rate;
//test
		if(sh->rtt_sample_times <20)
		{
			printk("%s: sk->sk_pacing_rate: %ld\n", __func__, sk->sk_pacing_rate);
		}
			
	}
}


/* Save "last known good" cwnd so we can restore it after losses or PROBE_RTT */
static void bbr_save_cwnd(struct sock *sk)	//284
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct seadp_bbr *bbr = seadp_csk_ca(sk);

	if (bbr->prev_ca_state < SEADP_CA_Recovery && bbr->mode != BBR_PROBE_RTT)
		bbr->prior_cwnd = sh->snd_cwnd;  /* this cwnd is good enough */
	else  /* loss recovery or BBR_PROBE_RTT have temporarily cut cwnd */
		bbr->prior_cwnd = max(bbr->prior_cwnd, sh->snd_cwnd);
}


/* Find target cwnd. Right-size the cwnd based on min RTT and the
 * estimated bottleneck bandwidth:
 *
 * cwnd = bw * min_rtt * gain = BDP * gain
 *
 * The key factor, gain, controls the amount of queue. While a small gain
 * builds a smaller queue, it becomes more vulnerable to noise in RTT
 * measurements (e.g., delayed ACKs or other ACK compression effects). This
 * noise may cause BBR to under-estimate the rate.
 *
 * To achieve full performance in high-speed paths, we budget enough cwnd to
 * fit full-sized skbs in-flight on both end hosts to fully utilize the path:
 *   - one skb in sending host Qdisc,
 *   - one skb in sending host TSO/GSO engine
 *   - one skb being received by receiver host LRO/GRO/delayed-ACK engine
 * Don't worry, at low rates (bbr_min_tso_rate) this won't bloat cwnd because
 * in such cases tso_segs_goal is 1. The minimum cwnd is 4 packets,
 * which allows 2 outstanding 2-packet sequences, to try to keep pipe
 * full even with ACK-every-other-packet delayed ACKs.
 */
static u32 bbr_target_cwnd(struct sock *sk, u32 bw, int gain)	//330
{
	struct seadp_bbr *bbr = seadp_csk_ca(sk);
	u32 cwnd;
	u64 w;

	/* If we've never had a valid RTT sample, cap cwnd at the initial
	 * default. This should only happen when the connection is not using TCP
	 * timestamps and has retransmitted all of the SYN/SYNACK/data packets
	 * ACKed so far. In this case, an RTO can cut cwnd to 1, in which
	 * case we need to slow-start up toward something safe: TCP_INIT_CWND.
	 */
	if (unlikely(bbr->min_rtt_us == ~0U))	 /* no valid RTT samples yet? */
		return SEADP_INIT_CWND;  /* be safe: cap at default initial cwnd*/

	w = (u64)bw * bbr->min_rtt_us;

	

	/* Apply a gain to the given value, then remove the BW_SCALE shift. */
	cwnd = (u32)(((u64)((w * gain) >> BBR_SCALE) + BW_UNIT - 1) / BW_UNIT);
	////if(cwnd==0) printk("1111111111, w: %llu, gain: %d\n", w, gain);
	/* Allow enough full-sized skbs in flight to utilize end systems. */
	cwnd += 3 * bbr->tso_segs_goal;

	/* Reduce delayed ACKs by rounding up cwnd to the next even number. */
	//cwnd = (cwnd + 1) & ~1U;				//not used Temporarily!!!!2020.2.5

	/* Ensure gain cycling gets inflight above BDP even for small BDPs. */
	if (bbr->mode == BBR_PROBE_BW && gain > BBR_UNIT)
		cwnd += 2;
	
	

	return cwnd;
}


/* An optimization in BBR to reduce losses: On the first round of recovery, we
 * follow the packet conservation principle: send P packets per P packets acked.
 * After that, we slow-start and send at most 2*P packets per P packets acked.
 * After recovery finishes, or upon undo, we restore the cwnd we had when
 * recovery started (capped by the target cwnd based on estimated BDP).
 *
 * TODO(ycheng/ncardwell): implement a rate-based approach.
 */
static bool bbr_set_cwnd_to_recover_or_restore(struct sock *sk, const struct seadp_rate_sample *rs, u32 acked, u32 *new_cwnd)	//371
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct seadp_bbr *bbr = seadp_csk_ca(sk);
	u8 prev_state = bbr->prev_ca_state, state = inet_csk(sk)->icsk_ca_state;
	u32 cwnd = sh->snd_cwnd;

	/* An ACK for P pkts should release at most 2*P packets. We do this
	 * in two steps. First, here we deduct the number of lost packets.
	 * Then, in bbr_set_cwnd() we slow start up toward the target cwnd.
	 */
	if (rs->losses > 0)
		cwnd = max_t(s32, cwnd - rs->losses, 1);

	if (state == SEADP_CA_Recovery && prev_state != SEADP_CA_Recovery) {
		/* Starting 1st round of Recovery, so do packet conservation. */
		bbr->packet_conservation = 1;
		bbr->next_rtt_delivered = sh->delivered;  /* start round now */
		/* Cut unused cwnd from app behavior, TSQ, or TSO deferral: */
		cwnd = seadp_packets_in_flight(sh) + acked;
	} else if (prev_state >= SEADP_CA_Recovery && state < SEADP_CA_Recovery) {
		/* Exiting loss recovery; restore cwnd saved before recovery. */
		bbr->restore_cwnd = 1;
		bbr->packet_conservation = 0;
	}
	bbr->prev_ca_state = state;

	if (bbr->restore_cwnd) {
		/* Restore cwnd after exiting loss recovery or PROBE_RTT. */
		cwnd = max(cwnd, bbr->prior_cwnd);
		bbr->restore_cwnd = 0;
	}

	if (bbr->packet_conservation) {
		*new_cwnd = max(cwnd, seadp_packets_in_flight(sh) + acked);
		return true;	/* yes, using packet conservation */
	}
	*new_cwnd = cwnd;
	return false;
}



/* Find the cwnd increment based on estimate of ack aggregation */
static u32 bbr_ack_aggregation_cwnd(struct sock *sk)
{
	struct seadp_bbr *bbr = seadp_csk_ca(sk);
	u32 max_aggr_cwnd, aggr_cwnd = 0;

	if (bbr_extra_acked_gain && bbr_full_bw_reached(sk) )
	{
		max_aggr_cwnd = ((u64)bbr_bw(sk) * bbr_extra_acked_max_us) / BW_UNIT;
		aggr_cwnd = (bbr_extra_acked_gain * bbr_extra_acked(sk)) >> BBR_SCALE;
		aggr_cwnd = min(aggr_cwnd, max_aggr_cwnd);
	}

	return aggr_cwnd;
}


/* Slow-start up toward target cwnd (if bw estimate is growing, or packet loss
 * has drawn us down below target), or snap down to target if we're above it.
 */
static void bbr_set_cwnd(struct sock *sk, const struct seadp_rate_sample *rs, u32 acked, u32 bw, int gain)	//416
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct seadp_bbr *bbr = seadp_csk_ca(sk);
	u32 cwnd = 0, target_cwnd = 0;

	if (!acked)
		return;

	if (bbr_set_cwnd_to_recover_or_restore(sk, rs, acked, &cwnd))
	{
		printk("%s: bbr_set_cwnd_to_recover_or_restore", __func__);	
		goto done;
	}
	/* If we're below target cwnd, slow start cwnd toward target cwnd. */
	target_cwnd = bbr_target_cwnd(sk, bw, gain);
	
	//target_cwnd += 10;

	target_cwnd += bbr_ack_aggregation_cwnd(sk);
	if(bbr->mode == BBR_PROBE_BW)
	{
		//target_cwnd += 500;
		//target_cwnd *= 2;	
	}
		
	if (bbr_full_bw_reached(sk))  /* only cut cwnd if we filled the pipe */
		cwnd = min(cwnd + acked, target_cwnd);
	else if (cwnd < target_cwnd || sh->delivered < SEADP_INIT_CWND)
		cwnd = cwnd + acked;


	///if(cwnd < 4) printk("cwnd: %d, target_cwnd: %d, bw: %d, cwnd_gain: %d, bbr_cwnd_gain: %d\n", cwnd, target_cwnd, bw, gain, bbr_cwnd_gain);
	cwnd = max(cwnd, bbr_cwnd_min_target);

done:
	sh->snd_cwnd = min(cwnd, sh->snd_cwnd_clamp);	/* apply global cap */
	
	if(sh->rtt_sample_times <20)
	{
		printk("%s: target_cwnd: %d, cwnd: %u, sh->snd_cwnd: %d, sk->sk_pacing_rate: %ld, bw: %u, in_flight: %u, sh->delivered: %u\n", __func__, target_cwnd, cwnd, sh->snd_cwnd, sk->sk_pacing_rate, bbr_bw(sk), seadp_packets_in_flight(sh), sh->delivered);
	}

	if (bbr->mode == BBR_PROBE_RTT)  /* drain queue, refresh min_rtt */
	{
		//printk("%s: ProbeRTT cwnd set\n", __func__);	
		sh->snd_cwnd = min(sh->snd_cwnd, bbr_cwnd_min_target);
	}
}

/* End cycle phase if it's time and/or we hit the phase's in-flight target. */

//each phase lasts a RTprop, look bbr paper!!!!!!!!!!!!!
static bool bbr_is_next_cycle_phase(struct sock *sk, const struct seadp_rate_sample *rs)	//444
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct seadp_bbr *bbr = seadp_csk_ca(sk);
	bool is_full_length = seadp_stamp_us_delta(sh->delivered_mstamp, bbr->cycle_mstamp) > bbr->min_rtt_us;	
	u32 inflight, bw;

	/* The pacing_gain of 1.0 paces at the estimated bw to try to fully
	 * use the pipe without increasing the queue.
	 */
	if (bbr->pacing_gain == BBR_UNIT)
		return is_full_length;		/* just use wall clock time */

	inflight = rs->prior_in_flight;  /* what was in-flight before ACK? */
	bw = bbr_max_bw(sk);

	/* A pacing_gain > 1.0 probes for bw by trying to raise inflight to at
	 * least pacing_gain*BDP; this may take more than min_rtt if min_rtt is
	 * small (e.g. on a LAN). We do not persist if packets are lost, since
	 * a path with small buffers may not hold that much.
	 */
	if (bbr->pacing_gain > BBR_UNIT)
	{
		//if(is_full_length && (rs->losses ||  inflight >= bbr_target_cwnd(sk, bw, bbr->pacing_gain))) printk("1\n");
		/* perhaps pacing_gain*BDP won't fit */
		return is_full_length && (rs->losses ||  inflight >= bbr_target_cwnd(sk, bw, bbr->pacing_gain));
	}
	/* A pacing_gain < 1.0 tries to drain extra queue we added if bw
	 * probing didn't find more bw. If inflight falls to match BDP then we
	 * estimate queue is drained; persisting would underutilize the pipe.
	 */
	
	//return  inflight <= bbr_target_cwnd(sk, bw, BBR_UNIT);
	//return is_full_length && inflight <= bbr_target_cwnd(sk, bw, BBR_UNIT);
	return inflight <= bbr_target_cwnd(sk, bw, BBR_UNIT);
}




static void bbr_advance_cycle_phase(struct sock *sk)	//481
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct seadp_bbr *bbr = seadp_csk_ca(sk);

	bbr->cycle_idx = (bbr->cycle_idx + 1) & (CYCLE_LEN - 1);
	bbr->cycle_mstamp = sh->delivered_mstamp;
	bbr->pacing_gain = bbr->lt_use_bw ? BBR_UNIT : bbr_pacing_gain[bbr->cycle_idx];
}

/* Gain cycling: cycle pacing gain to converge to fair share of available bw. */
static void bbr_update_cycle_phase(struct sock *sk, const struct seadp_rate_sample *rs)		//492
{
	struct seadp_bbr *bbr = seadp_csk_ca(sk);

	if (bbr->mode == BBR_PROBE_BW && bbr_is_next_cycle_phase(sk, rs))
		bbr_advance_cycle_phase(sk);
}

static void bbr_reset_startup_mode(struct sock *sk)	//502
{
	struct seadp_bbr *bbr = seadp_csk_ca(sk);

	bbr->mode = BBR_STARTUP;
	bbr->pacing_gain = bbr_high_gain;
	bbr->cwnd_gain	 = bbr_high_gain;
}


static void bbr_reset_probe_bw_mode(struct sock *sk)	//511
{
	struct seadp_bbr *bbr = seadp_csk_ca(sk);

	bbr->mode = BBR_PROBE_BW;	//bandwidth probe state!!
	bbr->pacing_gain = BBR_UNIT;
	bbr->cwnd_gain = bbr_cwnd_gain;
	bbr->cycle_idx = CYCLE_LEN - 1 - prandom_u32_max(bbr_cycle_rand);
	bbr_advance_cycle_phase(sk);	/* flip to next phase of gain cycle */
}

static void bbr_reset_mode(struct sock *sk)	//522
{
	if (!bbr_full_bw_reached(sk))
		bbr_reset_startup_mode(sk);
	else
		bbr_reset_probe_bw_mode(sk);
}

/* Start a new long-term sampling interval. */
static void bbr_reset_lt_bw_sampling_interval(struct sock *sk)	//531
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct seadp_bbr *bbr = seadp_csk_ca(sk);

	bbr->lt_last_stamp = div_u64(sh->delivered_mstamp, USEC_PER_MSEC);
	bbr->lt_last_delivered = sh->delivered;
	bbr->lt_last_lost = sh->lost;
	bbr->lt_rtt_cnt = 0;
}



/* Completely reset long-term bandwidth sampling. */
static void bbr_reset_lt_bw_sampling(struct sock *sk)	//543
{
	struct seadp_bbr *bbr = seadp_csk_ca(sk);

	bbr->lt_bw = 0;
	bbr->lt_use_bw = 0;
	bbr->lt_is_sampling = false;
	bbr_reset_lt_bw_sampling_interval(sk);
}

static void seadp_bbr_init(struct sock *sk)
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct seadp_bbr *bbr = seadp_csk_ca(sk);

	bbr->prior_cwnd = 0;
	bbr->tso_segs_goal = 0;	 /* default segs per skb until first ACK */
	bbr->rtt_cnt = 0;
	bbr->next_rtt_delivered = 0;
	bbr->prev_ca_state = TCP_CA_Open;
	bbr->packet_conservation = 0;

	bbr->probe_rtt_done_stamp = 0;
	bbr->probe_rtt_round_done = 0;
	bbr->min_rtt_us = seadp_min_rtt(sh);
	bbr->min_rtt_stamp = (u32)jiffies;

	minmax_reset(&bbr->bw, bbr->rtt_cnt, 0);  /* init max bw to 0 */

	bbr->has_seen_rtt = 0;
	bbr_init_pacing_rate_from_rtt(sk);

	bbr->restore_cwnd = 0;
	bbr->round_start = 0;
	bbr->idle_restart = 0;
	bbr->full_bw_reached = 0;
	bbr->full_bw = 0;
	bbr->full_bw_cnt = 0;
	bbr->cycle_mstamp = 0;
	bbr->cycle_idx = 0;
	bbr_reset_lt_bw_sampling(sk);
	bbr_reset_startup_mode(sk);


	bbr->ack_epoch_mstamp = sh->seadp_mstamp;
	bbr->ack_epoch_acked = 0;
	bbr->extra_acked_win_rtts = 0;
	bbr->extra_acked_win_idx = 0;
	bbr->extra_acked[0] = 0;
	bbr->extra_acked[1] = 0;

	cmpxchg(&sk->sk_pacing_status, SK_PACING_NONE, SK_PACING_NEEDED);

	printk("%s\n",__func__);	
}

/* Long-term bw sampling interval is done. Estimate whether we're policed. */
static void bbr_lt_bw_interval_done(struct sock *sk, u32 bw)	//554
{
	struct seadp_bbr *bbr = seadp_csk_ca(sk);
	u32 diff;

	if (bbr->lt_bw) 
	{	  /* do we have bw from a previous interval? */
		/* Is new bw close to the lt_bw from the previous interval? */
		diff = abs(bw - bbr->lt_bw);
		if ((diff * BBR_UNIT <= bbr_lt_bw_ratio * bbr->lt_bw) || (bbr_rate_bytes_per_sec(sk, diff, BBR_UNIT) <= bbr_lt_bw_diff)) 
		{
			/* All criteria are met; estimate we're policed. */
			bbr->lt_bw = (bw + bbr->lt_bw) >> 1;  /* avg 2 intvls */
			bbr->lt_use_bw = 1;
			bbr->pacing_gain = BBR_UNIT;  /* try to avoid drops */
			bbr->lt_rtt_cnt = 0;
			return;
		}
	}
	bbr->lt_bw = bw;
	bbr_reset_lt_bw_sampling_interval(sk);
}


/* Token-bucket traffic policers are common (see "An Internet-Wide Analysis of
 * Traffic Policing", SIGCOMM 2016). BBR detects token-bucket policers and
 * explicitly models their policed rate, to reduce unnecessary losses. We
 * estimate that we're policed if we see 2 consecutive sampling intervals with
 * consistent throughput and high packet loss. If we think we're being policed,
 * set lt_bw to the "long-term" average delivery rate from those 2 intervals.
 */
static void bbr_lt_bw_sampling(struct sock *sk, const struct seadp_rate_sample *rs)	//584
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct seadp_bbr *bbr = seadp_csk_ca(sk);
	u32 lost, delivered;
	u64 bw;
	u32 t;

	if (bbr->lt_use_bw) {	/* already using long-term rate, lt_bw? */
		if (bbr->mode == BBR_PROBE_BW && bbr->round_start && ++bbr->lt_rtt_cnt >= bbr_lt_bw_max_rtts) 
		{
			bbr_reset_lt_bw_sampling(sk);    /* stop using lt_bw */
			bbr_reset_probe_bw_mode(sk);  /* restart gain cycling */
		}
		return;
	}

	/* Wait for the first loss before sampling, to let the policer exhaust
	 * its tokens and estimate the steady-state rate allowed by the policer.
	 * Starting samples earlier includes bursts that over-estimate the bw.
	 */
	if (!bbr->lt_is_sampling) 
	{
		if (!rs->losses)	return;
		bbr_reset_lt_bw_sampling_interval(sk);
		bbr->lt_is_sampling = true;
	}

	/* To avoid underestimates, reset sampling if we run out of data. */
	if (rs->is_app_limited) 
	{
		bbr_reset_lt_bw_sampling(sk);
		return;
	}

	if (bbr->round_start)
		bbr->lt_rtt_cnt++;	/* count round trips in this interval */
	if (bbr->lt_rtt_cnt < bbr_lt_intvl_min_rtts)
		return;		/* sampling interval needs to be longer */
	if (bbr->lt_rtt_cnt > 4 * bbr_lt_intvl_min_rtts) {
		bbr_reset_lt_bw_sampling(sk);  /* interval is too long */
		return;
	}

	/* End sampling interval when a packet is lost, so we estimate the
	 * policer tokens were exhausted. Stopping the sampling before the
	 * tokens are exhausted under-estimates the policed rate.
	 */
	if (!rs->losses)
		return;

	/* Calculate packets lost and delivered in sampling interval. */
	lost = sh->lost - bbr->lt_last_lost;
	delivered = sh->delivered - bbr->lt_last_delivered;
	/* Is loss rate (lost/delivered) >= lt_loss_thresh? If not, wait. */
	if (!delivered || (lost << BBR_SCALE) < bbr_lt_loss_thresh * delivered)
		return;

	/* Find average delivery rate in this sampling interval. */
	t = div_u64(sh->delivered_mstamp, USEC_PER_MSEC) - bbr->lt_last_stamp;
	if ((s32)t < 1)
		return;		/* interval is less than one ms, so wait */
	/* Check if can multiply without overflow */
	if (t >= ~0U / USEC_PER_MSEC) {
		bbr_reset_lt_bw_sampling(sk);  /* interval too long; reset */
		return;
	}
	t *= USEC_PER_MSEC;
	bw = (u64)delivered * BW_UNIT;
	do_div(bw, t);
	bbr_lt_bw_interval_done(sk, bw);
}




/* Estimate the bandwidth based on how fast packets are delivered */
static void bbr_update_bw(struct sock *sk, const struct seadp_rate_sample *rs)	//657
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct seadp_bbr *bbr = seadp_csk_ca(sk);
	u64 bw;

	bbr->round_start = 0;
	if (rs->delivered < 0 || rs->interval_us <= 0)		//不是一次有效的网络状况采样！！！直接返回
		return; /* Not a valid observation */

	/* See if we've reached the next RTT */
	if (!before(rs->prior_delivered, bbr->next_rtt_delivered))	//??????????????? 
	{
		bbr->next_rtt_delivered = sh->delivered;
		bbr->rtt_cnt++;
		bbr->round_start = 1;
		bbr->packet_conservation = 0;
	}

	bbr_lt_bw_sampling(sk, rs);

	/* Divide delivered by the interval to find a (lower bound) bottleneck
	 * bandwidth sample. Delivered is in packets and interval_us in uS and
	 * ratio will be <<1 for most connections. So delivered is first scaled.
	 */
	bw = (u64)rs->delivered * BW_UNIT;
	do_div(bw, rs->interval_us);

	/* If this sample is application-limited, it is likely to have a very
	 * low delivered count that represents application behavior rather than
	 * the available network rate. Such a sample could drag down estimated
	 * bw, causing needless slow-down. Thus, to continue to send at the
	 * last measured network rate, we filter out app-limited samples unless
	 * they describe the path bw at least as well as our bw model.
	 *
	 * So the goal during app-limited phase is to proceed with the best
	 * network rate no matter how long. We automatically leave this
	 * phase when app writes faster than the network can deliver :)
	 */
	if (!rs->is_app_limited || bw >= bbr_max_bw(sk)) 
	{
		/* Incorporate new sample into our max bw filter. */
		minmax_running_max(&bbr->bw, bbr_bw_rtts, bbr->rtt_cnt, bw);
	}
}


/* Estimate when the pipe is full, using the change in delivery rate: BBR
 * estimates that STARTUP filled the pipe if the estimated bw hasn't changed by
 * at least bbr_full_bw_thresh (25%) after bbr_full_bw_cnt (3) non-app-limited
 * rounds. Why 3 rounds: 1: rwin autotuning grows the rwin, 2: we fill the
 * higher rwin, 3: we get higher delivery rate samples. Or transient
 * cross-traffic or radio noise can go away. CUBIC Hystart shares a similar
 * design goal, but uses delay and inter-ACK spacing instead of bandwidth.
 */
static void bbr_check_full_bw_reached(struct sock *sk, const struct seadp_rate_sample *rs)	//709
{
	struct seadp_bbr *bbr = seadp_csk_ca(sk);
	u32 bw_thresh;

	if (bbr_full_bw_reached(sk) || !bbr->round_start || rs->is_app_limited)
		return;

	bw_thresh = (u64)bbr->full_bw * bbr_full_bw_thresh >> BBR_SCALE;
	if (bbr_max_bw(sk) >= bw_thresh) {
		bbr->full_bw = bbr_max_bw(sk);
		bbr->full_bw_cnt = 0;
		return;
	}
	++bbr->full_bw_cnt;
	bbr->full_bw_reached = bbr->full_bw_cnt >= bbr_full_bw_cnt;
}

/* The goal of PROBE_RTT mode is to have BBR flows cooperatively and
 * periodically drain the bottleneck queue, to converge to measure the true
 * min_rtt (unloaded propagation delay). This allows the flows to keep queues
 * small (reducing queuing delay and packet loss) and achieve fairness among
 * BBR flows.
 *
 * The min_rtt filter window is 10 seconds. When the min_rtt estimate expires,
 * we enter PROBE_RTT mode and cap the cwnd at bbr_cwnd_min_target=4 packets.
 * After at least bbr_probe_rtt_mode_ms=200ms and at least one packet-timed
 * round trip elapsed with that flight size <= 4, we leave PROBE_RTT mode and
 * re-enter the previous mode. BBR uses 200ms to approximately bound the
 * performance penalty of PROBE_RTT's cwnd capping to roughly 2% (200ms/10s).
 *
 * Note that flows need only pay 2% if they are busy sending over the last 10
 * seconds. Interactive applications (e.g., Web, RPCs, video chunks) often have
 * natural silences or low-rate periods within 10 seconds where the rate is low
 * enough for long enough to drain its queue in the bottleneck. We pick up
 * these min RTT measurements opportunistically with our min_rtt filter. :-)
 */
static void bbr_update_min_rtt(struct sock *sk, const struct seadp_rate_sample *rs)	//763
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct seadp_bbr *bbr = seadp_csk_ca(sk);
	bool filter_expired;

	/* Track min RTT seen in the min_rtt_win_sec filter window: */
	filter_expired = after((u32)jiffies, bbr->min_rtt_stamp + bbr_min_rtt_win_sec * HZ);

	if (rs->rtt_us >= 0 && (rs->rtt_us <= bbr->min_rtt_us || filter_expired)) 
	{
		if(rs->rtt_us > bbr->min_rtt_us) printk("up\n");
		
		bbr->min_rtt_us = rs->rtt_us;
		bbr->min_rtt_stamp = (u32)jiffies;
		printk("%s: update bbr->min_rtt_us: %u, sh->delivered: %u\n", __func__, bbr->min_rtt_us, sh->delivered);



	}

	if (bbr_probe_rtt_mode_ms > 0 && filter_expired && !bbr->idle_restart && bbr->mode != BBR_PROBE_RTT) 
	{
		
		printk("%s: ProbeBW->ProbeRTT, sh->snd_cwnd: %d, sk->sk_pacing_rate: %d\n\n", __func__, sh->snd_cwnd, sk->sk_pacing_rate);
	
		bbr->mode = BBR_PROBE_RTT;  /* dip, drain queue */
		bbr->pacing_gain = BBR_UNIT;
		bbr->cwnd_gain = BBR_UNIT;
		bbr_save_cwnd(sk);  /* note cwnd so we can restore it */
		bbr->probe_rtt_done_stamp = 0;
	}

	if (bbr->mode == BBR_PROBE_RTT) 
	{
		/* Ignore low rate samples during this mode. */
		sh->app_limited = (sh->delivered + seadp_packets_in_flight(sh)) ? : 1;
		/* Maintain min packets in flight for max(200 ms, 1 round). */
		if (!bbr->probe_rtt_done_stamp && seadp_packets_in_flight(sh) <= bbr_cwnd_min_target) 
		{
			bbr->probe_rtt_done_stamp = (u32)jiffies + msecs_to_jiffies(bbr_probe_rtt_mode_ms);
			bbr->probe_rtt_round_done = 0;
			bbr->next_rtt_delivered = sh->delivered;
		} 
		else if (bbr->probe_rtt_done_stamp) 
		{
			if (bbr->round_start)
				bbr->probe_rtt_round_done = 1;
			if (bbr->probe_rtt_round_done && after((u32)jiffies, bbr->probe_rtt_done_stamp)) 
			{
				bbr->min_rtt_stamp = (u32)jiffies;
				bbr->restore_cwnd = 1;  /* snap to prior_cwnd */
				bbr_reset_mode(sk);
			}
		}
	}
	/* Restart after idle ends only once we process a new S/ACK for data */
	if (rs->delivered > 0)
		bbr->idle_restart = 0;
}



/* If pipe is probably full, drain the queue and then enter steady-state. */
static void bbr_check_drain(struct sock *sk, const struct seadp_rate_sample *rs)
{
	struct seadp_bbr *bbr = seadp_csk_ca(sk);
	struct seadp_sock *sh = seadp_sk(sk);
	
	if (bbr->mode == BBR_STARTUP && bbr_full_bw_reached(sk)) 
	{
		printk("%s: STARTUP->DRAIN, sh->snd_cwnd: %d, sk->sk_pacing_rate: %d, bw: %lu, bbr->min_rtt_us: %u, in_flight: %u, bbr_target_cwnd: %u\n", __func__, sh->snd_cwnd, sk->sk_pacing_rate, bbr_bw(sk), bbr->min_rtt_us, seadp_packets_in_flight(sh), bbr_target_cwnd(sk, bbr_max_bw(sk), BBR_UNIT));
		bbr->mode = BBR_DRAIN;	/* drain queue we created */
		bbr->pacing_gain = bbr_drain_gain;	/* pace slow to drain */
		bbr->cwnd_gain = bbr_high_gain;	/* maintain cwnd */
	}	/* fall through to check if in-flight is already small: */
/*
	if(bbr->mode == BBR_DRAIN)
	{
		printk("%s: sh->snd_cwnd: %d, sk->sk_pacing_rate: %d, bw: %lu\n", __func__, sh->snd_cwnd, sk->sk_pacing_rate, bbr_bw(sk));
		
	}
*/
	if (bbr->mode == BBR_DRAIN && seadp_packets_in_flight(seadp_sk(sk)) <= bbr_target_cwnd(sk, bbr_max_bw(sk), BBR_UNIT))
	{
		
		bbr_reset_probe_bw_mode(sk);  /* we estimate queue is drained */
		printk("%s: DRAIN->ProbeBW, sh->snd_cwnd: %d, sk->sk_pacing_rate: %d, bw: %lu, bbr->min_rtt_us: %u, in_flight: %u, bbr_target_cwnd: %u, bbr->cwnd_gain: %d\n", __func__, sh->snd_cwnd, sk->sk_pacing_rate, bbr_bw(sk), bbr->min_rtt_us, seadp_packets_in_flight(sh), bbr_target_cwnd(sk, bbr_max_bw(sk), BBR_UNIT), bbr->cwnd_gain);	
		printk("%s: sh->delivered: %u, time(us): %X\n", __func__, sh->delivered, seadp_clock_us());
	}
}


//improvement throughtput of wifi
static void bbr_update_ack_aggregation(struct sock *sk,const struct seadp_rate_sample *rs)
{
	u32 epoch_us, expected_acked, extra_acked;
	struct seadp_bbr *bbr = seadp_csk_ca(sk);
	struct seadp_sock *sh = seadp_sk(sk);


	if (!bbr_extra_acked_gain || rs->acked_sacked <= 0 || rs->delivered < 0 || rs->interval_us <= 0)
        	return;
	if (bbr->round_start) 
	{
		bbr->extra_acked_win_rtts = min(0x1F,bbr->extra_acked_win_rtts + 1);
		if (bbr->extra_acked_win_rtts >= bbr_extra_acked_win_rtts) 
		{
			bbr->extra_acked_win_rtts = 0;
			bbr->extra_acked_win_idx = bbr->extra_acked_win_idx ?0 : 1;
			bbr->extra_acked[bbr->extra_acked_win_idx] = 0;
		}   
	}
/* Compute how many packets we expected to be delivered over epoch. */
	epoch_us = seadp_stamp_us_delta(sh->delivered_mstamp, bbr->ack_epoch_mstamp);
	expected_acked = ((u64)bbr_bw(sk) * epoch_us) / BW_UNIT;
/* Reset the aggregation epoch if ACK rate is below expected rate or
* significantly large no. of ack received since epoch (potentially
* quite old epoch).
*/
	if (bbr->ack_epoch_acked <= expected_acked || (bbr->ack_epoch_acked + rs->acked_sacked >= bbr_ack_epoch_acked_reset_thresh)) 
	{
		bbr->ack_epoch_acked = 0;
		bbr->ack_epoch_mstamp = sh->delivered_mstamp;
		expected_acked = 0;
	}
    /* Compute excess data delivered, beyond what was expected. */
	bbr->ack_epoch_acked = min(0xFFFFFU, bbr->ack_epoch_acked + rs->acked_sacked);
	extra_acked = bbr->ack_epoch_acked - expected_acked;
	extra_acked = min(extra_acked, sh->snd_cwnd);
	if (extra_acked > bbr->extra_acked[bbr->extra_acked_win_idx])
			bbr->extra_acked[bbr->extra_acked_win_idx] = extra_acked;
}



static void bbr_update_model(struct sock *sk, const struct seadp_rate_sample *rs)	//814
{
	bbr_update_bw(sk, rs);

	bbr_update_ack_aggregation(sk, rs);

	bbr_update_cycle_phase(sk, rs);
	bbr_check_full_bw_reached(sk, rs);
	bbr_check_drain(sk, rs);
	bbr_update_min_rtt(sk, rs);
}


u32 seadp_tso_autosize(const struct sock *sk, unsigned int mss_now, int min_tso_segs)
{
	u32 bytes, segs;
	bytes = min( (sk->sk_pacing_rate >> 10) / mss_now, MAX_AGGREGATION_COUNT);


	segs = max_t(u32, bytes, min_tso_segs);

	return segs;
}



static void bbr_set_tso_segs_goal(struct sock *sk)
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct seadp_bbr *bbr = seadp_csk_ca(sk);

	u32 min_segs;

	min_segs = sk->sk_pacing_rate < (bbr_min_tso_rate >> 3) ? 1 : 2;
	
	bbr->tso_segs_goal = min(seadp_tso_autosize(sk, SEADP_MSS, min_segs), 0x7FU);

}


static void seadp_bbr_main(struct sock *sk, const struct seadp_rate_sample *rs)		//823
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct seadp_bbr *bbr = seadp_csk_ca(sk);

	u32 bw;

	bbr_update_model(sk, rs);

	bw = bbr_bw(sk);
	
	if(sh->rtt_sample_times <20)
	{
		printk("%s: bw: %lu\n", __func__, bw);
	}
	
		

	bbr_set_pacing_rate(sk, bw, bbr->pacing_gain);

	bbr_set_tso_segs_goal(sk);		//

	bbr_set_cwnd(sk, rs, rs->acked_sacked, bw, bbr->cwnd_gain);
	
	if(sh->rtt_sample_times == 5000 || sh->rtt_sample_times == 5500 || sh->rtt_sample_times == 10000 || sh->rtt_sample_times == 10500 || sh->rtt_sample_times == 20000 || sh->rtt_sample_times == 20500 || sh->rtt_sample_times == 30000 || sh->rtt_sample_times == 30500 || sh->rtt_sample_times == 40000 || sh->rtt_sample_times == 50000 || sh->rtt_sample_times == 60000 || sh->rtt_sample_times == 70000)
	{
		printk("%s: sh->rtt_sample_times: %u, sk->sk_pacing_rate: %d, sh->snd_cwnd: %d, bbr->min_rtt_us: %u, sh->delivered: %u, in_flight: %u, bw: %u, bbr->rtt_cnt: %u\n", __func__, sh->rtt_sample_times, sk->sk_pacing_rate, sh->snd_cwnd, bbr->min_rtt_us, sh->delivered, seadp_packets_in_flight(sh), bbr_bw(sk), bbr->rtt_cnt);
	}

}

static u32 seadp_bbr_sndbuf_expand(struct sock *sk)
{
	printk("%s\n",__func__);
}

static u32 seadp_bbr_undo_cwnd(struct sock *sk)
{
	printk("%s\n",__func__);
}
static void seadp_bbr_cwnd_event(struct sock *sk, enum seadp_ca_event event)
{
	struct seadp_sock *sh = seadp_sk(sk);
	struct seadp_bbr *bbr = seadp_csk_ca(sk);

	if (event == CA_EVENT_TX_START && sh->app_limited) {
		bbr->idle_restart = 1;
		/* Avoid pointless buffer overflows: pace at est. bw if we don't
		 * need more speed (we're restarting from idle and app-limited).
		 */
		if (bbr->mode == BBR_PROBE_BW)
			bbr_set_pacing_rate(sk, bbr_bw(sk), BBR_UNIT);
	}
	printk("%s\n",__func__);
}
static u32 seadp_bbr_ssthresh(struct sock *sk)
{
	printk("%s\n",__func__);
}
static u32 seadp_bbr_tso_segs_goal(struct sock *sk)
{
	struct seadp_bbr *bbr = seadp_csk_ca(sk);
	
	//if(bbr->mode == BBR_PROBE_BW && bbr->pacing_gain == bbr_pacing_gain[0])	return  bbr->tso_segs_goal + 10;

	return bbr->tso_segs_goal;				//这里我们将此函数语义定为最大的聚合数！！！！

	//printk("%s\n",__func__);
}
static size_t seadp_bbr_get_info(struct sock *sk, u32 ext, int *attr, union seadp_cc_info *info)
{
	printk("%s\n",__func__);
}
static void seadp_bbr_set_state(struct sock *sk, u8 new_state)
{
	struct seadp_bbr *bbr = seadp_csk_ca(sk);

	if (new_state == SEADP_CA_Loss) {
		struct seadp_rate_sample rs = { .losses = 1 };

		bbr->prev_ca_state = SEADP_CA_Loss;
		bbr->full_bw = 0;
		bbr->round_start = 1;	/* treat RTO like end of a round */
		bbr_lt_bw_sampling(sk, &rs);
	}

	printk("%s\n",__func__);
}
struct seadp_congestion_ops seadp_bbr_cong_ops __read_mostly = {
	.name		= "seadp_bbr",
	.owner		= THIS_MODULE,
	.init		= seadp_bbr_init,
	.cong_control	= seadp_bbr_main,	//tcp_ack->tcp_cong_control里面
	.sndbuf_expand	= seadp_bbr_sndbuf_expand,
	.undo_cwnd	= seadp_bbr_undo_cwnd,	//tcp_undo_cwnd_reduction里面
	.cwnd_event	= seadp_bbr_cwnd_event,	//tcp超时重传定时器里面tcp_retransmit_timer->tcp_enter_loss->tcp_ca_event
	.ssthresh	= seadp_bbr_ssthresh,	//tcp超时重传定时器里面tcp_retransmit_timer->tcp_enter_loss
	.tso_segs_goal	= seadp_bbr_tso_segs_goal,
	.get_info	= seadp_bbr_get_info,
	.set_state	= seadp_bbr_set_state,	//tcp超时重传定时器里面tcp_retransmit_timer->tcp_enter_loss->tcp_set_ca_state
};
struct seadp_congestion_ops *seadp_ca_find_key(u32 key)	//通过哈希key寻找拥塞控制结构体
{
	struct seadp_congestion_ops *e;

	list_for_each_entry_rcu(e, &seadp_cong_list, list) {
		if (e->key == key)
			return e;
	}

	return NULL;
}

int seadp_register_congestion_control(struct seadp_congestion_ops *ca)	//注册
{
	int ret = 0;

	/* all algorithms must implement these */
	if (!ca->ssthresh || !ca->undo_cwnd ||
	    !(ca->cong_avoid || ca->cong_control)) {
		pr_err("%s does not implement required ops\n", ca->name);
		return -EINVAL;
	}

	ca->key = jhash(ca->name, sizeof(ca->name), strlen(ca->name));
	//printk("key1:%d\n", ca->key);

	spin_lock(&seadp_cong_list_lock);	//写者加锁！！
	if (seadp_ca_find_key(ca->key)) {
		pr_notice("%s already registered or non-unique key\n",
			  ca->name);
		ret = -EEXIST;
	} else {
		list_add_tail_rcu(&ca->list, &seadp_cong_list);
		pr_debug("%s registered\n", ca->name);
	}
	spin_unlock(&seadp_cong_list_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(seadp_register_congestion_control);



void seadp_unregister_congestion_control(struct seadp_congestion_ops *ca)
{
	spin_lock(&seadp_cong_list_lock);
	list_del_rcu(&ca->list);
	spin_unlock(&seadp_cong_list_lock);

	/* Wait for outstanding readers to complete before the
	 * module gets removed entirely.
	 *
	 * A try_module_get() should fail by now as our module is
	 * in "going" state since no refs are held anymore and
	 * module_exit() handler being called.
	 */
	synchronize_rcu();
}
EXPORT_SYMBOL_GPL(seadp_unregister_congestion_control);

/* Assign choice of congestion control. */
void seadp_assign_congestion_control_default(struct sock *sk, struct seadp_congestion_ops *ca)
{
	struct seadp_sock *sh = seadp_sk(sk);
	
	u32 key = jhash(ca->name, sizeof(ca->name), strlen(ca->name));;
	//printk("key2:%d\n", key);
	rcu_read_lock();
	if (likely(try_module_get(ca->owner)))
	{
		ca = seadp_ca_find_key(key);
	}
	if(!ca)	printk("no congestion\n");
	
	sh->seadp_ca_ops = ca;
	
	
	
out:
	rcu_read_unlock();
	
}

void seadp_cleanup_congestion_control(struct sock *sk)
{
	struct seadp_sock *sh = seadp_sk(sk);

	if(!sh->seadp_ca_ops) return;
	if (sh->seadp_ca_ops->release)
		sh->seadp_ca_ops->release(sk);
	if(sh->seadp_ca_ops)	//NULL检查！！！
		module_put(sh->seadp_ca_ops->owner);
}
