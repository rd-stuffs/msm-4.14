/*
 * CPUFreq governor based on scheduler-provided CPU utilization data.
 *
 * Copyright (C) 2016, Intel Corporation
 * Author: Rafael J. Wysocki <rafael.j.wysocki@intel.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cpufreq.h>
#include <linux/kthread.h>
#include <uapi/linux/sched/types.h>
#include <linux/slab.h>
#include <linux/sched/sysctl.h>
#include "sched.h"

#define SUGOV_KTHREAD_PRIORITY	50

DEFINE_PER_CPU_READ_MOSTLY(unsigned long, response_time_mult);

struct sugov_tunables {
	struct gov_attr_set attr_set;
	unsigned int		rate_limit_us;
	unsigned int		response_time_ms;
};

struct sugov_policy {
	struct cpufreq_policy *policy;

	struct sugov_tunables *tunables;
	struct list_head tunables_hook;

	raw_spinlock_t update_lock;  /* For shared policies */
	u64 last_freq_update_time;
	s64 freq_update_delay_ns;
	unsigned int freq_response_time_ms;
	unsigned int next_freq;
	unsigned int cached_raw_freq;

	/* The next fields are only needed if fast switch cannot be used. */
	struct irq_work irq_work;
	struct kthread_work work;
	struct mutex work_lock;
	struct kthread_worker worker;
	struct task_struct *thread;
	bool work_in_progress;

	bool limits_changed;
	bool need_freq_update;
};

struct sugov_cpu {
	struct update_util_data update_util;
	struct sugov_policy *sg_policy;
	unsigned int cpu;

	bool iowait_boost_pending;
	unsigned int iowait_boost;
	unsigned int iowait_boost_max;
	u64 last_update;

	struct sched_walt_cpu_load walt_load;

	/* The fields below are only needed when sharing a policy. */
	unsigned long util;
	unsigned long max;
	unsigned int flags;
};

static DEFINE_PER_CPU(struct sugov_cpu, sugov_cpu);
static unsigned int stale_ns;
static DEFINE_PER_CPU(struct sugov_tunables *, cached_tunables);

/************************ Governor internals ***********************/

static bool sugov_should_rate_limit(struct sugov_policy *sg_policy, u64 time)
{
	s64 delta_ns = time - sg_policy->last_freq_update_time;
	return delta_ns < sg_policy->freq_update_delay_ns;
}

static bool sugov_should_update_freq(struct sugov_policy *sg_policy, u64 time)
{
	/*
	 * Since cpufreq_update_util() is called with rq->lock held for
	 * the @target_cpu, our per-cpu data is fully serialized.
	 *
	 * However, drivers cannot in general deal with cross-cpu
	 * requests, so while get_next_freq() will work, our
	 * sugov_update_commit() call may not for the fast switching platforms.
	 *
	 * Hence stop here for remote requests if they aren't supported
	 * by the hardware, as calculating the frequency is pointless if
	 * we cannot in fact act on it.
	 *
	 * This is needed on the slow switching platforms too to prevent CPUs
	 * going offline from leaving stale IRQ work items behind.
	 */
	if (!cpufreq_can_do_remote_dvfs(sg_policy->policy))
		return false;

	if (unlikely(READ_ONCE(sg_policy->limits_changed))) {
		WRITE_ONCE(sg_policy->limits_changed, false);
		sg_policy->need_freq_update = true;
		return true;
	}

	/*
	 * When frequency-invariant utilization tracking is present, there's no
	 * rate limit when increasing frequency. Therefore, the next frequency
	 * must be determined before a decision can be made to rate limit the
	 * frequency change, hence the rate limit check is bypassed here.
	 */
	if (arch_scale_freq_invariant())
		return true;

	/* If the last frequency wasn't set yet then we can still amend it */
	if (sg_policy->work_in_progress)
		return true;

	return !sugov_should_rate_limit(sg_policy, time);
}

static inline bool use_pelt(void)
{
#ifdef CONFIG_SCHED_WALT
	return (!sysctl_sched_use_walt_cpu_util || walt_disabled);
#else
	return true;
#endif
}

static bool sugov_update_next_freq(struct sugov_policy *sg_policy, u64 time,
				   unsigned int next_freq)
{
	if (sg_policy->need_freq_update) {
		sg_policy->need_freq_update = false;
		/*
		 * The policy limits have changed, but if the return value of
		 * cpufreq_driver_resolve_freq() after applying the new limits
		 * is still equal to the previously selected frequency, the
		 * driver callback need not be invoked unless the driver
		 * specifically wants that to happen on every update of the
		 * policy limits.
		 */
		if (cpufreq_driver_test_flags(CPUFREQ_NEED_UPDATE_LIMITS))
			goto must_update;
		/*
		 * Even if the driver doesn't require notification on every
		 * limits update, we still need to update our internal state
		 * to reflect the new limits and avoid rate limiting blocking
		 * future updates. Return false to skip the driver callback.
		 */
		sg_policy->next_freq = next_freq;
		sg_policy->last_freq_update_time = time;
		return false;
	}

	/*
	 * When a frequency update isn't mandatory (!need_freq_update), the rate
	 * limit is checked again upon frequency reduction because systems with
	 * frequency-invariant utilization bypass the rate limit check entirely
	 * in sugov_should_update_freq(). This is done so that the rate limit
	 * can be applied only for frequency reduction when frequency-invariant
	 * utilization is present. Now that the next frequency is known, the
	 * rate limit can be selectively applied to frequency reduction on such
	 * systems. A check for arch_scale_freq_invariant() is omitted here
	 * because unconditionally rechecking the rate limit is cheaper.
	 */
	if (next_freq == sg_policy->next_freq ||
	    (next_freq < sg_policy->next_freq &&
	     sugov_should_rate_limit(sg_policy, time)))
		return false;

must_update:
	if (sg_policy->next_freq > next_freq &&
	    sg_policy->next_freq != UINT_MAX)
		next_freq = (sg_policy->next_freq + next_freq) >> 1;

	sg_policy->next_freq = next_freq;
	sg_policy->last_freq_update_time = time;

	return true;
}

static void sugov_fast_switch(struct sugov_policy *sg_policy, u64 time,
			      unsigned int next_freq)
{
	struct cpufreq_policy *policy = sg_policy->policy;

	if (!sugov_update_next_freq(sg_policy, time, next_freq))
		return;

	next_freq = cpufreq_driver_fast_switch(policy, next_freq);
	if (!next_freq)
		return;

	policy->cur = next_freq;
}

static void sugov_deferred_update(struct sugov_policy *sg_policy, u64 time,
				  unsigned int next_freq)
{
	if (!sugov_update_next_freq(sg_policy, time, next_freq))
		return;

	if (likely(use_pelt()))
		sg_policy->work_in_progress = true;

	sched_irq_work_queue(&sg_policy->irq_work);
}

/**
 * get_next_freq - Compute a new frequency for a given cpufreq policy.
 * @sg_policy: schedutil policy object to compute the new frequency for.
 * @util: Current CPU utilization.
 * @max: CPU capacity.
 *
 * If the utilization is frequency-invariant, choose the new frequency to be
 * proportional to it, that is
 *
 * next_freq = C * max_freq * util / max
 *
 * Otherwise, approximate the would-be frequency-invariant utilization by
 * util_raw * (curr_freq / max_freq) which leads to
 *
 * next_freq = C * curr_freq * util_raw / max
 *
 * Take C = 1.25 for the frequency tipping point at (util / max) = 0.8.
 *
 * The lowest driver-supported frequency which is equal or greater than the raw
 * next_freq (as calculated above) is returned, subject to policy min/max and
 * cpufreq driver limitations.
 */
static unsigned int get_next_freq(struct sugov_policy *sg_policy,
				  unsigned long util, unsigned long max)
{
	struct cpufreq_policy *policy = sg_policy->policy;
	unsigned int freq;
	unsigned int idx, l_freq, h_freq;

	if (arch_scale_freq_invariant())
		freq = policy->cpuinfo.max_freq;
	else
		/*
		 * Apply a 25% margin so that we select a higher frequency than
		 * the current one before the CPU is fully busy:
		 */
		freq = policy->cur + (policy->cur >> 2);

	freq = map_util_freq(util, freq, max);

	if (freq == sg_policy->cached_raw_freq && !sg_policy->need_freq_update)
		return sg_policy->next_freq;

	sg_policy->cached_raw_freq = freq;
	l_freq = cpufreq_driver_resolve_freq(policy, freq);
	idx = cpufreq_frequency_table_target(policy, freq, CPUFREQ_RELATION_H);
	h_freq = policy->freq_table[idx].frequency;
	h_freq = clamp(h_freq, policy->min, policy->max);
	if (l_freq <= h_freq || l_freq == policy->min)
		return l_freq;

	/*
	 * Use the frequency step below if the calculated frequency is <20%
	 * higher than it.
	 */
	if (mult_frac(100, freq - h_freq, l_freq - h_freq) < 20)
		return h_freq;

	return l_freq;
}

/*
 * DVFS decision are made at discrete points. If CPU stays busy, the util will
 * continue to grow, which means it could need to run at a higher frequency
 * before the next decision point was reached. IOW, we can't follow the util as
 * it grows immediately, but there's a delay before we issue a request to go to
 * higher frequency. The headroom caters for this delay so the system continues
 * to run at adequate performance point.
 *
 * This function provides enough headroom to provide adequate performance
 * assuming the CPU continues to be busy. This headroom is based on the
 * dvfs_update_delay of the cpufreq governor or the current task's time slice,
 * whichever is higher.
 *
 * XXX: Should we provide headroom when the util is decaying?
 */
static inline unsigned long sugov_apply_dvfs_headroom(unsigned long util, int cpu)
{
	struct rq *rq = cpu_rq(cpu);
	u64 delay;
	unsigned long cap, approx, h_max, growth, decay;

	if (!util)
		return 0;

	/*
	 * What is the possible worst case scenario for updating util_avg, ctx
	 * switch or TICK?
	 */
	if (rq->cfs.h_nr_running > 1)
		delay = min_t(u64, sched_slice(&rq->cfs, &rq->curr->se) / NSEC_PER_USEC, TICK_USEC);
	else
		delay = TICK_USEC;
	delay = max(delay, per_cpu(dvfs_update_delay, cpu));

	/*
	 * Capacity-aware DVFS headroom based on PELT for H_ideal = (C - util) * alpha
	 *
	 * alpha = h_max / 1024, where h_max = approximate_util_avg(0, delay) is the
	 * maximum growth possible for this delay on a 1024-capacity core.
	 *
	 * To avoid division, rewrite (C - util) * alpha as:
	 *   growth = h_max * C / 1024 (= C * alpha)
	 *   decay  = h_max + util - approx (= util * alpha)
	 *   H_ideal = growth - decay
	 *
	 * Derived from accumulate_sum() and approximate_util_avg() in pelt.c.
	 */
	cap = capacity_orig_of(cpu);
	approx = approximate_util_avg(util, delay);
	h_max = approximate_util_avg(0, delay);
	growth = mult_frac(h_max, cap, SCHED_CAPACITY_SCALE);
	decay = h_max + util - approx;

	if (growth > decay)
		return util + growth - decay;

	return util;
}

static inline u64 sugov_calc_freq_response_ms(struct sugov_policy *sg_policy)
{
	int cpu = cpumask_first(sg_policy->policy->cpus);
	unsigned long cap = arch_scale_cpu_capacity(NULL, cpu);
	unsigned int max_freq, sec_max_freq;

	max_freq = sg_policy->policy->cpuinfo.max_freq;
	sec_max_freq = __resolve_freq(sg_policy->policy,
				      max_freq - 1,
				      CPUFREQ_RELATION_H);

	/*
	 * We will request max_freq as soon as util crosses the capacity at
	 * second highest frequency. So effectively our response time is the
	 * util at which we cross the cap@2nd_highest_freq.
	 */
	cap = sec_max_freq * cap / max_freq;

	return approximate_runtime(min_t(unsigned long, cap + 1, SCHED_CAPACITY_SCALE));
}

static inline void sugov_update_response_time_mult(struct sugov_policy *sg_policy)
{
	unsigned long mult;
	int cpu;

	if (unlikely(!sg_policy->freq_response_time_ms))
		sg_policy->freq_response_time_ms = sugov_calc_freq_response_ms(sg_policy);

	mult = sg_policy->freq_response_time_ms * SCHED_CAPACITY_SCALE;
	mult /=	sg_policy->tunables->response_time_ms;

	if (SCHED_WARN_ON(!mult))
		mult = SCHED_CAPACITY_SCALE;

	for_each_cpu(cpu, sg_policy->policy->cpus)
		per_cpu(response_time_mult, cpu) = mult;
}

/*
 * Shrink or expand how long it takes to reach the maximum performance of the
 * policy.
 *
 * sg_policy->freq_response_time_ms is a constant value defined by PELT
 * HALFLIFE and the capacity of the policy (assuming HMP systems).
 *
 * sg_policy->tunables->response_time_ms is a user defined response time. By
 * setting it lower than sg_policy->freq_response_time_ms, the system will
 * respond faster to changes in util, which will result in reaching maximum
 * performance point quicker. By setting it higher, it'll slow down the amount
 * of time required to reach the maximum OPP.
 *
 * This should be applied when selecting the frequency.
 */
static inline unsigned long
sugov_apply_response_time(unsigned long util, int cpu)
{
	unsigned long mult;

	mult = per_cpu(response_time_mult, cpu) * util;

	return mult >> SCHED_CAPACITY_SHIFT;
}

static void sugov_get_util(unsigned long *util, unsigned long *max, int cpu,
			   u64 time)
{
	struct rq *rq = cpu_rq(cpu);
	unsigned long max_cap, rt;
	struct sugov_cpu *loadcpu = &per_cpu(sugov_cpu, cpu);
	s64 delta;

	max_cap = arch_scale_cpu_capacity(NULL, cpu);
	*max = max_cap;

	*util = boosted_cpu_util(cpu, &loadcpu->walt_load);

	if (likely(use_pelt())) {
		sched_avg_update(rq);
		delta = time - rq->age_stamp;
		if (unlikely(delta < 0))
			delta = 0;
		rt = div64_u64(rq->rt_avg, sched_avg_period() + delta);
		rt = (rt * max_cap) >> SCHED_CAPACITY_SHIFT;
		/*
		 * Speed up/slow down response timee first then apply DVFS headroom.
		 */
		*util = min(sugov_apply_dvfs_headroom(sugov_apply_response_time(*util + rt, cpu), cpu), max_cap);
	}
}

static void sugov_set_iowait_boost(struct sugov_cpu *sg_cpu, u64 time)
{
	/* Clear iowait_boost if the CPU appears to have been idle. */
	if (sg_cpu->iowait_boost) {
		s64 delta_ns = time - sg_cpu->last_update;

		/*
		 * Clear boost if time has advanced beyond TICK_NSEC, or if
		 * time went backwards (clock instability, TSC adjustment, etc).
		 * Treating backwards time as idle prevents stale boost values.
		 */
		if (delta_ns > TICK_NSEC || delta_ns < 0) {
			sg_cpu->iowait_boost = 0;
			sg_cpu->iowait_boost_pending = false;
		}
	}

	if (sg_cpu->flags & SCHED_CPUFREQ_IOWAIT) {
		if (sg_cpu->iowait_boost_pending)
			return;

		sg_cpu->iowait_boost_pending = true;

		if (sg_cpu->iowait_boost) {
			sg_cpu->iowait_boost <<= 1;
			if (sg_cpu->iowait_boost > sg_cpu->iowait_boost_max)
				sg_cpu->iowait_boost = sg_cpu->iowait_boost_max;
		} else {
			sg_cpu->iowait_boost = sg_cpu->sg_policy->policy->min;
		}
	}
}

static void sugov_iowait_boost(struct sugov_cpu *sg_cpu, unsigned long *util,
			       unsigned long *max)
{
	unsigned int boost_util, boost_max;

	if (!sg_cpu->iowait_boost)
		return;

	if (sg_cpu->iowait_boost_pending) {
		sg_cpu->iowait_boost_pending = false;
	} else {
		sg_cpu->iowait_boost >>= 1;
		if (sg_cpu->iowait_boost < sg_cpu->sg_policy->policy->min) {
			sg_cpu->iowait_boost = 0;
			return;
		}
	}

	boost_util = sg_cpu->iowait_boost;
	boost_max = sg_cpu->iowait_boost_max;

	if (*util * boost_max < *max * boost_util) {
		*util = boost_util;
		*max = boost_max;
	}
}

static void sugov_update_single(struct update_util_data *hook, u64 time,
				unsigned int flags)
{
	struct sugov_cpu *sg_cpu = container_of(hook, struct sugov_cpu, update_util);
	struct sugov_policy *sg_policy = sg_cpu->sg_policy;
	struct cpufreq_policy *policy = sg_policy->policy;
	unsigned long util, max;
	unsigned int next_f;

	if (flags & SCHED_CPUFREQ_PL)
		return;

	flags &= ~SCHED_CPUFREQ_RT_DL;
	sugov_set_iowait_boost(sg_cpu, time);
	sg_cpu->last_update = time;

	/*
	 * For slow-switch systems, single policy requests can't run at the
	 * moment if update is in progress, unless we acquire update_lock.
	 */
	if (sg_policy->work_in_progress)
		return;

	if (!sugov_should_update_freq(sg_policy, time))
		return;

	if (flags & SCHED_CPUFREQ_DL) {
		/* clear cache when it's bypassed */
		sg_policy->cached_raw_freq = 0;
		next_f = policy->cpuinfo.max_freq;
	} else {
		sugov_get_util(&util, &max, sg_cpu->cpu, time);
		sugov_iowait_boost(sg_cpu, &util, &max);
		next_f = get_next_freq(sg_policy, util, max);
	}
	/*
	 * This code runs under rq->lock for the target CPU, so it won't run
	 * concurrently on two different CPUs for the same target and it is not
	 * necessary to acquire the lock in the fast switch case.
	 */
	if (sg_policy->policy->fast_switch_enabled) {
		sugov_fast_switch(sg_policy, time, next_f);
	} else {
		raw_spin_lock(&sg_policy->update_lock);
		sugov_deferred_update(sg_policy, time, next_f);
		raw_spin_unlock(&sg_policy->update_lock);
	}
}

static unsigned int sugov_next_freq_shared(struct sugov_cpu *sg_cpu, u64 time)
{
	struct sugov_policy *sg_policy = sg_cpu->sg_policy;
	struct cpufreq_policy *policy = sg_policy->policy;
	unsigned long util = 0, max = 1;
	unsigned int j;

	for_each_cpu(j, policy->cpus) {
		struct sugov_cpu *j_sg_cpu = &per_cpu(sugov_cpu, j);
		unsigned long j_util, j_max;
		s64 delta_ns;

		/*
		 * If the CPU utilization was last updated before the previous
		 * frequency update and the time elapsed between the last update
		 * of the CPU utilization and the last frequency update is long
		 * enough, don't take the CPU into account as it probably is
		 * idle now (and clear iowait_boost for it).
		 */
		delta_ns = time - j_sg_cpu->last_update;
		if (delta_ns > stale_ns) {
			j_sg_cpu->iowait_boost = 0;
			j_sg_cpu->iowait_boost_pending = false;
			continue;
		}
		if (j_sg_cpu->flags & SCHED_CPUFREQ_DL) {
			/* clear cache when it's bypassed */
			sg_policy->cached_raw_freq = 0;
			return policy->cpuinfo.max_freq;
		}

		/*
		 * Use >= to ensure max is always updated to the current CPU
		 * capacity even when util is 0, preventing a stale max value
		 * from causing incorrect frequency calculations on the next
		 * non-zero util update.
		 */
		j_util = j_sg_cpu->util;
		j_max = j_sg_cpu->max;
		if (j_util * max >= j_max * util) {
			util = j_util;
			max = j_max;
		}

		sugov_iowait_boost(j_sg_cpu, &util, &max);
	}

	return get_next_freq(sg_policy, util, max);
}

static void sugov_update_shared(struct update_util_data *hook, u64 time,
				unsigned int flags)
{
	struct sugov_cpu *sg_cpu = container_of(hook, struct sugov_cpu, update_util);
	struct sugov_policy *sg_policy = sg_cpu->sg_policy;
	unsigned long util, max;
	unsigned int next_f;

	if (flags & SCHED_CPUFREQ_PL)
		return;

	sugov_get_util(&util, &max, sg_cpu->cpu, time);

	flags &= ~SCHED_CPUFREQ_RT_DL;

	raw_spin_lock(&sg_policy->update_lock);

	sg_cpu->util = util;
	sg_cpu->max = max;
	sg_cpu->flags = flags;

	sugov_set_iowait_boost(sg_cpu, time);
	sg_cpu->last_update = time;

	if (sugov_should_update_freq(sg_policy, time) &&
		!(flags & SCHED_CPUFREQ_CONTINUE)) {
		if (flags & SCHED_CPUFREQ_DL) {
			/* clear cache when it's bypassed */
			sg_policy->cached_raw_freq = 0;
			next_f = sg_policy->policy->cpuinfo.max_freq;
		} else {
			next_f = sugov_next_freq_shared(sg_cpu, time);
		}

		if (sg_policy->policy->fast_switch_enabled)
			sugov_fast_switch(sg_policy, time, next_f);
		else
			sugov_deferred_update(sg_policy, time, next_f);
	}

	raw_spin_unlock(&sg_policy->update_lock);
}

static void sugov_work(struct kthread_work *work)
{
	struct sugov_policy *sg_policy = container_of(work, struct sugov_policy, work);
	unsigned int freq;
	unsigned long flags;

	/*
	 * Hold sg_policy->update_lock shortly to handle the case where:
	 * incase sg_policy->next_freq is read here, and then updated by
	 * sugov_deferred_update() just before work_in_progress is set to false
	 * here, we may miss queueing the new update.
	 *
	 * Note: If a work was queued after the update_lock is released,
	 * sugov_work() will just be called again by kthread_work code; and the
	 * request will be proceed before the sugov thread sleeps.
	 */
	raw_spin_lock_irqsave(&sg_policy->update_lock, flags);
	freq = sg_policy->next_freq;
	sg_policy->work_in_progress = false;
	raw_spin_unlock_irqrestore(&sg_policy->update_lock, flags);

	mutex_lock(&sg_policy->work_lock);
	__cpufreq_driver_target(sg_policy->policy, freq, CPUFREQ_RELATION_L);
	mutex_unlock(&sg_policy->work_lock);
}

static void sugov_irq_work(struct irq_work *irq_work)
{
	struct sugov_policy *sg_policy;

	sg_policy = container_of(irq_work, struct sugov_policy, irq_work);

	/*
	 * For RT and deadline tasks, the schedutil governor shoots the
	 * frequency to maximum. Special care must be taken to ensure that this
	 * kthread doesn't result in the same behavior.
	 *
	 * This is (mostly) guaranteed by the work_in_progress flag. The flag is
	 * updated only at the end of the sugov_work() function and before that
	 * the schedutil governor rejects all other frequency scaling requests.
	 *
	 * There is a very rare case though, where the RT thread yields right
	 * after the work_in_progress flag is cleared. The effects of that are
	 * neglected for now.
	 */
	kthread_queue_work(&sg_policy->worker, &sg_policy->work);
}

/************************** sysfs interface ************************/

static struct sugov_tunables *global_tunables;
static DEFINE_MUTEX(global_tunables_lock);

static inline struct sugov_tunables *to_sugov_tunables(struct gov_attr_set *attr_set)
{
	return container_of(attr_set, struct sugov_tunables, attr_set);
}

static ssize_t rate_limit_us_show(struct gov_attr_set *attr_set, char *buf)
{
	struct sugov_tunables *tunables = to_sugov_tunables(attr_set);

	return sprintf(buf, "%u\n", tunables->rate_limit_us);
}

static ssize_t rate_limit_us_store(struct gov_attr_set *attr_set,
				      const char *buf, size_t count)
{
	struct sugov_tunables *tunables = to_sugov_tunables(attr_set);
	struct sugov_policy *sg_policy;
	unsigned int rate_limit_us;
	int cpu;

	if (kstrtouint(buf, 10, &rate_limit_us))
		return -EINVAL;

	tunables->rate_limit_us = rate_limit_us;

	list_for_each_entry(sg_policy, &attr_set->policy_list, tunables_hook) {
		sg_policy->freq_update_delay_ns = rate_limit_us * NSEC_PER_USEC;

		for_each_cpu(cpu, sg_policy->policy->cpus)
			per_cpu(dvfs_update_delay, cpu) = rate_limit_us;
	}

	return count;
}

static struct governor_attr rate_limit_us = __ATTR_RW(rate_limit_us);

static ssize_t response_time_ms_show(struct gov_attr_set *attr_set, char *buf)
{
	struct sugov_tunables *tunables = to_sugov_tunables(attr_set);

	return sprintf(buf, "%u\n", tunables->response_time_ms);
}

static ssize_t
response_time_ms_store(struct gov_attr_set *attr_set, const char *buf, size_t count)
{
	struct sugov_tunables *tunables = to_sugov_tunables(attr_set);
	struct sugov_policy *sg_policy;
	unsigned int response_time_ms;

	if (kstrtouint(buf, 10, &response_time_ms))
		return -EINVAL;

	/* XXX need special handling for high values? */

	tunables->response_time_ms = response_time_ms;

	list_for_each_entry(sg_policy, &attr_set->policy_list, tunables_hook) {
		if (sg_policy->tunables == tunables)
			sugov_update_response_time_mult(sg_policy);
	}

	return count;
}

static struct governor_attr response_time_ms = __ATTR_RW(response_time_ms);

static struct attribute *sugov_attributes[] = {
	&rate_limit_us.attr,
	&response_time_ms.attr,
	NULL
};

static void sugov_tunables_free(struct kobject *kobj)
{
	struct gov_attr_set *attr_set = container_of(kobj, struct gov_attr_set, kobj);

	kfree(to_sugov_tunables(attr_set));
}

static struct kobj_type sugov_tunables_ktype = {
	.default_attrs = sugov_attributes,
	.sysfs_ops = &governor_sysfs_ops,
	.release = &sugov_tunables_free,
};

/********************** cpufreq governor interface *********************/

static struct cpufreq_governor schedutil_gov;

static struct sugov_policy *sugov_policy_alloc(struct cpufreq_policy *policy)
{
	struct sugov_policy *sg_policy;

	sg_policy = kzalloc(sizeof(*sg_policy), GFP_KERNEL);
	if (!sg_policy)
		return NULL;

	sg_policy->policy = policy;
	raw_spin_lock_init(&sg_policy->update_lock);
	return sg_policy;
}

static void sugov_policy_free(struct sugov_policy *sg_policy)
{
	kfree(sg_policy);
}

static int sugov_kthread_create(struct sugov_policy *sg_policy)
{
	struct task_struct *thread;
	struct sched_param param = { .sched_priority = SUGOV_KTHREAD_PRIORITY };
	struct cpufreq_policy *policy = sg_policy->policy;
	int ret;

	/* kthread only required for slow path */
	if (policy->fast_switch_enabled)
		return 0;

	kthread_init_work(&sg_policy->work, sugov_work);
	kthread_init_worker(&sg_policy->worker);
	thread = kthread_create(kthread_worker_fn, &sg_policy->worker,
				"sugov:%d",
				cpumask_first(policy->related_cpus));
	if (IS_ERR(thread)) {
		pr_err("failed to create sugov thread: %ld\n", PTR_ERR(thread));
		return PTR_ERR(thread);
	}

	ret = sched_setscheduler_nocheck(thread, SCHED_FIFO, &param);
	if (ret) {
		kthread_stop(thread);
		pr_warn("%s: failed to set SCHED_FIFO\n", __func__);
		return ret;
	}

	sg_policy->thread = thread;
	if (!policy->dvfs_possible_from_any_cpu)
		kthread_bind_mask(thread, policy->related_cpus);
	init_irq_work(&sg_policy->irq_work, sugov_irq_work);
	mutex_init(&sg_policy->work_lock);

	wake_up_process(thread);

	return 0;
}

static void sugov_kthread_stop(struct sugov_policy *sg_policy)
{
	/* kthread only required for slow path */
	if (sg_policy->policy->fast_switch_enabled)
		return;

	kthread_flush_worker(&sg_policy->worker);
	kthread_stop(sg_policy->thread);
	mutex_destroy(&sg_policy->work_lock);
}

static struct sugov_tunables *sugov_tunables_alloc(struct sugov_policy *sg_policy)
{
	struct sugov_tunables *tunables;

	tunables = kzalloc(sizeof(*tunables), GFP_KERNEL);
	if (tunables) {
		gov_attr_set_init(&tunables->attr_set, &sg_policy->tunables_hook);
		if (!have_governor_per_policy())
			global_tunables = tunables;
	}
	return tunables;
}

static void sugov_tunables_save(struct cpufreq_policy *policy,
		struct sugov_tunables *tunables)
{
	int cpu;
	struct sugov_tunables *cached = per_cpu(cached_tunables, policy->cpu);

	if (!have_governor_per_policy())
		return;

	if (!cached) {
		cached = kzalloc(sizeof(*tunables), GFP_KERNEL);
		if (!cached)
			return;

		for_each_cpu(cpu, policy->related_cpus)
			per_cpu(cached_tunables, cpu) = cached;
	}
}

static void sugov_clear_global_tunables(void)
{
	if (!have_governor_per_policy())
		global_tunables = NULL;
}

static void sugov_tunables_restore(struct cpufreq_policy *policy)
{
	struct sugov_tunables *cached = per_cpu(cached_tunables, policy->cpu);

	if (!cached)
		return;
}

static int sugov_init(struct cpufreq_policy *policy)
{
	struct sugov_policy *sg_policy;
	struct sugov_tunables *tunables;
	int ret = 0;

	/* State should be equivalent to EXIT */
	if (policy->governor_data)
		return -EBUSY;

	cpufreq_enable_fast_switch(policy);

	sg_policy = sugov_policy_alloc(policy);
	if (!sg_policy) {
		ret = -ENOMEM;
		goto disable_fast_switch;
	}

	ret = sugov_kthread_create(sg_policy);
	if (ret)
		goto free_sg_policy;

	mutex_lock(&global_tunables_lock);

	if (global_tunables) {
		if (WARN_ON(have_governor_per_policy())) {
			ret = -EINVAL;
			goto stop_kthread;
		}
		policy->governor_data = sg_policy;
		sg_policy->tunables = global_tunables;

		gov_attr_set_get(&global_tunables->attr_set, &sg_policy->tunables_hook);
		sugov_update_response_time_mult(sg_policy);
		goto out;
	}

	tunables = sugov_tunables_alloc(sg_policy);
	if (!tunables) {
		ret = -ENOMEM;
		goto stop_kthread;
	}

	policy->governor_data = sg_policy;
	sg_policy->tunables = tunables;

	tunables->rate_limit_us = 2000;
	tunables->response_time_ms = sugov_calc_freq_response_ms(sg_policy);
	sugov_update_response_time_mult(sg_policy);

	stale_ns = sched_ravg_window + (sched_ravg_window >> 3);

	sugov_tunables_restore(policy);

	ret = kobject_init_and_add(&tunables->attr_set.kobj, &sugov_tunables_ktype,
				   get_governor_parent_kobj(policy), "%s",
				   schedutil_gov.name);
	if (ret)
		goto fail;

out:
	mutex_unlock(&global_tunables_lock);
	return 0;

fail:
	kobject_put(&tunables->attr_set.kobj);
	policy->governor_data = NULL;
	sugov_clear_global_tunables();

stop_kthread:
	sugov_kthread_stop(sg_policy);
	mutex_unlock(&global_tunables_lock);

free_sg_policy:
	sugov_policy_free(sg_policy);

disable_fast_switch:
	cpufreq_disable_fast_switch(policy);

	pr_err("initialization failed (error %d)\n", ret);
	return ret;
}

static void sugov_exit(struct cpufreq_policy *policy)
{
	struct sugov_policy *sg_policy = policy->governor_data;
	struct sugov_tunables *tunables = sg_policy->tunables;
	unsigned int count;

	mutex_lock(&global_tunables_lock);

	/* Save tunables before last owner release it in gov_attr_set_put() */
	if (tunables->attr_set.usage_count == 1)
		sugov_tunables_save(policy, tunables);

	count = gov_attr_set_put(&tunables->attr_set, &sg_policy->tunables_hook);
	policy->governor_data = NULL;

	if (!count)
		sugov_clear_global_tunables();

	mutex_unlock(&global_tunables_lock);

	sugov_kthread_stop(sg_policy);
	sugov_policy_free(sg_policy);
	cpufreq_disable_fast_switch(policy);
}

static int sugov_start(struct cpufreq_policy *policy)
{
	struct sugov_policy *sg_policy = policy->governor_data;
	unsigned int cpu;

	sg_policy->freq_update_delay_ns		= sg_policy->tunables->rate_limit_us * NSEC_PER_USEC;
	sg_policy->last_freq_update_time = 0;
	sg_policy->next_freq = 0;
	sg_policy->work_in_progress = false;
	sg_policy->limits_changed = false;
	sg_policy->cached_raw_freq = 0;

	sg_policy->need_freq_update = cpufreq_driver_test_flags(CPUFREQ_NEED_UPDATE_LIMITS);

	for_each_cpu(cpu, policy->cpus) {
		struct sugov_cpu *sg_cpu = &per_cpu(sugov_cpu, cpu);

		memset(sg_cpu, 0, sizeof(*sg_cpu));
		sg_cpu->cpu = cpu;
		sg_cpu->sg_policy = sg_policy;
		per_cpu(dvfs_update_delay, cpu) = sg_policy->tunables->rate_limit_us;
		sg_cpu->flags = SCHED_CPUFREQ_DL;
		sg_cpu->iowait_boost_max = policy->cpuinfo.max_freq;
	}

	for_each_cpu(cpu, policy->cpus) {
		struct sugov_cpu *sg_cpu = &per_cpu(sugov_cpu, cpu);

		cpufreq_add_update_util_hook(cpu, &sg_cpu->update_util,
					     policy_is_shared(policy) ?
							sugov_update_shared :
							sugov_update_single);
	}
	return 0;
}

static void sugov_stop(struct cpufreq_policy *policy)
{
	struct sugov_policy *sg_policy = policy->governor_data;
	unsigned int cpu;

	for_each_cpu(cpu, policy->cpus)
		cpufreq_remove_update_util_hook(cpu);

	synchronize_rcu();

	if (!policy->fast_switch_enabled) {
		irq_work_sync(&sg_policy->irq_work);
		kthread_cancel_work_sync(&sg_policy->work);
	}
}

static void sugov_limits(struct cpufreq_policy *policy)
{
	struct sugov_policy *sg_policy = policy->governor_data;
	unsigned long flags, now;
	unsigned int freq;

	if (!policy->fast_switch_enabled) {
		mutex_lock(&sg_policy->work_lock);
		cpufreq_policy_apply_limits(policy);
		mutex_unlock(&sg_policy->work_lock);
	} else {
		raw_spin_lock_irqsave(&sg_policy->update_lock, flags);
		freq = policy->cur;
		now = ktime_get_ns();

		/*
		 * cpufreq_driver_resolve_freq() has a clamp, so we do not need
		 * to do any sort of additional validation here.
		 */
		freq = cpufreq_driver_resolve_freq(policy, freq);
		sg_policy->cached_raw_freq = freq;
		sugov_fast_switch(sg_policy, now, freq);
		raw_spin_unlock_irqrestore(&sg_policy->update_lock, flags);
	}

	WRITE_ONCE(sg_policy->limits_changed, true);
}

static struct cpufreq_governor schedutil_gov = {
	.name = "schedutil",
	.owner = THIS_MODULE,
	.dynamic_switching = true,
	.init = sugov_init,
	.exit = sugov_exit,
	.start = sugov_start,
	.stop = sugov_stop,
	.limits = sugov_limits,
};

#ifdef CONFIG_CPU_FREQ_DEFAULT_GOV_SCHEDUTIL
struct cpufreq_governor *cpufreq_default_governor(void)
{
	return &schedutil_gov;
}
#endif

cpufreq_governor_init(schedutil_gov);
