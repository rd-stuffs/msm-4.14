/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2018-2019 Sultan Alsawaf <sultan@kerneltoast.com>.
 */
#ifndef _CPU_INPUT_BOOST_H_
#define _CPU_INPUT_BOOST_H_

#include <linux/types.h>

#ifdef CONFIG_CPU_INPUT_BOOST
extern unsigned int zygote_boost_duration;
extern unsigned int cgroup_boost_duration;
extern unsigned int reclaim_boost_duration;
void cpu_input_boost_kick(void);
void cpu_input_boost_kick_max(unsigned int duration_ms);
bool cpu_input_boost_within_input(unsigned long timeout_ms);
#else
#define zygote_boost_duration 0
#define cgroup_boost_duration 0
#define reclaim_boost_duration 0
static inline void cpu_input_boost_kick(void)
{
}
static inline void cpu_input_boost_kick_max(unsigned int duration_ms)
{
}
static inline bool cpu_input_boost_within_input(unsigned long timeout_ms)
{
	return true;
}
#endif

#endif /* _CPU_INPUT_BOOST_H_ */
