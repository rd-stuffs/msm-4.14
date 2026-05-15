// SPDX-License-Identifier: GPL-2.0
#include <linux/jiffies.h>
#include <linux/export.h>

__visible u64 jiffies_64 __cacheline_aligned_in_smp = INITIAL_JIFFIES;
EXPORT_SYMBOL(jiffies_64);
