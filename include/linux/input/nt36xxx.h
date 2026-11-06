/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _LINUX_INPUT_NT36XXX_H
#define _LINUX_INPUT_NT36XXX_H

#include <linux/types.h>

#if IS_ENABLED(CONFIG_TOUCHSCREEN_NT36xxx_HOSTDL_SPI)
void nvt_set_charger_mode(bool plugged_in);
#else
static inline void nvt_set_charger_mode(bool plugged_in) {}
#endif

#endif /* _LINUX_INPUT_NT36XXX_H */
