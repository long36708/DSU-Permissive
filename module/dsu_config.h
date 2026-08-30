/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef DSU_PERMISSIVE_CONFIG_H
#define DSU_PERMISSIVE_CONFIG_H

#include <linux/types.h>

#define DSU_CONFIG_PATH "/dsu_permissive.conf"

/* loader 熔断计数文件名；KO 加载前由 dsuinit 维护，second-stage 成功后由模块清零。 */
#define DSU_FAILCOUNT_PATH "/dsu_permissive_failcount"
/* 连续失败达到该次数后，dsuinit 自动跳过 KO 加载，回退到原始启动行为。 */
#define DSU_FAILCOUNT_THRESHOLD 2

bool dsu_config_selinux_intercept(void);
bool dsu_config_avb_intercept(void);
bool dsu_config_verity_table_spoof(void);
bool dsu_config_always_avb(void);

#endif
