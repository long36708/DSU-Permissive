// SPDX-License-Identifier: GPL-2.0-only
#include <linux/moduleparam.h>
#include <linux/types.h>

#include "dsu_config.h"

static bool selinux_intercept = true;
static bool avb_intercept = true;
static bool verity_table_spoof;
static bool always_avb;

/* 参数仅在 finit_module() 时使用；不创建可被后续程序读取的 sysfs 节点。 */
module_param(selinux_intercept, bool, 0000);
MODULE_PARM_DESC(selinux_intercept,
		 "是否启用 DSU 启动期 SELinux 拦截");
module_param(avb_intercept, bool, 0000);
MODULE_PARM_DESC(avb_intercept, "是否启用 DSU first-stage AVB 拦截");
module_param(verity_table_spoof, bool, 0000);
MODULE_PARM_DESC(verity_table_spoof,
		 "是否将匹配的 DSU first-stage dm-verity 表统一伪装为 linear");
module_param(always_avb, bool, 0000);
MODULE_PARM_DESC(always_avb,
		 "是否对正常（非 DSU）启动也启用 AVB 视图篡改；默认关闭，仅 DSU 生效");

bool dsu_config_selinux_intercept(void)
{
	return selinux_intercept;
}

bool dsu_config_avb_intercept(void)
{
	return avb_intercept;
}

bool dsu_config_verity_table_spoof(void)
{
	/*
	 * 表伪装是 DSU 无-footer GSI 专用绕过，依赖 DSU 映射名 *_gsi。
	 * 正常（非 DSU）启动下强制关闭，避免拿有效 hashtree 的分区做 linear
	 * 直读而破坏完整性；dm_ioctl_proxy 亦以 avb_enforced/模式做二次约束。
	 */
	if (!dsu_config_always_avb())
		return verity_table_spoof;
	return false;
}

bool dsu_config_always_avb(void)
{
	return always_avb;
}
