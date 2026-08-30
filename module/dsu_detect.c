// SPDX-License-Identifier: GPL-2.0-only
#include <linux/namei.h>
#include <linux/path.h>

#include "dsu_config.h"
#include "dsu_detect.h"

#define DSU_BOOTED_MARKER "/metadata/gsi/dsu/booted"
#define DSU_AVB_ENFORCE_MARKER "/metadata/gsi/dsu/avb_enforce"

static bool path_exists(const char *name)
{
	struct path path;

	if (kern_path(name, LOOKUP_FOLLOW, &path))
		return false;

	path_put(&path);
	return true;
}

bool dsu_detect_active(void)
{
	/*
	 * AOSP first-stage init 会在判断 DSU 前删除旧标记，并且只在 DSU
	 * 映射成功后重新创建该标记；这也是 IsGsiRunning() 的唯一条件。
	 *
	 * always_avb 模式：即使非 DSU 正常启动也生效。仍受
	 * dsu_detect_avb_enforced() 约束——用户置位 avb_enforce 标记即硬拒绝。
	 */
	if (dsu_config_always_avb())
		return true;
	return path_exists(DSU_BOOTED_MARKER);
}

bool dsu_detect_avb_enforced(void)
{
	/*
	 * 任何模式下都尊重该标记：它代表用户明确要强制 AVB，模块必须完全
	 * 透传、不篡改任何视图。always_avb 开关也不能覆盖它。
	 */
	return path_exists(DSU_AVB_ENFORCE_MARKER);
}
