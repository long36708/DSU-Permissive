// SPDX-License-Identifier: GPL-2.0-only
typedef unsigned long size_t;

#define AT_FDCWD (-100L)
#define O_RDONLY 0L
#define O_WRONLY 1L
#define O_CREAT 0100L
#define O_TRUNC 01000L
#define O_CLOEXEC 02000000L
#define O_NOFOLLOW 0400000L

#define SYS_OPENAT 56L
#define SYS_CLOSE 57L
#define SYS_UNLINKAT 35L
#define SYS_READ 63L
#define SYS_WRITE 64L
#define SYS_EXECVE 221L
#define SYS_FINIT_MODULE 273L

#define ERR_EEXIST (-17L)
#define ERR_ENOENT (-2L)

#define MODULE_CONFIG_CAPACITY 96U
#define MODULE_PARAMS_CAPACITY 96U
#define FAILCOUNT_PATH "/dsu_permissive_failcount"
#define FAILCOUNT_THRESHOLD 2
#define FAILCOUNT_CAPACITY 16U

static int log_fd = 2;

static long raw_syscall1(long number, long argument0)
{
	register long x0 __asm__("x0") = argument0;
	register long x8 __asm__("x8") = number;

	__asm__ volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory", "cc");
	return x0;
}

static long raw_syscall3(long number, long argument0, long argument1,
			 long argument2)
{
	register long x0 __asm__("x0") = argument0;
	register long x1 __asm__("x1") = argument1;
	register long x2 __asm__("x2") = argument2;
	register long x8 __asm__("x8") = number;

	__asm__ volatile("svc #0" : "+r"(x0)
			 : "r"(x1), "r"(x2), "r"(x8) : "memory", "cc");
	return x0;
}

static long raw_syscall4(long number, long argument0, long argument1,
			 long argument2, long argument3)
{
	register long x0 __asm__("x0") = argument0;
	register long x1 __asm__("x1") = argument1;
	register long x2 __asm__("x2") = argument2;
	register long x3 __asm__("x3") = argument3;
	register long x8 __asm__("x8") = number;

	__asm__ volatile("svc #0" : "+r"(x0)
			 : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
			 : "memory", "cc");
	return x0;
}

static size_t string_length(const char *text)
{
	size_t length = 0;

	while (text[length])
		++length;
	return length;
}

static void write_log(const char *text)
{
	raw_syscall3(SYS_WRITE, log_fd, (long)text, string_length(text));
}

static size_t append_text(char *buffer, size_t capacity, size_t cursor,
			  const char *text)
{
	while (*text && cursor < capacity)
		buffer[cursor++] = *text++;
	return cursor;
}

static size_t append_number(char *buffer, size_t capacity, size_t cursor,
			    long value)
{
	char digits[32];
	unsigned long magnitude;
	size_t digit_cursor = sizeof(digits);

	magnitude = value < 0 ? (unsigned long)(-(value + 1)) + 1 :
			       (unsigned long)value;
	do {
		digits[--digit_cursor] = '0' + magnitude % 10;
		magnitude /= 10;
	} while (magnitude);
	if (value < 0)
		digits[--digit_cursor] = '-';

	while (digit_cursor < sizeof(digits) && cursor < capacity)
		buffer[cursor++] = digits[digit_cursor++];
	return cursor;
}

static int consume_text(const char *buffer, size_t length, size_t *cursor,
			const char *expected)
{
	while (*expected) {
		if (*cursor == length || buffer[*cursor] != *expected)
			return 0;
		++*cursor;
		++expected;
	}
	return 1;
}

static int parse_module_config(const char *buffer, size_t length,
			       char *parameters, size_t capacity)
{
	size_t cursor = 0;
	size_t output = 0;
	char selinux_value;
	char avb_value;
	char verity_table_value;
	char always_avb_value;

	if (!consume_text(buffer, length, &cursor, "selinux_intercept=") ||
	    cursor == length)
		return 0;
	selinux_value = buffer[cursor++];
	if ((selinux_value != '0' && selinux_value != '1') ||
	    !consume_text(buffer, length, &cursor, "\navb_intercept=") ||
	    cursor == length)
		return 0;
	avb_value = buffer[cursor++];
	if (avb_value != '0' && avb_value != '1')
		return 0;

	/*
	 * format=3 used two switches; format=4 added verity_table_spoof.
	 * Keep accepting both so a loader update can safely replace an older
	 * image; the then-absent mode stays at the module default (disabled).
	 */
	verity_table_value = '\0';
	if (cursor != length) {
		if (cursor + 1 == length && buffer[cursor] == '\n')
			goto parsed;
		if (!consume_text(buffer, length, &cursor,
				  "\nverity_table_spoof=") || cursor == length)
			return 0;
		verity_table_value = buffer[cursor++];
		if ((verity_table_value != '0' && verity_table_value != '1') ||
		    (cursor == length ||
		     (cursor + 1 == length && buffer[cursor] != '\n')))
			return 0;
	}

	always_avb_value = '\0';
	if (cursor != length) {
		if (cursor + 1 == length && buffer[cursor] == '\n')
			goto parsed;
		if (!consume_text(buffer, length, &cursor,
				  "\nalways_avb=") || cursor == length)
			return 0;
		always_avb_value = buffer[cursor++];
		if ((always_avb_value != '0' && always_avb_value != '1') ||
		    (cursor != length &&
		     (cursor + 1 != length || buffer[cursor] != '\n')))
			return 0;
	}

parsed:
	output = append_text(parameters, capacity - 1, output,
			     "selinux_intercept=");
	if (output == capacity - 1)
		return 0;
	parameters[output++] = selinux_value;
	output = append_text(parameters, capacity - 1, output, " avb_intercept=");
	if (output == capacity - 1)
		return 0;
	parameters[output++] = avb_value;
	if (verity_table_value) {
		output = append_text(parameters, capacity - 1, output,
				     " verity_table_spoof=");
		if (output == capacity - 1)
			return 0;
		parameters[output++] = verity_table_value;
	}
	if (always_avb_value) {
		output = append_text(parameters, capacity - 1, output,
				     " always_avb=");
		if (output == capacity - 1)
			return 0;
		parameters[output++] = always_avb_value;
	}
	parameters[output] = '\0';
	return 1;
}

static void write_error(const char *operation, long error)
{
	char buffer[256];
	size_t cursor = 0;

	cursor = append_text(buffer, sizeof(buffer), cursor, "<3>dsuinit：");
	cursor = append_text(buffer, sizeof(buffer), cursor, operation);
	cursor = append_text(buffer, sizeof(buffer), cursor, "失败，错误码 ");
	cursor = append_number(buffer, sizeof(buffer), cursor, error);
	cursor = append_text(buffer, sizeof(buffer), cursor, "\n");
	raw_syscall3(SYS_WRITE, log_fd, (long)buffer, cursor);
}

static void setup_log(void)
{
	long result;

	result = raw_syscall4(SYS_OPENAT, AT_FDCWD, (long)"/dev/kmsg",
			      O_WRONLY | O_CLOEXEC, 0);
	if (result >= 0)
		log_fd = (int)result;
}

/*
 * 熔断计数：dsuinit 在加载 KO 前读取并自增；若连续失败达到阈值则跳过加载，
 * 回退到原始启动行为。second-stage 成功后由内核模块删除该文件清零。
 * 任何读写失败都按"保守"处理：读不出当 0，写不出则跳过加载（fail-safe）。
 */
static long read_failcount(void)
{
	char buffer[FAILCOUNT_CAPACITY];
	long file;
	long result;
	long value = 0;
	size_t index = 0;

	file = raw_syscall4(SYS_OPENAT, AT_FDCWD, (long)FAILCOUNT_PATH,
			    O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
	if (file == ERR_ENOENT)
		return 0;
	if (file < 0)
		return 0;

	result = raw_syscall3(SYS_READ, file, (long)buffer, sizeof(buffer));
	raw_syscall1(SYS_CLOSE, file);
	if (result <= 0)
		return 0;

	while (index < (size_t)result && buffer[index] >= '0' &&
	       buffer[index] <= '9') {
		value = value * 10 + (buffer[index] - '0');
		if (value > FAILCOUNT_THRESHOLD + 8)
			value = FAILCOUNT_THRESHOLD + 8;
		++index;
	}
	return value;
}

static int write_failcount(long value)
{
	char buffer[FAILCOUNT_CAPACITY];
	size_t length = 0;
	size_t i, j;
	long file;
	long result;

	if (value <= 0)
		value = 0;
	/* 先逆序分解各位，再整理解出正序写入（高位在前）。 */
	do {
		buffer[length++] = '0' + (int)(value % 10);
		value /= 10;
	} while (value && length < sizeof(buffer));

	for (i = 0, j = length; i < j; ++i, --j) {
		char tmp = buffer[i];
		buffer[i] = buffer[j - 1];
		buffer[j - 1] = tmp;
	}

	file = raw_syscall4(SYS_OPENAT, AT_FDCWD, (long)FAILCOUNT_PATH,
			    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
			    0600);
	if (file < 0)
		return -1;
	result = raw_syscall3(SYS_WRITE, file, (long)buffer, length);
	raw_syscall1(SYS_CLOSE, file);
	return result == (long)length ? 0 : -1;
}

static void load_module_parameters(char *parameters, size_t capacity)
{
	char config[MODULE_CONFIG_CAPACITY];
	long file;
	long result;

	parameters[0] = '\0';
	file = raw_syscall4(SYS_OPENAT, AT_FDCWD,
			    (long)"/dsu_permissive.conf",
			    O_RDONLY | O_CLOEXEC | O_NOFOLLOW, 0);
	if (file == ERR_ENOENT) {
		write_log("<4>dsuinit：未找到内嵌配置，使用模块默认开关\n");
		return;
	}
	if (file < 0) {
		write_error("打开 /dsu_permissive.conf ", file);
		return;
	}
	result = raw_syscall3(SYS_UNLINKAT, AT_FDCWD,
			      (long)"/dsu_permissive.conf", 0);
	if (result < 0) {
		write_error("移除 /dsu_permissive.conf ", result);
		write_log("<3>dsuinit：配置仍有路径，拒绝读取并使用模块默认开关\n");
		raw_syscall1(SYS_CLOSE, file);
		return;
	}

	result = raw_syscall3(SYS_READ, file, (long)config,
			      MODULE_CONFIG_CAPACITY);
	raw_syscall1(SYS_CLOSE, file);
	if (result < 0) {
		write_error("读取 /dsu_permissive.conf ", result);
		return;
	}
	if ((size_t)result == MODULE_CONFIG_CAPACITY ||
	    !parse_module_config(config, (size_t)result, parameters, capacity)) {
		write_log("<3>dsuinit：内嵌配置无效，使用模块默认开关\n");
		parameters[0] = '\0';
		return;
	}
	write_log("<6>dsuinit：已加载并移除 init_boot 内嵌开关\n");
}

static void load_module(void)
{
	long file;
	long result;
	long failcount;
	char parameters[MODULE_PARAMS_CAPACITY];

	/*
	 * 熔断：连续失败达阈值则跳过加载，原样启动，避免无法开机。
	 * 先读取计数，达到阈值直接放弃；否则先自增（在加载前标记本次尝试），
	 * 这样一旦 KO 导致崩溃，下次重启读到的就是 +1 的值。
	 */
	failcount = read_failcount();
	if (failcount >= FAILCOUNT_THRESHOLD) {
		write_log("<3>dsuinit：熔断计数已达 ");
		{
			char num[4];
			size_t i = 0;

			num[i++] = '0' + (int)(failcount % 10);
			write_log(num);
		}
		write_log("，跳过 KO 加载，回退原始启动（请用 repatch 工具重置配置）\n");
		return;
	}
	if (write_failcount(failcount + 1)) {
		/*
		 * 写计数失败（如只读 fs）：保守跳过加载，宁可不用功能也不冒
		 * 无法回退的风险。
		 */
		write_log("<3>dsuinit：无法写入熔断计数，保守跳过 KO 加载\n");
		return;
	}

	file = raw_syscall4(SYS_OPENAT, AT_FDCWD,
			    (long)"/dsu_permissive.ko",
			    O_RDONLY | O_CLOEXEC, 0);
	if (file < 0) {
		write_error("打开 /dsu_permissive.ko ", file);
		return;
	}

	load_module_parameters(parameters, sizeof(parameters));
	result = raw_syscall3(SYS_FINIT_MODULE, file, (long)parameters, 0);
	raw_syscall1(SYS_CLOSE, file);
	if (result == 0) {
		write_log("<6>dsuinit：dsu_permissive.ko 已加载\n");
	} else if (result == ERR_EEXIST) {
		write_log("<4>dsuinit：模块已存在，继续执行原 init 链\n");
	} else {
		write_error("加载 dsu_permissive.ko ", result);
	}
}

static long execute(const char *path, char **arguments, char **environment)
{
	long result = raw_syscall3(SYS_EXECVE, (long)path, (long)arguments,
				   (long)environment);

	write_error(path, result);
	return result;
}

int dsuinit_main(long argument_count, char **arguments, char **environment)
{
	(void)argument_count;
	setup_log();
	write_log("<6>dsuinit：开始加载 DSU-Permissive\n");
	load_module();

	execute("/init.next", arguments, environment);
	execute("/init.real", arguments, environment);
	execute("/system/bin/init", arguments, environment);
	write_log("<0>dsuinit：所有 init 执行路径均失败，停止启动\n");
	return 127;
}
