#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>
#include <linux/stop_machine.h>
#include <asm/cacheflush.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Me");
MODULE_DESCRIPTION("Nothing much...");

static void change_module_name(void);
static unsigned long my_lookup_address(const char *name);

static void change_module_name(void)
{
    // See with lsmod

    char new_name[] = "Yo dude I've changed";
    const int l = strlen(new_name);
    strncpy(__this_module.name, new_name, l);
    __this_module.name[l] = '\x00';
}

static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name",
};
static struct kprobe first_try_forbidden_kp = {
    .symbol_name = "io_idle",
};
static struct kprobe second_try_forbidden_kp = {
    .symbol_name = "io_idle",
};

static unsigned long kallsyms_lookup_name_addr = 0;
static unsigned long io_idle_addr = 0;

static int register_kp(void)
{
    int er;
    if ((er = register_kprobe(&kp)) < 0)
    {
        pr_err("hdkm: failed registering\n");
        printk("hdkm: err: %d\n", er);
        return er;
    }
    pr_err("hdkm: registered successfully!");
    kallsyms_lookup_name_addr = (unsigned long)(kp.addr);
    pr_info("hdkm: kallsyms_lookup_name @ %lx", kallsyms_lookup_name_addr);
    return 0;
}

static int try_register_blacklisted_kp(struct kprobe *kp_struct)
{
    int er;
    if ((er = register_kprobe(kp_struct)) < 0)
    {
        pr_err("hdkm: failed registering\n");
        printk("hdkm: err: %d\n", er);
        return er;
    }
    pr_err("hdkm: registered successfully!\n");
    io_idle_addr = (unsigned long)(kp_struct->addr);
    pr_info("hdkm: io_idle_addr @ %lx\n", io_idle_addr);
    return 0;
}

struct patch_args
{
    unsigned long addr;
    int rc;
};

static int patch_within_kprobe_blacklist(void *args_struct)
{
    // Do as the following gdb commands:
    // x/1bx &addr+231+1  # Verify that there's 0x01 there
    // set {unsigned char}(&addr+231+1) = 0x00

    struct patch_args *pa = args_struct;
    unsigned char *p = (unsigned char *)(pa->addr + 231 + 1);
    unsigned char curr;
    void *(*text_poke)(void *addr, const void *opcode, size_t len);
    char op[1] = "\x00";

    curr = *p;
    if (curr != 0x01)
    {
        pr_err("Unexpected value at %px: 0x%02x (expected 0x01)\n", p, (curr & 0xFF));
        pa->rc = -EINVAL;
        return 0;
    }

    text_poke = (void *(*)(void *, const void *, size_t))my_lookup_address("text_poke");

    text_poke((void *)p, op, 1);

    flush_icache_range((unsigned long)p, (unsigned long)p + 1);
    pr_info("flush_icache_range called on: %lx, %lx\n", (unsigned long)p, (unsigned long)p + 1);

    curr = *p;
    if (curr != 0x00)
    {
        pr_err("Unexpected value at %px: 0x%02x (expected 0x01)\n", p, (curr & 0xFF));
        pa->rc = -EINVAL;
        return 0;
    }

    pr_info("Patched %px: 0x01 -> 0x00\n", (void *)p);
    pa->rc = 0;
    return 0;
}

static unsigned long my_lookup_address(const char *name)
{
    unsigned long r = 0;
    if (kallsyms_lookup_name_addr == 0)
    {
        return 0;
    }
    unsigned long (*my_kallsyms_lookup_name)(const char *) = (unsigned long (*)(const char *))kallsyms_lookup_name_addr;
    r = my_kallsyms_lookup_name(name);
    pr_info("my_lookup_address returning: %lx\n", r);
    return r;
}

static int __init hdkm_init(void)
{
    pr_info("hdkm: module loaded\n");
    // Change module name in memory
    change_module_name();

    // kprobe on kallsyms_lookup_name to find it's address
    if (register_kp() != 0)
    {
        pr_err("hdkm: Failed kprobing kallsyms_lookup_name method\n");
        return -1;
    }

    // Find some interesting functions using kallsyms_lookup_name
    pr_info("hdkm: kallsyms_lookup_name @ %lx\n", my_lookup_address("kallsyms_lookup_name")); // Note the 4 bytes difference between the address kprobe returned...
    pr_info("hdkm: kill_something_info @ %lx\n", my_lookup_address("kill_something_info"));
    pr_info("hdkm: entry_SYSCALL_64 @ %lx\n", my_lookup_address("entry_SYSCALL_64"));
    pr_info("hdkm: io_idle @ %lx\n", my_lookup_address("io_idle"));

    // Print 8 bytes at the address of kallsyms_lookup_name to see the 0xCC byte put by kprobe.
    unsigned char *b = (unsigned char *)my_lookup_address("kallsyms_lookup_name");
    printk("hdkm: bytes at kallsyms_lookup_name (with kprobe): ");
    for (int i = 0; i < 8; i++)
    {
        printk("%02x", b[i] & 0xff);
    }
    printk("\n");
    // Unregister kprobe and print again
    unregister_kprobe(&kp);
    printk("unregistered kprobe\n");
    b = (unsigned char *)my_lookup_address("kallsyms_lookup_name");
    printk("hdkm: bytes at kallsyms_lookup_name (original):\n");
    for (int i = 0; i < 8; i++)
    {
        printk("%02x", b[i] & 0xff);
    }
    printk("\n");

    // Try kprobe function within kprobe blacklist
    if (try_register_blacklisted_kp(&first_try_forbidden_kp) != 0)
    {
        pr_err("hdkm: As expected, failed kprobing io_idle method\n");
    }
    else
    {
        pr_err("hdkm: Unexpected, successfully kprobing io_idle method\n");
        return -1;
    }
    // Patch within_kprobe_blacklist to return always return true
    // Run on one CPU and stop others
    struct patch_args pa = {
        .addr = my_lookup_address("within_kprobe_blacklist"),
        .rc = 0,
    };
    stop_machine(patch_within_kprobe_blacklist, &pa, NULL);

    // This time should succeeded
    if (try_register_blacklisted_kp(&second_try_forbidden_kp) != 0)
    {
        pr_err("hdkm: Unexpected, failed kprobing io_idle method\n");
        return -1;
    }
    pr_info("hdkm: Great success!\n");

    return 0;
}

static void __exit hdkm_exit(void)
{
    pr_info("hdkm: module unloaded\n");
}

module_init(hdkm_init);
module_exit(hdkm_exit);
