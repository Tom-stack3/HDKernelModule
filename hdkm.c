#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/seq_file.h>
#include <linux/kprobes.h>

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
    .addr = 0,
};

static unsigned long kallsyms_lookup_name_addr = 0;

static int register_kp(void)
{
    int er;
    if ((er = register_kprobe(&kp)) < 0)
    {
        pr_err("hdkm: failed registering");
        printk("hdkm: err: %d\n", er);
        return er;
    }
    pr_err("hdkm: registered successfully!");
    kallsyms_lookup_name_addr = (unsigned long)(kp.addr);
    pr_info("hdkm: kallsyms_lookup_name @ %lx", kallsyms_lookup_name_addr);
    return 0;
}

static unsigned long my_lookup_address(const char *name)
{
    if (kallsyms_lookup_name_addr == 0)
    {
        return 0;
    }
    unsigned long (*my_kallsyms_lookup_name)(const char *) = (unsigned long (*)(const char *))kallsyms_lookup_name_addr;
    return my_kallsyms_lookup_name(name);
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
        return 1;
    }

    // Find some interesting functions using kallsyms_lookup_name
    pr_info("hdkm: kallsyms_lookup_name @ %lx\n", my_lookup_address("kallsyms_lookup_name"));
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
    printk("unregistered kprobe");
    b = (unsigned char *)my_lookup_address("kallsyms_lookup_name");
    printk("hdkm: bytes at kallsyms_lookup_name (original):");
    for (int i = 0; i < 8; i++)
    {
        printk("%02x", b[i] & 0xff);
    }
    printk("\n");

    return 0;
}

static void __exit hdkm_exit(void)
{
    pr_info("hdkm: module unloaded\n");
}

module_init(hdkm_init);
module_exit(hdkm_exit);
