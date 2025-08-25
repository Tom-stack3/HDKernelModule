#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/seq_file.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Me");
MODULE_DESCRIPTION("Nothing much...");

void change_module_name(void);

void change_module_name(void)
{
    // See with lsmod

    char new_name[] = "Yo dude I've changed";
    const int l = strlen(new_name);
    strncpy(__this_module.name, new_name, l);
    __this_module.name[l] = '\x00';
}

static int __init hdkm_init(void)
{
    pr_info("hdkm_proc: module loaded\n");
    change_module_name();
    return 0;
}

static void __exit hdkm_exit(void)
{
    pr_info("hdkm_proc: module unloaded\n");
}

module_init(hdkm_init);
module_exit(hdkm_exit);
