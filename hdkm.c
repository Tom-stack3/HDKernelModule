#include <linux/kernel.h> 
#include <linux/init.h>
#include <linux/module.h>
#include <linux/seq_file.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Me");
MODULE_DESCRIPTION("Nothing much...");

void hook_on_proc_func(void);

static int __init hdkm_init(void)
{
    pr_info("hdkm_proc: module loaded\n");
    return 0;
}

static void __exit hdkm_exit(void)
{
    pr_info("hdkm_proc: module unloaded\n");
}

module_init(hdkm_init);
module_exit(hdkm_exit);
