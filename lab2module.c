#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/pid.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/sched.h>
#include <linux/types.h>
#include <linux/dcache.h>
#include <linux/fdtable.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <linux/page-flags.h>
#include <linux/pagemap.h>
#include <asm/io.h>



#define BUFFER_SIZE 1024

MODULE_LICENSE("Dual BSD/GPL");

static struct mutex lock;
static struct dentry *debug_dir;
static struct dentry *debug_file;
static struct task_struct* task = NULL;
static void print_page(struct seq_file *file, struct task_struct *task);
static void print_thread_struct(struct seq_file *file, struct task_struct *task);
static int print_struct(struct seq_file *file, void *data);

static ssize_t write_function(struct file *file, const char __user *buffer, size_t length, loff_t *ptr_offset) {
  char user_data[BUFFER_SIZE];
  unsigned long pid;
  copy_from_user(user_data, buffer, length);
  sscanf(user_data, "pid: %ld", &pid);
  task = get_pid_task(find_get_pid(pid),PIDTYPE_PID);
  single_open(file, print_struct, NULL);
  return strlen(user_data);
}

static int open_function(struct inode *inode, struct file *file){
  mutex_lock(&lock);
  return 0;
}

static int release_function(struct inode *inode, struct file *file){
  mutex_unlock(&lock);
  return 0;
}

static struct file_operations fops = {
  .read = seq_read,
  .write = write_function,
  .open = open_function,
  .release = release_function
};


static int __init mod_init(void) {
  mutex_init(&lock);
  debug_dir = debugfs_create_dir("lab2", NULL);
  debug_file = debugfs_create_file("filetocnange", 0777, debug_dir, NULL, &fops);
  return 0;
}

static void __exit mod_exit(void) {
  debugfs_remove_recursive(debug_dir);
}


static int print_struct(struct seq_file *file, void *data) {
  print_page(file, task);
  print_thread_struct(file, task);
  return 0;
}

static struct page *get_current_page(struct mm_struct* mm, long vr_address){
  pgd_t *pgd;
  p4d_t *p4d;
  pud_t *pud;
  pmd_t *pmd;
  pte_t *pte;
  struct page *page = NULL;
  pgd = pgd_offset(mm, vr_address);
  if (!pgd_present(*pgd)) {
    return NULL;
  }
  p4d = p4d_offset(pgd, vr_address);
  if (!p4d_present(*p4d)) {
    return NULL;
  }
  pud = pud_offset(p4d, vr_address);
  if (!pud_present(*pud)) {
    return NULL;
  }
  pmd = pmd_offset(pud, vr_address);
  if (!pmd_present(*pmd)) {
    return NULL;
  }
  pte = pte_offset_kernel(pmd, vr_address);
  if (!pte_present(*pte)) {
    return NULL;
  }
  page = pte_page(*pte);
  return page;
}

static void print_page(struct seq_file *file, struct task_struct *task) {
  if (task == NULL){
    seq_printf(file, "Can't find page_struct with this PID\n"); 
  } else {
    struct page *page_struct;
    struct mm_struct *mm = task->mm;
    if (mm == NULL){
      seq_printf(file, "Can't find page_struct with this PID\n"); 
    } else {
      struct vm_area_struct *vm_area = mm->mmap;
      long vr_address;
      seq_printf(file, "page_struct\n");
      seq_printf(file, "%s\t%10s\t%5s\n","phys_address","vr_address","flags"); 
      for (vr_address = vm_area->vm_start; vr_address <= vm_area->vm_end; vr_address += PAGE_SIZE){
        page_struct = get_current_page(mm,vr_address);
	if (page_struct != NULL){       
	  seq_printf(file, "0x%lx",vr_address);   
	  seq_printf(file, "\t0x%lx\t",virt_to_phys(vr_address));
	  if (page_struct->flags & PG_locked){
            seq_printf(file,"lock ");
	  }
	  if (page_struct->flags & PG_referenced){
            seq_printf(file,"ref ");
	  }
	  if (page_struct->flags & PG_uptodate){
            seq_printf(file,"uptodate ");
	  }
	  if (page_struct->flags & PG_dirty){
            seq_printf(file,"dirty ");
	  }
	  if (page_struct->flags & PG_lru){
            seq_printf(file,"lru ");
	  }
	  if (page_struct->flags & PG_error){
            seq_printf(file,"error ");
	  }
	  seq_printf(file,"\n"); 
	}

      }
    }
  }	    
}

static void print_thread_struct(struct seq_file *file, struct task_struct *task) {
  if (task == NULL){
    seq_printf(file, "Can't find thread_struct with this PID\n"); 
  } else {
    seq_printf(file, "thread_struct : {\n");
    seq_printf(file, "\tStack pointer register = %lx\n",task->thread.sp);
    seq_printf(file, "\tExtra segment register(es) = %lx\n",task->thread.es);    
    seq_printf(file, "\tExtra segment register(fs) = %lx\n",task->thread.fsbase);
    seq_printf(file, "\tExtra segment register(gs) = %lx\n",task->thread.gsbase);
    seq_printf(file, "\tData segment register = %lx\n",task->thread.ds);
    seq_printf(file, "}\n");
  }
}


module_init(mod_init);
module_exit(mod_exit);
