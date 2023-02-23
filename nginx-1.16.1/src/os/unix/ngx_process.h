
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_PROCESS_H_INCLUDED_
#define _NGX_PROCESS_H_INCLUDED_


#include <ngx_setaffinity.h>
#include <ngx_setproctitle.h>


typedef pid_t       ngx_pid_t;

#define NGX_INVALID_PID  -1

typedef void (*ngx_spawn_proc_pt) (ngx_cycle_t *cycle, void *data);

typedef struct {
    ngx_pid_t           pid;                // 进程id
    int                 status;             // 进程状态
    ngx_socket_t        channel[2];         // socket pair创建的socket句柄，用于父子进程通信

    ngx_spawn_proc_pt   proc;               // 进程执行函数
    void               *data;               // 进程执行函数的参数
    char               *name;               // 进程名称

    unsigned            respawn:1;          // 重新创建
    unsigned            just_spawn:1;       // 第一次创建
    unsigned            detached:1;         // 分离的
    unsigned            exiting:1;
    unsigned            exited:1;
} ngx_process_t;


typedef struct {
    char         *path;
    char         *name;
    char *const  *argv;
    char *const  *envp;
} ngx_exec_ctx_t;


#define NGX_MAX_PROCESSES         1024
// cache loader会用到，当第一次启动的时候，使用NGX_PROCESS_NORESPAWN，就是启动一个进程执行ngx_cache_manager_process_cycle.
// 但需要注意和上面的DETACHED的区别，因为在nginx里，一般父子进程都有很多管道通讯，只有DETACHED的模式下没有pipe通讯，
// 这个NORESPAWN是保留了和父进程的管道通讯的
// 但是当重新加载配置的时候，还是继续使用NGX_PROCESS_JUST_SPAWN来区分新欢旧爱的
#define NGX_PROCESS_NORESPAWN     -1
// just:刚刚搞出来的，别动我，只动就的，用于区分新旧
// respawn:本进程被master管理，死的时候可以自动拉起
// spwawn由于前面没有re，只是fork出来就拉倒，所以JUST_SPAWN只有just是有含义的
#define NGX_PROCESS_JUST_SPAWN    -2
// 当worker进程因为意外退出的时候，master进程会执行再生(respawn)操作。
#define NGX_PROCESS_RESPAWN       -3
// just是刚刚的意思，刚刚spawn出来的，用于更新配置的时候，因为更新配置执行如下的步骤
// 1.master加载新配置文件
// 2.fork新的worker进程
// 3.给使用旧配置文件的worker进程发QUIT信号
// 第二步fork进程的时候腰加上NGX_PROCESS_JUST_RESPAWN这个标志，用于给第三步区分哪些是旧进程，哪些是新欢。
#define NGX_PROCESS_JUST_RESPAWN  -4
// fork出来的进程和父进程没有管理的关系
// 比如nginx的master升级（老版本有bug）,新的master从旧的mastr fork出来，就需要这样的标志，fork出来后和父进程没啥关系
#define NGX_PROCESS_DETACHED      -5


#define ngx_getpid   getpid
#define ngx_getppid  getppid

#ifndef ngx_log_pid
#define ngx_log_pid  ngx_pid
#endif


ngx_pid_t ngx_spawn_process(ngx_cycle_t *cycle,
    ngx_spawn_proc_pt proc, void *data, char *name, ngx_int_t respawn);
ngx_pid_t ngx_execute(ngx_cycle_t *cycle, ngx_exec_ctx_t *ctx);
ngx_int_t ngx_init_signals(ngx_log_t *log);
void ngx_debug_point(void);


#if (NGX_HAVE_SCHED_YIELD)
#define ngx_sched_yield()  sched_yield()
#else
#define ngx_sched_yield()  usleep(1)
#endif


extern int            ngx_argc;
extern char         **ngx_argv;
extern char         **ngx_os_argv;

extern ngx_pid_t      ngx_pid;
extern ngx_pid_t      ngx_parent;
extern ngx_socket_t   ngx_channel;
extern ngx_int_t      ngx_process_slot;
extern ngx_int_t      ngx_last_process;
extern ngx_process_t  ngx_processes[NGX_MAX_PROCESSES];


#endif /* _NGX_PROCESS_H_INCLUDED_ */
