#include <bpf/libbpf_legacy.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include "execve_counter.skel.h"

typedef __u64 u64;
typedef char stringkey[64];

static int libbpf_print_fn(enum libbpf_print_level level, const char * format, va_list args)
{
  return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
  struct execve_counter_bpf *skel;
  int err;

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  libbpf_set_print(libbpf_print_fn);
  
  // open BPF application
  // 被定义在生成的 execve_counter.skel.h 文件中
  skel = execve_counter_bpf__open();
  if (!skel) {
    fprintf(stderr, "failed to open bpf skeleton\n");
    return 1;
  }

  // load & verify bpf program
  // map是在execve_counter_bpf__load中完成的创建，跟踪代码你会发现(参考libbpf源码)，最终会调用bpf系统调用创建map
  err = execve_counter_bpf__load(skel);
  if(err) {
    fprintf(stderr, "failed to load and verify bpf skeleton\n");
    goto cleanup;
  }

  // init the counter
  stringkey key = "execve_counter";
  u64 v = 0;
  // 创建 map ，bpf_map__update_elem 可以在 libbpf.h 中找到相关定义
  // 在attach handler之前，先使用libbpf封装的bpf_map__update_elem初始化了bpf map中的key(初始化为0，如果没有这一步，第一次bpf程序执行时，会提示找不到key
  err = bpf_map__update_elem(skel->maps.execve_counter, &key, sizeof(key), &v, sizeof(v), BPF_ANY);
  if (err != 0){
    fprintf(stderr,  "failed to init the counter, %d\n", err);
    goto cleanup;
  }

  // attach tracepoint handler
  err = execve_counter_bpf__attach(skel);
  if (err){
    fprintf(stderr, "failed to attach bpf skeleton\n");
    goto cleanup;
  }

  for (;;){
    //read counter value from map
    // 用于获取 map 数据 bpf_map__lookup_elem 可以在 libbpf.h 中找到相关定义
    err = bpf_map__lookup_elem(skel->maps.execve_counter,&key,sizeof(key),&v,sizeof(v),BPF_ANY);
    if (err!=0){
      fprintf(stderr, "lookup key from map err: %d\n", err);
      goto cleanup;
    }else{
      printf("execve_counter is %llu\n", v);
    }

    sleep(5);
  }

cleanup:
  execve_counter_bpf__destroy(skel);
  return -err;
}
