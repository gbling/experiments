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
  skel = execve_counter_bpf__open();
  if (!skel) {
    fprintf(stderr, "failed to open bpf skeleton\n");
    return 1;
  }

  // load & verify bpf program
  err = execve_counter_bpf__load(skel);
  if(err) {
    fprintf(stderr, "failed to load and verify bpf skeleton\n");
    goto cleanup;
  }

  // init the counter
  stringkey key = "execve_counter";
  u64 v = 0;
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
