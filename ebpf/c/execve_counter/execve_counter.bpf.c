#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

typedef __u64 u64;
// 表示创建了一个名为 stringkey 的新类型，该类型是一个包含 64 个字符的字符数组
typedef char stringkey[64];

// 定义 map 结构 execve_counter，通过 SEC 宏将其标记为BPF MAP变量
struct {
    // __uint 是在 /usr/include/bpf/bpf_helpers.h 中定义的宏
    /*
        #define __uint(name, val) int (*name)[val]
        #define __type(name, val) typeof(val) *name
        #define __array(name, val) typeof(val) *name[]
    */
    
    // __uint(type, BPF_MAP_TYPE_HASH) 替换之后就是 int (*type)[BPF_MAP_TYPE_HASH]，是一个名字为 type 的数组指针
    __uint(type, BPF_MAP_TYPE_HASH);
    
    // __uint(max_entries, 128) 替换之后就是 int (*max_entries)[128]
    __uint(max_entries, 128);
    
    stringkey* key;

    // __type 替换后就是 typeof(u64) *value，typeof 用于返回对象或函数的类型，这句实际的意思就是创建一个u64类型的指针名字为value
    __type(value, u64);
} execve_counter SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
    int bpf_prog(void *ctx)
{
    stringkey key = "execve_counter";
    u64 *v = NULL;

    // bpf_map_lookup_elem 通过 man bpf 可以找到对应的说明，原文为：
    // Look up an element by key in a specified map and return its value.
    // 用于查询 map 中具体某个 key 的 value
    v = bpf_map_lookup_elem(&execve_counter, &key);
    // 判断只要 v 不为空，每次就累加 1
    if (v != NULL){
        *v += 1;
    }
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
