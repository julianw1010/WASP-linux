#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <stdint.h>
#include <stdarg.h>
#include <limits.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <linux/perf_event.h>
#include <linux/hw_breakpoint.h>
#include <linux/mempolicy.h>
#include <asm/unistd.h>

/*
 * WASP: Workload-Aware Self-Replicating Page-Tables (Simplified)
 * 
 * Implementation based on ASPLOS '24 paper by Qu & Yu.
 * Simplified steering: always use fastest replica for each thread.
 */

// ============================================================================
// 1. CONFIGURATION
// ============================================================================

#define DEBUG_MODE 1
#define LOG_FILE "/var/log/waspd.log"

#define PTL_TEST_SIZE      (16 * 4096)
#define PTL_STRIDE         4096
#define PTL_ITERATIONS     50
#define PTL_UPDATE_INTERVAL 1

static double cpu_ghz = 2.8;

static double THR_MAR = 10.0 * 1000000.0;
static double THR_DTLB = 0.01;

#define MAX_NUMA_NODES             8
#define MAX_EXCLUDED_NAMES         32
#define MAX_NAME_LEN               64

#define PR_SET_PGTABLE_REPL        100
#define PR_GET_PGTABLE_REPL        101
#define PR_SET_PGTABLE_REPL_NODE   102
#define PR_GET_PGTABLE_REPL_NODE   103

#define NODE_UNINITIALIZED         (-999)
#define NODE_AUTO                  (-1)

#define SYSCTL_INHERIT_PATH        "/proc/sys/kernel/mitosis_inherit"

volatile sig_atomic_t stop_requested = 0;
static FILE *log_fp = NULL;
static pid_t daemon_pid = 0;
static int latency_mode = 1;
static int ptl_interval = PTL_UPDATE_INTERVAL;

// Excluded program names
static char excluded_names[MAX_EXCLUDED_NAMES][MAX_NAME_LEN];
static int num_excluded = 0;

static void print_mitosis_status(void);
static void get_process_name(pid_t pid, char *name, size_t len);

typedef struct {
    double latencies[MAX_NUMA_NODES];
    volatile int ready;
} ptl_result_t;

// ============================================================================
// 2. LOGGING
// ============================================================================

static void log_msg(const char *level, const char *fmt, ...) {
    va_list args;
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char time_buf[32];
    
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    
    if (log_fp) {
        fprintf(log_fp, "[%s] [%s] ", time_buf, level);
        va_start(args, fmt);
        vfprintf(log_fp, fmt, args);
        va_end(args);
        fprintf(log_fp, "\n");
        fflush(log_fp);
    }
    
    if (DEBUG_MODE) {
        printf("[%s] [%s] ", time_buf, level);
        va_start(args, fmt);
        vprintf(fmt, args);
        va_end(args);
        printf("\n");
        fflush(stdout);
    }
}

#define LOG_INFO(...)  log_msg("INFO", __VA_ARGS__)
#define LOG_WARN(...)  log_msg("WARN", __VA_ARGS__)
#define LOG_ERROR(...) log_msg("ERROR", __VA_ARGS__)
#define LOG_DEBUG(...) do { if (DEBUG_MODE) log_msg("DEBUG", __VA_ARGS__); } while(0)

// ============================================================================
// 3. LOW-LEVEL HELPERS
// ============================================================================

static inline uint64_t rdtsc_fenced(void) {
    uint32_t lo, hi;
    asm volatile("lfence; rdtsc; lfence" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
}

static inline void clflush(void *p) {
    asm volatile("clflush (%0)" :: "r"(p) : "memory");
}

static inline void mfence(void) {
    asm volatile("mfence" ::: "memory");
}

static long sys_mbind(void *start, unsigned long len, int mode,
                      const unsigned long *nmask, unsigned long maxnode, unsigned flags) {
    return syscall(__NR_mbind, start, len, mode, nmask, maxnode, flags);
}

static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

static double get_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_sec * 1000.0 + tv.tv_usec / 1000.0;
}

static void detect_cpu_freq(void) {
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (f) {
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            double mhz;
            if (sscanf(line, "cpu MHz : %lf", &mhz) == 1) {
                cpu_ghz = mhz / 1000.0;
                fclose(f);
                return;
            }
        }
        fclose(f);
    }
    uint64_t start = rdtsc_fenced();
    usleep(10000);
    uint64_t end = rdtsc_fenced();
    cpu_ghz = (double)(end - start) / 10000000.0;
}

static int is_daemon_or_child(pid_t tgid) {
    if (tgid == daemon_pid) return 1;
    
    char stat_path[64];
    snprintf(stat_path, sizeof(stat_path), "/proc/%d/stat", tgid);
    FILE *f = fopen(stat_path, "r");
    if (f) {
        char buf[512];
        if (fgets(buf, sizeof(buf), f)) {
            char *close_paren = strrchr(buf, ')');
            if (close_paren) {
                pid_t ppid = 0;
                char state;
                if (sscanf(close_paren + 2, "%c %d", &state, &ppid) == 2) {
                    fclose(f);
                    if (ppid == daemon_pid) return 1;
                    return 0;
                }
            }
        }
        fclose(f);
    }
    return 0;
}

// ============================================================================
// 4. STRUCTURES
// ============================================================================

typedef struct {
    int fd;
    struct perf_event_attr pe;
    const char *name;
} perf_counter_t;

typedef struct thread_node {
    pid_t tid;
    int current_assigned_node;
    struct thread_node *next;
} thread_node_t;

typedef struct process_node {
    pid_t tgid;
    perf_counter_t mem_loads;
    perf_counter_t mem_stores;
    perf_counter_t dtlb_loads;
    perf_counter_t dtlb_stores;
    perf_counter_t dtlb_load_walks;
    perf_counter_t dtlb_store_walks;
    
    long long prev_mem_loads;
    long long prev_mem_stores;
    long long prev_dtlb_loads;
    long long prev_dtlb_stores;
    long long prev_dtlb_load_walks;
    long long prev_dtlb_store_walks;
    
    int mitosis_enabled;
    thread_node_t *threads;
    struct process_node *next;
} process_node_t;

process_node_t *proc_list_head = NULL;

int num_online_nodes = 0;
int node_to_cpu_map[MAX_NUMA_NODES];
double ptl_matrix[MAX_NUMA_NODES][MAX_NUMA_NODES];
int ptl_baseline_valid = 0;
time_t last_ptl_update = 0;

// ============================================================================
// 5. SYSTEM HELPERS
// ============================================================================

static void set_mitosis_inheritance(int enable) {
    FILE *f = fopen(SYSCTL_INHERIT_PATH, "w");
    if (f) {
        fprintf(f, "%d", enable ? 1 : -1);
        fclose(f);
        printf("         Kernel inheritance %s\n", enable ? "ENABLED" : "DISABLED");
        fflush(stdout);
    }
}

static void increase_fd_limit(void) {
    struct rlimit rlim;
    if (getrlimit(RLIMIT_NOFILE, &rlim) == 0) {
        rlim.rlim_cur = 65536;
        if (rlim.rlim_max < 65536) rlim.rlim_max = 65536;
        setrlimit(RLIMIT_NOFILE, &rlim);
    }
}

static int is_kernel_thread(pid_t pid) {
    char path[64];
    FILE *f;
    int is_kernel = 1;
    
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    f = fopen(path, "r");
    if (f) {
        if (fgetc(f) != EOF) is_kernel = 0;
        fclose(f);
    }
    return is_kernel;
}

static int get_node_for_cpu(int cpu) {
    char path[128];
    for (int n = 0; n < MAX_NUMA_NODES; n++) {
        snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/node%d", cpu, n);
        if (access(path, F_OK) == 0) return n;
    }
    return 0;
}

static void init_topology(void) {
    int nodes_found = 0;
    
    printf("\n");
    printf("         === Detecting NUMA Topology ===\n");
    
    for (int i = 0; i < MAX_NUMA_NODES; i++) {
        node_to_cpu_map[i] = -1;
        for (int j = 0; j < MAX_NUMA_NODES; j++) {
            ptl_matrix[i][j] = 99999.0;
        }
        
        char path[64];
        snprintf(path, sizeof(path), "/sys/devices/system/node/node%d", i);
        if (access(path, F_OK) == 0) {
            nodes_found++;
        }
    }
    num_online_nodes = nodes_found;
    
    for (int cpu = 0; cpu < 1024; cpu++) {
        char path[128];
        snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d", cpu);
        if (access(path, F_OK) != 0) break;
        
        int node = get_node_for_cpu(cpu);
        if (node < MAX_NUMA_NODES && node_to_cpu_map[node] == -1) {
            node_to_cpu_map[node] = cpu;
        }
    }
    
    printf("         Found %d NUMA nodes:\n", num_online_nodes);
    for (int i = 0; i < num_online_nodes; i++) {
        if (node_to_cpu_map[i] != -1) {
            printf("           Node %d -> first CPU: %d\n", i, node_to_cpu_map[i]);
        }
    }
    printf("\n");
    fflush(stdout);
}

static int get_thread_node(pid_t tid) {
    char path[64], buff[2048];
    FILE *f;
    int cpu_id = -1;
    
    snprintf(path, sizeof(path), "/proc/%d/stat", tid);
    f = fopen(path, "r");
    if (!f) return 0;
    
    if (fgets(buff, sizeof(buff), f)) {
        char *close_paren = strrchr(buff, ')');
        if (close_paren) {
            int field = 3;  // First token after ')' is field 3
            char *token = strtok(close_paren + 2, " ");
            while (token && field < 39) {
                token = strtok(NULL, " ");
                field++;
            }
            if (token) cpu_id = atoi(token);
        }
    }
    fclose(f);
    
    if (cpu_id == -1) return 0;
    return get_node_for_cpu(cpu_id);
}

// ============================================================================
// 5a. EXCLUSION HELPERS
// ============================================================================

static int add_excluded_name(const char *name) {
    if (num_excluded >= MAX_EXCLUDED_NAMES) {
        fprintf(stderr, "Error: Maximum of %d excluded names allowed\n", MAX_EXCLUDED_NAMES);
        return 0;
    }
    if (strlen(name) >= MAX_NAME_LEN) {
        fprintf(stderr, "Error: Excluded name '%s' too long (max %d chars)\n", name, MAX_NAME_LEN - 1);
        return 0;
    }
    strncpy(excluded_names[num_excluded], name, MAX_NAME_LEN - 1);
    excluded_names[num_excluded][MAX_NAME_LEN - 1] = '\0';
    num_excluded++;
    return 1;
}

static int is_excluded_process(pid_t pid) {
    if (num_excluded == 0) return 0;
    
    char name[MAX_NAME_LEN];
    get_process_name(pid, name, sizeof(name));
    
    for (int i = 0; i < num_excluded; i++) {
        if (strcmp(name, excluded_names[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

// ============================================================================
// 6. FAST PTL MEASUREMENT
// ============================================================================

static double measure_latency_to_node(int target_node) {
    size_t size = PTL_TEST_SIZE;
    size_t stride = PTL_STRIDE;
    size_t count = size / stride;
    
    void *buf = mmap(NULL, size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (buf == MAP_FAILED) {
        return 99999.0;
    }
    
    unsigned long nodemask = 1UL << target_node;
    if (sys_mbind(buf, size, 2, &nodemask, MAX_NUMA_NODES + 1, 1) != 0) {
        munmap(buf, size);
        return 99999.0;
    }
    
    memset(buf, 0xAA, size);
    
    volatile char **chain = (volatile char **)buf;
    for (size_t i = 0; i < count - 1; i++) {
        chain[i * stride / sizeof(char*)] = (char*)buf + ((i + 1) * stride);
    }
    chain[(count - 1) * stride / sizeof(char*)] = (char*)buf;
    
    volatile char **p = chain;
    for (int i = 0; i < 100; i++) {
        p = (volatile char **)*p;
    }
    
    uint64_t total = 0;
    p = chain;
    for (int i = 0; i < PTL_ITERATIONS; i++) {
        clflush((void*)p);
        mfence();
        uint64_t start = rdtsc_fenced();
        p = (volatile char **)*p;
        uint64_t end = rdtsc_fenced();
        total += (end - start);
    }
    
    if (p == NULL) abort();
    
    munmap(buf, size);
    
    double avg_cycles = (double)total / PTL_ITERATIONS;
    double ns = avg_cycles / cpu_ghz;
    
    return ns;
}

static void measure_from_source_node(int src_node, ptl_result_t *result) {
    int cpu = node_to_cpu_map[src_node];
    if (cpu >= 0) {
        cpu_set_t mask;
        CPU_ZERO(&mask);
        CPU_SET(cpu, &mask);
        sched_setaffinity(0, sizeof(mask), &mask);
    }
    
    for (int dst = 0; dst < num_online_nodes; dst++) {
        if (node_to_cpu_map[dst] == -1) {
            result->latencies[dst] = 99999.0;
            continue;
        }
        result->latencies[dst] = measure_latency_to_node(dst);
    }
    
    __atomic_store_n(&result->ready, 1, __ATOMIC_RELEASE);
}

static void update_ptl_matrix(void) {
    time_t now = time(NULL);
    if (now - last_ptl_update < ptl_interval) {
        return;
    }
    
    last_ptl_update = now;
    
    double start_time = get_time_ms();
    
    ptl_result_t *result = mmap(NULL, sizeof(ptl_result_t),
                                 PROT_READ | PROT_WRITE,
                                 MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (result == MAP_FAILED) {
        fprintf(stderr, "         ERROR: Failed to allocate shared memory\n");
        return;
    }
    
    for (int src = 0; src < num_online_nodes; src++) {
        if (node_to_cpu_map[src] == -1) continue;
        
        memset(result, 0, sizeof(ptl_result_t));
        
        pid_t pid = fork();
        if (pid == 0) {
            measure_from_source_node(src, result);
            _exit(0);
        } else if (pid > 0) {
            int status;
            waitpid(pid, &status, 0);
            
            for (int dst = 0; dst < num_online_nodes; dst++) {
                ptl_matrix[src][dst] = result->latencies[dst];
            }
        }
    }
    
    double elapsed = get_time_ms() - start_time;
    
    munmap(result, sizeof(ptl_result_t));
    
    printf("\n");
    
    int col_width = 8;
    int data_width = num_online_nodes * col_width;
    
    printf("         ┌─ PTL Matrix (%.0fms) ", elapsed);
    for (int i = 0; i < data_width - 19; i++) printf("─");
    printf("┐\n");
    
    printf("         │");
    for (int dst = 0; dst < num_online_nodes; dst++) {
        if (node_to_cpu_map[dst] != -1) {
            printf("   N%d   ", dst);
        }
    }
    printf("│\n");
    
    for (int src = 0; src < num_online_nodes; src++) {
        if (node_to_cpu_map[src] == -1) continue;
        
        double row_min = 99999.0, row_max = 0.0;
        for (int dst = 0; dst < num_online_nodes; dst++) {
            if (node_to_cpu_map[dst] == -1) continue;
            double lat = ptl_matrix[src][dst];
            if (lat < row_min) row_min = lat;
            if (lat > row_max) row_max = lat;
        }
        double row_range = row_max - row_min;
        
        printf("      N%d │", src);
        
        for (int dst = 0; dst < num_online_nodes; dst++) {
            if (node_to_cpu_map[dst] == -1) continue;
            
            double lat = ptl_matrix[src][dst];
            
            if (lat == row_min) {
                printf(" \033[32m%5.0f\033[0m  ", lat);
            } else {
                double normalized = row_range > 0 ? (lat - row_min) / row_range : 0.0;
                if (normalized < 0.5) {
                    printf(" \033[33m%5.0f\033[0m  ", lat);
                } else {
                    printf(" \033[31m%5.0f\033[0m  ", lat);
                }
            }
        }
        printf("│\n");
    }
    
    printf("         └");
    for (int i = 0; i < data_width; i++) printf("─");
    printf("┘\n");
    
    if (!ptl_baseline_valid) {
        ptl_baseline_valid = 1;
        printf("         [OK] PTL baseline established\n");
    }
    
    print_mitosis_status();
    
    printf("\n");
    fflush(stdout);
}

/*
 * Find the fastest replica node for a thread on current_node.
 * Returns the node with lowest latency (could be local or remote).
 */
static int find_fastest_replica(int current_node) {
    if (current_node < 0 || current_node >= num_online_nodes) {
        return current_node;
    }
    
    double best_latency = 99999.0;
    int best_node = current_node;
    
    for (int dst = 0; dst < num_online_nodes; dst++) {
        if (node_to_cpu_map[dst] == -1) continue;
        
        double latency = ptl_matrix[current_node][dst];
        if (latency < best_latency) {
            best_latency = latency;
            best_node = dst;
        }
    }
    
    return best_node;
}

// ============================================================================
// 7. PERF COUNTER MANAGEMENT
// ============================================================================

static void close_counter(perf_counter_t *pc) {
    if (pc->fd != -1) {
        close(pc->fd);
        pc->fd = -1;
    }
}

static int setup_counter(perf_counter_t *pc, pid_t pid, uint32_t type,
                         uint64_t config, const char *name) {
    memset(&pc->pe, 0, sizeof(struct perf_event_attr));
    pc->pe.type = type;
    pc->pe.size = sizeof(struct perf_event_attr);
    pc->pe.config = config;
    pc->pe.disabled = 1;
    pc->pe.exclude_kernel = 1;
    pc->pe.exclude_hv = 1;
    pc->pe.inherit = 0;
    pc->name = name;
    
    pc->fd = perf_event_open(&pc->pe, pid, -1, -1, 0);
    if (pc->fd == -1) {
        return 0;
    }
    
    ioctl(pc->fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(pc->fd, PERF_EVENT_IOC_ENABLE, 0);
    return 1;
}

static long long read_counter(perf_counter_t *pc) {
    long long count = 0;
    if (pc->fd == -1) return 0;
    if (read(pc->fd, &count, sizeof(long long)) != sizeof(long long)) return 0;
    return count;
}

// ============================================================================
// 8. THREAD NODE MANAGEMENT
// ============================================================================

static thread_node_t* find_thread(process_node_t *proc, pid_t tid) {
    thread_node_t *t = proc->threads;
    while (t) {
        if (t->tid == tid) return t;
        t = t->next;
    }
    return NULL;
}

static thread_node_t* add_thread(process_node_t *proc, pid_t tid) {
    thread_node_t *t = find_thread(proc, tid);
    if (t) return t;
    
    t = (thread_node_t*)calloc(1, sizeof(thread_node_t));
    if (!t) return NULL;
    
    t->tid = tid;
    t->current_assigned_node = NODE_UNINITIALIZED;
    t->next = proc->threads;
    proc->threads = t;
    
    return t;
}

static void cleanup_dead_threads(process_node_t *proc) {
    thread_node_t **curr = &proc->threads;
    while (*curr) {
        thread_node_t *t = *curr;
        char path[64];
        snprintf(path, sizeof(path), "/proc/%d/task/%d", proc->tgid, t->tid);
        
        if (access(path, F_OK) != 0) {
            *curr = t->next;
            free(t);
        } else {
            curr = &t->next;
        }
    }
}

static void free_threads(process_node_t *proc) {
    thread_node_t *t = proc->threads;
    while (t) {
        thread_node_t *next = t->next;
        free(t);
        t = next;
    }
    proc->threads = NULL;
}

// ============================================================================
// 9. PROCESS NODE MANAGEMENT
// ============================================================================

static process_node_t* create_process_node(pid_t tgid) {
    process_node_t *node = (process_node_t*)calloc(1, sizeof(process_node_t));
    if (!node) return NULL;
    
    node->tgid = tgid;
    node->mem_loads.fd = -1;
    node->mem_stores.fd = -1;
    node->dtlb_loads.fd = -1;
    node->dtlb_stores.fd = -1;
    node->dtlb_load_walks.fd = -1;
    node->dtlb_store_walks.fd = -1;
    node->mitosis_enabled = 0;
    node->threads = NULL;
    
    int ok = 1;
    
    if (!setup_counter(&node->mem_loads, tgid, PERF_TYPE_HW_CACHE,
            (PERF_COUNT_HW_CACHE_L1D) |
            (PERF_COUNT_HW_CACHE_OP_READ << 8) |
            (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16), "L1D-loads")) {
        setup_counter(&node->mem_loads, tgid, PERF_TYPE_HARDWARE,
                      PERF_COUNT_HW_INSTRUCTIONS, "instructions");
    }
    
    setup_counter(&node->mem_stores, tgid, PERF_TYPE_HW_CACHE,
            (PERF_COUNT_HW_CACHE_L1D) |
            (PERF_COUNT_HW_CACHE_OP_WRITE << 8) |
            (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16), "L1D-stores");
    
    setup_counter(&node->dtlb_loads, tgid, PERF_TYPE_HW_CACHE,
            (PERF_COUNT_HW_CACHE_DTLB) |
            (PERF_COUNT_HW_CACHE_OP_READ << 8) |
            (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16), "DTLB-loads");
    
    setup_counter(&node->dtlb_stores, tgid, PERF_TYPE_HW_CACHE,
            (PERF_COUNT_HW_CACHE_DTLB) |
            (PERF_COUNT_HW_CACHE_OP_WRITE << 8) |
            (PERF_COUNT_HW_CACHE_RESULT_ACCESS << 16), "DTLB-stores");
    
    setup_counter(&node->dtlb_load_walks, tgid, PERF_TYPE_HW_CACHE,
            (PERF_COUNT_HW_CACHE_DTLB) |
            (PERF_COUNT_HW_CACHE_OP_READ << 8) |
            (PERF_COUNT_HW_CACHE_RESULT_MISS << 16), "DTLB-load-walks");
    
    setup_counter(&node->dtlb_store_walks, tgid, PERF_TYPE_HW_CACHE,
            (PERF_COUNT_HW_CACHE_DTLB) |
            (PERF_COUNT_HW_CACHE_OP_WRITE << 8) |
            (PERF_COUNT_HW_CACHE_RESULT_MISS << 16), "DTLB-store-walks");
    
    if (node->mem_loads.fd == -1) {
        ok = 0;
    }
    
    if (!ok) {
        close_counter(&node->mem_loads);
        close_counter(&node->mem_stores);
        close_counter(&node->dtlb_loads);
        close_counter(&node->dtlb_stores);
        close_counter(&node->dtlb_load_walks);
        close_counter(&node->dtlb_store_walks);
        free(node);
        return NULL;
    }
    
    node->prev_mem_loads = read_counter(&node->mem_loads);
    node->prev_mem_stores = read_counter(&node->mem_stores);
    node->prev_dtlb_loads = read_counter(&node->dtlb_loads);
    node->prev_dtlb_stores = read_counter(&node->dtlb_stores);
    node->prev_dtlb_load_walks = read_counter(&node->dtlb_load_walks);
    node->prev_dtlb_store_walks = read_counter(&node->dtlb_store_walks);
    
    return node;
}

static process_node_t* find_process(pid_t tgid) {
    process_node_t *curr = proc_list_head;
    while (curr) {
        if (curr->tgid == tgid) return curr;
        curr = curr->next;
    }
    return NULL;
}

static void add_process(pid_t tgid) {
    if (find_process(tgid)) return;
    
    process_node_t *node = create_process_node(tgid);
    if (node) {
        node->next = proc_list_head;
        proc_list_head = node;
    }
}

static void get_process_name(pid_t pid, char *name, size_t len) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    FILE *f = fopen(path, "r");
    if (f) {
        if (fgets(name, len, f)) {
            char *nl = strchr(name, '\n');
            if (nl) *nl = '\0';
        } else {
            snprintf(name, len, "unknown");
        }
        fclose(f);
    } else {
        snprintf(name, len, "unknown");
    }
}

static void cleanup_dead_processes(void) {
    process_node_t **curr = &proc_list_head;
    while (*curr) {
        process_node_t *entry = *curr;
        if (kill(entry->tgid, 0) == -1 && errno == ESRCH) {
            if (entry->mitosis_enabled) {
                printf("         [DEAD] Process died: PID %d (had Mitosis enabled)\n", entry->tgid);
                fflush(stdout);
            }
            
            close_counter(&entry->mem_loads);
            close_counter(&entry->mem_stores);
            close_counter(&entry->dtlb_loads);
            close_counter(&entry->dtlb_stores);
            close_counter(&entry->dtlb_load_walks);
            close_counter(&entry->dtlb_store_walks);
            free_threads(entry);
            
            *curr = entry->next;
            free(entry);
        } else {
            curr = &entry->next;
        }
    }
}

// ============================================================================
// 10. MITOSIS CONTROL
// ============================================================================

static int enable_mitosis_for_process(process_node_t *proc) {
    int ret = prctl(PR_SET_PGTABLE_REPL, 1, proc->tgid, 0, 0);
    if (ret == 0) {
        proc->mitosis_enabled = 1;
        printf("\n");
        printf("         ═════════════════════════════════════════════════════════\n");
        printf("         [+] MITOSIS ENABLED for PID %d\n", proc->tgid);
        printf("             Page-table replicas created on all NUMA nodes\n");
        printf("         ═════════════════════════════════════════════════════════\n");
        printf("\n");
        fflush(stdout);
        return 1;
    } else {
        fprintf(stderr, "         ERROR: Failed to enable Mitosis for %d: %s\n", proc->tgid, strerror(errno));
        return 0;
    }
}

static int disable_mitosis_for_process(process_node_t *proc) {
    int ret = prctl(PR_SET_PGTABLE_REPL, 0, proc->tgid, 0, 0);
    if (ret == 0) {
        proc->mitosis_enabled = 0;
        
        thread_node_t *t = proc->threads;
        while (t) {
            t->current_assigned_node = NODE_UNINITIALIZED;
            t = t->next;
        }
        
        printf("\n");
        printf("         ═════════════════════════════════════════════════════════\n");
        printf("         [-] MITOSIS DISABLED for PID %d\n", proc->tgid);
        printf("             Page-table replicas removed\n");
        printf("         ═════════════════════════════════════════════════════════\n");
        printf("\n");
        fflush(stdout);
        return 1;
    } else {
        fprintf(stderr, "         ERROR: Failed to disable Mitosis for %d: %s\n", proc->tgid, strerror(errno));
        return 0;
    }
}

/*
 * Steer thread to use the specified replica node.
 * target_node can be a specific node (0..N-1) or NODE_AUTO for local.
 */
static void steer_thread_to_replica(process_node_t *proc, thread_node_t *thread, int target_node) {
    if (thread->current_assigned_node == target_node) {
        return;
    }
    
    int ret = prctl(PR_SET_PGTABLE_REPL_NODE, target_node, thread->tid, 0, 0);
    if (ret == 0) {
        int old_node = thread->current_assigned_node;
        int physical_node = get_thread_node(thread->tid);
        thread->current_assigned_node = target_node;
        
        // Only log changes (not initial assignments)
        if (old_node != NODE_UNINITIALIZED) {
            double old_latency = (old_node >= 0 && old_node < MAX_NUMA_NODES) 
                ? ptl_matrix[physical_node][old_node] 
                : ptl_matrix[physical_node][physical_node];
            double new_latency = (target_node >= 0 && target_node < MAX_NUMA_NODES)
                ? ptl_matrix[physical_node][target_node]
                : ptl_matrix[physical_node][physical_node];
            
            printf("         [STEER] Thread %d (PID %d): Node %d -> Node %d (%.0fns -> %.0fns)\n",
                   thread->tid, proc->tgid,
                   (old_node == NODE_AUTO) ? physical_node : old_node,
                   (target_node == NODE_AUTO) ? physical_node : target_node,
                   old_latency, new_latency);
            fflush(stdout);
        }
    }
}

// ============================================================================
// 11. STATUS DISPLAY
// ============================================================================

static void print_mitosis_status(void) {
    int enabled_count = 0;
    process_node_t *proc = proc_list_head;
    while (proc) {
        if (proc->mitosis_enabled) enabled_count++;
        proc = proc->next;
    }
    
    if (enabled_count == 0) return;
    
    printf("\n");
    printf("         ┌─────────┬──────────────────┬─────────────────┬────────────────────────────────┐\n");
    printf("         │   PID   │       Name       │  Replica Node   │           Thread IDs           │\n");
    printf("         ├─────────┼──────────────────┼─────────────────┼────────────────────────────────┤\n");
    
    proc = proc_list_head;
    while (proc) {
        if (proc->mitosis_enabled) {
            char proc_name[32];
            get_process_name(proc->tgid, proc_name, sizeof(proc_name));
            
            #define IDX_AUTO (MAX_NUMA_NODES)
            #define IDX_UNINIT (MAX_NUMA_NODES + 1)
            #define NUM_BUCKETS (MAX_NUMA_NODES + 2)
            
            pid_t tids[NUM_BUCKETS][4096];
            int tid_counts[NUM_BUCKETS] = {0};
            
            thread_node_t *t = proc->threads;
            while (t) {
                int bucket;
                if (t->current_assigned_node == NODE_AUTO) {
                    bucket = IDX_AUTO;
                } else if (t->current_assigned_node == NODE_UNINITIALIZED) {
                    bucket = IDX_UNINIT;
                } else if (t->current_assigned_node >= 0 && t->current_assigned_node < MAX_NUMA_NODES) {
                    bucket = t->current_assigned_node;
                } else {
                    bucket = IDX_UNINIT;
                }
                
                if (tid_counts[bucket] < 4096) {
                    tids[bucket][tid_counts[bucket]++] = t->tid;
                }
                t = t->next;
            }
            
            for (int b = 0; b < NUM_BUCKETS; b++) {
                for (int i = 0; i < tid_counts[b] - 1; i++) {
                    for (int j = i + 1; j < tid_counts[b]; j++) {
                        if (tids[b][i] > tids[b][j]) {
                            pid_t tmp = tids[b][i];
                            tids[b][i] = tids[b][j];
                            tids[b][j] = tmp;
                        }
                    }
                }
            }
            
            int first_row = 1;
            for (int b = 0; b < NUM_BUCKETS; b++) {
                if (tid_counts[b] == 0) continue;
                
                char node_str[20];
                if (b == IDX_AUTO) {
                    snprintf(node_str, sizeof(node_str), "AUTO (local)");
                } else if (b == IDX_UNINIT) {
                    snprintf(node_str, sizeof(node_str), "UNINITIALIZED");
                } else {
                    snprintf(node_str, sizeof(node_str), "Node %d", b);
                }
                
                char tid_str[256] = "";
                int pos = 0;
                int i = 0;
                while (i < tid_counts[b] && pos < 200) {
                    int range_start = tids[b][i];
                    int range_end = range_start;
                    
                    while (i + 1 < tid_counts[b] && tids[b][i + 1] == range_end + 1) {
                        range_end = tids[b][++i];
                    }
                    
                    if (pos > 0) {
                        pos += snprintf(tid_str + pos, sizeof(tid_str) - pos, ", ");
                    }
                    
                    if (range_end > range_start + 1) {
                        pos += snprintf(tid_str + pos, sizeof(tid_str) - pos, "%d-%d", range_start, range_end);
                    } else if (range_end == range_start + 1) {
                        pos += snprintf(tid_str + pos, sizeof(tid_str) - pos, "%d,%d", range_start, range_end);
                    } else {
                        pos += snprintf(tid_str + pos, sizeof(tid_str) - pos, "%d", range_start);
                    }
                    
                    i++;
                }
                
                if (strlen(tid_str) > 30) {
                    tid_str[27] = '.';
                    tid_str[28] = '.';
                    tid_str[29] = '.';
                    tid_str[30] = '\0';
                }
                
                if (first_row) {
                    printf("         │ %7d │ %-16s │ %-15s │ %-30s │\n", 
                           proc->tgid, proc_name, node_str, tid_str);
                    first_row = 0;
                } else {
                    printf("         │         │                  │ %-15s │ %-30s │\n", 
                           node_str, tid_str);
                }
            }
            
            if (first_row) {
                printf("         │ %7d │ %-16s │        -        │ (no threads)                   │\n", 
                       proc->tgid, proc_name);
            }
        }
        proc = proc->next;
    }
    
    printf("         └─────────┴──────────────────┴─────────────────┴────────────────────────────────┘\n");
    printf("\n");
    fflush(stdout);
}

// ============================================================================
// 12. MAIN DECISION LOGIC
// ============================================================================

static void update_metrics_and_decide(void) {
    process_node_t *proc = proc_list_head;
    
    while (proc) {
        long long mem_loads = read_counter(&proc->mem_loads);
        long long mem_stores = read_counter(&proc->mem_stores);
        long long dtlb_loads = read_counter(&proc->dtlb_loads);
        long long dtlb_stores = read_counter(&proc->dtlb_stores);
        long long dtlb_load_walks = read_counter(&proc->dtlb_load_walks);
        long long dtlb_store_walks = read_counter(&proc->dtlb_store_walks);
        
        long long d_mem = (mem_loads - proc->prev_mem_loads) + 
                          (mem_stores - proc->prev_mem_stores);
        long long d_dtlb = (dtlb_loads - proc->prev_dtlb_loads) + 
                           (dtlb_stores - proc->prev_dtlb_stores);
        long long d_walks = (dtlb_load_walks - proc->prev_dtlb_load_walks) + 
                            (dtlb_store_walks - proc->prev_dtlb_store_walks);
        
        proc->prev_mem_loads = mem_loads;
        proc->prev_mem_stores = mem_stores;
        proc->prev_dtlb_loads = dtlb_loads;
        proc->prev_dtlb_stores = dtlb_stores;
        proc->prev_dtlb_load_walks = dtlb_load_walks;
        proc->prev_dtlb_store_walks = dtlb_store_walks;
        
        if (d_mem < 0) d_mem = 0;
        if (d_dtlb < 0) d_dtlb = 0;
        if (d_walks < 0) d_walks = 0;
        
        double MAR = (double)d_mem;
        double DTLB_MR = (d_dtlb > 0) ? (double)d_walks / (double)d_dtlb : 0.0;
        
        if (MAR < 10000) {
            proc = proc->next;
            continue;
        }
        
        int mar_exceeded = (MAR > THR_MAR);
        int dtlb_exceeded = (DTLB_MR > THR_DTLB);
        int should_enable = mar_exceeded && dtlb_exceeded;
        
        if (should_enable && !proc->mitosis_enabled) {
            printf("         [METRICS] PID %d: Thresholds exceeded (MAR=%.1fM, DTLB=%.2f%%) - enabling Mitosis\n",
                   proc->tgid, MAR/1e6, DTLB_MR*100);
            fflush(stdout);
            enable_mitosis_for_process(proc);
        } else if (!should_enable && proc->mitosis_enabled) {
            printf("         [METRICS] PID %d: Below thresholds (MAR=%.1fM, DTLB=%.2f%%) - disabling Mitosis\n",
                   proc->tgid, MAR/1e6, DTLB_MR*100);
            fflush(stdout);
            disable_mitosis_for_process(proc);
        }
        
        // Simple thread steering: each thread uses the fastest replica
        if (proc->mitosis_enabled && latency_mode) {
            cleanup_dead_threads(proc);
            
            char task_path[64];
            snprintf(task_path, sizeof(task_path), "/proc/%d/task", proc->tgid);
            DIR *task_d = opendir(task_path);
            
            if (task_d) {
                struct dirent *task_dir;
                while ((task_dir = readdir(task_d)) != NULL) {
                    if (task_dir->d_type == DT_DIR && isdigit(task_dir->d_name[0])) {
                        pid_t tid = atoi(task_dir->d_name);
                        thread_node_t *thread = add_thread(proc, tid);
                        if (thread) {
                            int physical_node = get_thread_node(tid);
                            int best_node = find_fastest_replica(physical_node);
                            
                            // Use NODE_AUTO if local is fastest, otherwise use specific node
                            int target = (best_node == physical_node) ? NODE_AUTO : best_node;
                            steer_thread_to_replica(proc, thread, target);
                        }
                    }
                }
                closedir(task_d);
            }
        }
        
        proc = proc->next;
    }
}

// ============================================================================
// 13. PROCESS SCANNING
// ============================================================================

static int is_numeric(const char *s) {
    if (!s || !*s) return 0;
    while (*s) {
        if (!isdigit(*s)) return 0;
        s++;
    }
    return 1;
}

static void scan_proc_dir(void) {
    DIR *d = opendir("/proc");
    if (!d) return;
    
    struct dirent *dir;
    while ((dir = readdir(d)) != NULL) {
        if (dir->d_type == DT_DIR && is_numeric(dir->d_name)) {
            pid_t tgid = atoi(dir->d_name);
            
            if (tgid <= 1) continue;
            if (is_daemon_or_child(tgid)) continue;
            if (is_kernel_thread(tgid)) continue;
            if (is_excluded_process(tgid)) continue;
            
            add_process(tgid);
        }
    }
    closedir(d);
}

// ============================================================================
// 14. SIGNAL HANDLING & CLEANUP
// ============================================================================

static void signal_handler(int signum) {
    (void)signum;
    stop_requested = 1;
}

static void cleanup_and_exit(void) {
    printf("\n");
    printf("         Shutting down WASP daemon...\n");
    
    int disabled_count = 0;
    process_node_t *curr = proc_list_head;
    
    while (curr) {
        if (curr->mitosis_enabled) {
            if (prctl(PR_SET_PGTABLE_REPL, 0, curr->tgid, 0, 0) == 0) {
                disabled_count++;
            }
        }
        
        close_counter(&curr->mem_loads);
        close_counter(&curr->mem_stores);
        close_counter(&curr->dtlb_loads);
        close_counter(&curr->dtlb_stores);
        close_counter(&curr->dtlb_load_walks);
        close_counter(&curr->dtlb_store_walks);
        free_threads(curr);
        
        process_node_t *temp = curr;
        curr = curr->next;
        free(temp);
    }
    
    proc_list_head = NULL;
    set_mitosis_inheritance(1);
    
    printf("         Disabled Mitosis for %d processes\n", disabled_count);
    fflush(stdout);
    
    if (log_fp && log_fp != stdout) {
        fclose(log_fp);
    }
    
    exit(0);
}

static time_t last_status_print = 0;

// ============================================================================
// 15. ARGUMENT PARSING & USAGE
// ============================================================================

static void print_usage(const char *prog) {
    printf("Usage: %s <mode> [options]\n", prog);
    printf("\nRequired:\n");
    printf("  mode              0 = Naive (perf counters only), 1 = Full (PTL steering)\n");
    printf("\nOptions:\n");
    printf("  -i, --interval N  Seconds between PTL measurements [default: %d]\n", PTL_UPDATE_INTERVAL);
    printf("  -x, --exclude NAME  Exclude program by name (can be repeated)\n");
    printf("  -h, --help        Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s 0                      # Naive mode, no latency measurement\n", prog);
    printf("  %s 1                      # Full mode, measure PTL every %d seconds\n", prog, PTL_UPDATE_INTERVAL);
    printf("  %s 1 -i 5                 # Full mode, measure PTL every 5 seconds\n", prog);
    printf("  %s 1 -x stream            # Full mode, exclude 'stream' from monitoring\n", prog);
    printf("  %s 1 -x stream -x bench   # Full mode, exclude 'stream' and 'bench'\n", prog);
}

static int parse_args(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage(argv[0]);
        return -1;
    }
    
    // Check for help first
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;  // Success but exit
        }
    }
    
    // First positional argument is mode
    if (strcmp(argv[1], "0") == 0) {
        latency_mode = 0;
    } else if (strcmp(argv[1], "1") == 0) {
        latency_mode = 1;
    } else {
        fprintf(stderr, "Invalid mode '%s'. Use 0 or 1.\n", argv[1]);
        return -1;
    }
    
    // Parse remaining options
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--interval") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires an argument\n", argv[i]);
                return -1;
            }
            ptl_interval = atoi(argv[++i]);
            if (ptl_interval < 1) {
                fprintf(stderr, "Invalid interval '%s'. Must be >= 1 second.\n", argv[i]);
                return -1;
            }
        } else if (strcmp(argv[i], "-x") == 0 || strcmp(argv[i], "--exclude") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: %s requires a program name\n", argv[i]);
                return -1;
            }
            if (!add_excluded_name(argv[++i])) {
                return -1;
            }
        } else if (isdigit(argv[i][0])) {
            // Legacy support: second positional argument is interval
            ptl_interval = atoi(argv[i]);
            if (ptl_interval < 1) {
                fprintf(stderr, "Invalid ptl_interval '%s'. Must be >= 1 second.\n", argv[i]);
                return -1;
            }
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            print_usage(argv[0]);
            return -1;
        }
    }
    
    return 1;  // Continue execution
}

// ============================================================================
// 16. MAIN
// ============================================================================

int main(int argc, char *argv[]) {
    int parse_result = parse_args(argc, argv);
    if (parse_result <= 0) {
        return parse_result == 0 ? 0 : 1;
    }
    
    if (geteuid() != 0) {
        fprintf(stderr, "Error: WASP daemon must run as root\n");
        return 1;
    }
    
    daemon_pid = getpid();
    
    log_fp = fopen(LOG_FILE, "a");
    if (!log_fp) log_fp = stdout;
    
    printf("\n");
    printf("╔═══════════════════════════════════════════════════════════════╗\n");
    printf("║                                                               ║\n");
    printf("║   WASP: Workload-Aware Self-Replicating Page-Tables           ║\n");
    printf("║   Simplified: Always use fastest replica per thread           ║\n");
    if (latency_mode) {
        printf("║   Mode: FULL (PTL interval: %3ds)                             ║\n", ptl_interval);
    } else {
        printf("║   Mode: NAIVE (perf counters only)                            ║\n");
    }
    printf("║                                                               ║\n");
    printf("╚═══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    detect_cpu_freq();
    printf("         Detected CPU frequency: %.2f GHz\n", cpu_ghz);
    printf("         Daemon PID: %d (excluded from monitoring)\n", daemon_pid);
    
    printf("         Configuration:\n");
    printf("           MAR threshold:       %.0f accesses/sec\n", THR_MAR);
    printf("           DTLB miss threshold: %.2f%%\n", THR_DTLB * 100);
    if (latency_mode) {
        printf("           PTL update interval: %d seconds\n", ptl_interval);
        printf("           PTL test size:       %d KB\n", PTL_TEST_SIZE / 1024);
    }
    
    if (num_excluded > 0) {
        printf("         Excluded programs:     ");
        for (int i = 0; i < num_excluded; i++) {
            if (i > 0) printf(", ");
            printf("%s", excluded_names[i]);
        }
        printf("\n");
    }
    fflush(stdout);
    
    increase_fd_limit();
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGCHLD, SIG_IGN);
    
    set_mitosis_inheritance(0);
    init_topology();
    
    if (num_online_nodes < 2) {
        fprintf(stderr, "Error: WASP requires at least 2 NUMA nodes. Found: %d\n", num_online_nodes);
        return 1;
    }
    
    if (latency_mode) {
        printf("         Performing initial PTL measurement...\n");
        fflush(stdout);
        update_ptl_matrix();
    } else {
        printf("         Skipping PTL measurement (naive mode)\n");
        fflush(stdout);
    }
    
    printf("         ═════════════════════════════════════════════════════════\n");
    printf("           WASP daemon running - monitoring all processes\n");
    printf("           Press Ctrl+C to stop\n");
    printf("         ═════════════════════════════════════════════════════════\n");
    printf("\n");
    fflush(stdout);
    
    while (!stop_requested) {
        cleanup_dead_processes();
        scan_proc_dir();
        if (latency_mode) {
            update_ptl_matrix();
        } else {
            time_t now = time(NULL);
            if (now - last_status_print >= ptl_interval) {
                print_mitosis_status();
                last_status_print = now;
            }
        }
        update_metrics_and_decide();
        sleep(1);
    }
    
    cleanup_and_exit();
    return 0;
}
