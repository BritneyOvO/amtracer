#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>

extern uint64_t amtracer_trace(uint64_t);
extern void amtracer_trace_end(void), amtracer_trace_leaf(void);
extern uint64_t amtracer_trace_fault(const void *);
extern void amtracer_trace_atomic(void), amtracer_trace_svc(void);
extern uint64_t amtracer_trace_fallback(uint64_t);
extern uint64_t amtracer_trace_many(uint64_t);
extern void amtracer_trace_many_end(void);
extern uint64_t amtracer_trace_cross(uint64_t);
extern void amtracer_trace_cross_end(void), amtracer_trace_cross_leaf(void), amtracer_trace_cross_leaf_end(void);

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t condition = PTHREAD_COND_INITIALIZER;
static unsigned generation, completed, ready, stopping;
static unsigned rounds, threads, mode, rate, migrate;
static uint64_t input, failures, elapsed_min, elapsed_max;
static uint64_t latency[32 * 1024];
static unsigned latency_count;
static unsigned fault_count, fault_bad_pc;
static cpu_set_t allowed;

static uint64_t now(clockid_t clock) {
    struct timespec time;
    if (clock_gettime(clock, &time)) abort();
    return (uint64_t)time.tv_sec * 1000000000 + (uint64_t)time.tv_nsec;
}

static void fault_handler(int signal, siginfo_t *info, void *context) {
    (void)signal;
    (void)info;
    ucontext_t *state = context;
    uintptr_t expected = (uintptr_t)amtracer_trace_fault;
    if (state->uc_mcontext.pc != expected) {
        __atomic_fetch_add(&fault_bad_pc, 1, __ATOMIC_RELAXED);
        _exit(120);
    }
    __atomic_fetch_add(&fault_count, 1, __ATOMIC_RELAXED);
    state->uc_mcontext.pc = expected + 4;
    state->uc_mcontext.regs[0] = 12;
}

static void *worker(void *opaque) {
    unsigned index = (unsigned)(uintptr_t)opaque;
    unsigned seen = index == 0 ? 0 : generation;
    pthread_mutex_lock(&lock);
    ready++;
    pthread_cond_broadcast(&condition);
    for (;;) {
        while (!stopping && generation == seen) pthread_cond_wait(&condition, &lock);
        if (stopping) break;
        seen = generation;
        unsigned count = rounds, selected = mode, per_second = rate, moving = migrate;
        uint64_t argument = input;
        pthread_mutex_unlock(&lock);
        uint64_t errors = 0;
        uint64_t started = now(CLOCK_MONOTONIC);
        uint64_t minimum = UINT64_MAX, maximum = 0;
        uint64_t samples[1024];
        unsigned sampled = 0;
        for (unsigned i = 0; i < count; i++) {
            if (moving) {
                unsigned nth = i % (unsigned)CPU_COUNT(&allowed);
                unsigned found = 0;
                for (int cpu = 0; cpu < CPU_SETSIZE; cpu++) {
                    if (!CPU_ISSET(cpu, &allowed)) continue;
                    if (found++ != nth) continue;
                    cpu_set_t single;
                    CPU_ZERO(&single);
                    CPU_SET(cpu, &single);
                    if (sched_setaffinity(0, sizeof(single), &single)) errors++;
                    break;
                }
            }
            uint64_t start = now(CLOCK_MONOTONIC);
            uint64_t result;
            if (selected == 1) result = amtracer_trace_fault(NULL);
            else if (selected == 2) result = amtracer_trace_many(argument);
            else if (selected == 3) result = amtracer_trace_cross(argument);
            else result = amtracer_trace(argument);
            uint64_t elapsed = now(CLOCK_MONOTONIC) - start;
            uint64_t expected = selected == 1 ? 12 : selected == 2 ? argument : selected == 3 ? argument + 1 : argument ? 17 : 106;
            if (result != expected) errors++;
            if (elapsed < minimum) minimum = elapsed;
            if (elapsed > maximum) maximum = elapsed;
            if (i % ((count + 1023) / 1024) == 0 && sampled < 1024) samples[sampled++] = elapsed;
            if (per_second) {
                uint64_t deadline = started + ((uint64_t)i + 1) * 1000000000 / per_second;
                struct timespec until = { (time_t)(deadline / 1000000000), (long)(deadline % 1000000000) };
                int error;
                do { error = clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &until, NULL); } while (error == EINTR);
                if (error) errors++;
            }
        }
        pthread_mutex_lock(&lock);
        failures += errors;
        if (minimum < elapsed_min) elapsed_min = minimum;
        if (maximum > elapsed_max) elapsed_max = maximum;
        memcpy(latency + latency_count, samples, sampled * sizeof(*samples));
        latency_count += sampled;
        completed++;
        pthread_cond_broadcast(&condition);
        if (index != 0) { pthread_mutex_unlock(&lock); return NULL; }
    }
    pthread_mutex_unlock(&lock);
    return NULL;
}

static int compare(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

int main(void) {
    if (sched_getaffinity(0, sizeof(allowed), &allowed) || CPU_COUNT(&allowed) == 0) return 1;
    struct sigaction action = { .sa_sigaction = fault_handler, .sa_flags = SA_SIGINFO };
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGSEGV, &action, NULL)) return 1;
    pthread_t persistent;
    if (pthread_create(&persistent, NULL, worker, NULL)) return 1;
    pthread_mutex_lock(&lock);
    while (ready != 1) pthread_cond_wait(&condition, &lock);
    pthread_mutex_unlock(&lock);
    printf("{\"pid\":%d,\"trace\":\"%p\",\"end\":\"%p\",\"leaf\":\"%p\",\"fault\":\"%p\","
           "\"many\":\"%p\",\"many_end\":\"%p\",\"atomic\":\"%p\",\"svc\":\"%p\",\"fallback\":\"%p\","
           "\"cross\":\"%p\",\"cross_end\":\"%p\",\"cross_leaf\":\"%p\",\"cross_leaf_end\":\"%p\"}\n",
           getpid(), amtracer_trace, amtracer_trace_end, amtracer_trace_leaf, amtracer_trace_fault,
           amtracer_trace_many, amtracer_trace_many_end, amtracer_trace_atomic, amtracer_trace_svc, amtracer_trace_fallback,
           amtracer_trace_cross, amtracer_trace_cross_end, amtracer_trace_cross_leaf, amtracer_trace_cross_leaf_end);
    fflush(stdout);
    char command[256];
    while (fgets(command, sizeof(command), stdin)) {
        if (!strncmp(command, "quit", 4)) break;
        unsigned n, t, m, r, moving;
        uint64_t argument;
        if (sscanf(command, "run %u %u %" SCNu64 " %u %u %u", &n, &t, &argument, &m, &r, &moving) != 6 ||
            n == 0 || n > 1000000 || t == 0 || t > 32 || m > 3 || moving > 1) return 2;
        pthread_mutex_lock(&lock);
        rounds = n; threads = t; input = argument; mode = m; rate = r; migrate = moving;
        completed = 0; failures = 0; ready = 1; elapsed_min = UINT64_MAX; elapsed_max = 0; latency_count = 0;
        __atomic_store_n(&fault_count, 0, __ATOMIC_RELAXED);
        __atomic_store_n(&fault_bad_pc, 0, __ATOMIC_RELAXED);
        pthread_t later[31];
        for (unsigned i = 1; i < t; i++) if (pthread_create(&later[i - 1], NULL, worker, (void *)(uintptr_t)i)) abort();
        while (ready != t) pthread_cond_wait(&condition, &lock);
        uint64_t started = now(CLOCK_MONOTONIC), cpu = now(CLOCK_PROCESS_CPUTIME_ID);
        generation++;
        pthread_cond_broadcast(&condition);
        while (completed != threads) pthread_cond_wait(&condition, &lock);
        uint64_t elapsed = now(CLOCK_MONOTONIC) - started, cpu_elapsed = now(CLOCK_PROCESS_CPUTIME_ID) - cpu;
        pthread_mutex_unlock(&lock);
        for (unsigned i = 1; i < t; i++) pthread_join(later[i - 1], NULL);
        qsort(latency, latency_count, sizeof(*latency), compare);
        struct rusage usage;
        if (getrusage(RUSAGE_SELF, &usage)) return 3;
        printf("{\"calls\":%u,\"threads\":%u,\"failures\":%" PRIu64 ",\"elapsed_ns\":%" PRIu64 ",\"cpu_ns\":%" PRIu64
               ",\"min_ns\":%" PRIu64 ",\"max_ns\":%" PRIu64 ",\"samples\":%u,\"p50_ns\":%" PRIu64 ",\"p95_ns\":%" PRIu64 ",\"p99_ns\":%" PRIu64
               ",\"faults\":%u,\"fault_bad_pc\":%u,\"maxrss_kb\":%ld}\n",
               n * t, t, failures, elapsed, cpu_elapsed, elapsed_min, elapsed_max, latency_count,
               latency[latency_count * 50 / 100], latency[latency_count * 95 / 100], latency[latency_count * 99 / 100],
               __atomic_load_n(&fault_count, __ATOMIC_RELAXED), __atomic_load_n(&fault_bad_pc, __ATOMIC_RELAXED), usage.ru_maxrss);
        fflush(stdout);
    }
    pthread_mutex_lock(&lock);
    stopping = 1;
    pthread_cond_broadcast(&condition);
    pthread_mutex_unlock(&lock);
    pthread_join(persistent, NULL);
    return 0;
}
