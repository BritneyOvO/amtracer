#define _GNU_SOURCE
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <unistd.h>

extern uint64_t amtracer_target(const uint64_t *value);
extern void amtracer_point(void);
static volatile int stop;
static const uint64_t values[] = { 0x1122334455667788ULL, 0x8877665544332211ULL };

__attribute__((noinline)) static uint64_t call_chain(unsigned depth) {
    if (depth) return call_chain(depth - 1) + 1;
    return amtracer_target(values);
}

static void *worker(void *unused) {
    (void)unused;
    while (!__atomic_load_n(&stop, __ATOMIC_RELAXED)) {
        (void)call_chain(4);
        (void)syscall(__NR_getpid);
        usleep(10000);
    }
    return NULL;
}

int main(int argc, char **argv) {
    unsigned seconds = argc > 1 ? (unsigned)strtoul(argv[1], NULL, 10) : 60;
    printf("{\"pid\":%d,\"target\":\"%p\",\"point\":\"%p\",\"memory\":\"%p\"}\n",
           getpid(), amtracer_target, amtracer_point, values);
    fflush(stdout);
    pthread_t first, later;
    if (pthread_create(&first, NULL, worker, NULL)) return 1;
    sleep(3);
    if (pthread_create(&later, NULL, worker, NULL)) return 1;
    sleep(seconds);
    __atomic_store_n(&stop, 1, __ATOMIC_RELAXED);
    pthread_join(first, NULL);
    pthread_join(later, NULL);
    return 0;
}
