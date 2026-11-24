#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static long (*current_call)(void);
static int running = 1;

static void *worker(void *unused) {
    (void)unused;
    for (;;) {
        pthread_mutex_lock(&lock);
        int keep_running = running;
        if (current_call) current_call();
        pthread_mutex_unlock(&lock);
        if (!keep_running) return NULL;
        usleep(20000);
    }
}

int main(int argc, char **argv) {
    if (argc != 3) return 1;
    void *a = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!a) { fprintf(stderr, "%s\n", dlerror()); return 1; }
    current_call = (long (*)(void))dlsym(a, "mapping_call");
    if (!current_call) return 1;
    pthread_t thread;
    if (pthread_create(&thread, NULL, worker, NULL)) return 1;
    printf("{\"pid\":%d}\n", getpid());
    fflush(stdout);
    void *b = NULL;
    int cmd;
    while ((cmd = getchar()) != EOF) {
        if (cmd == 'b') {
            b = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
            if (!b) { fprintf(stderr, "%s\n", dlerror()); return 1; }
            pthread_mutex_lock(&lock);
            current_call = (long (*)(void))dlsym(b, "mapping_call");
            pthread_mutex_unlock(&lock);
            if (!current_call) return 1;
            puts("b loaded"); fflush(stdout);
        } else if (cmd == 'a') {
            pthread_mutex_lock(&lock);
            dlclose(a);
            a = NULL;
            pthread_mutex_unlock(&lock);
            puts("a unloaded"); fflush(stdout);
        } else if (cmd == 'q') {
            break;
        }
    }
    pthread_mutex_lock(&lock);
    running = 0;
    current_call = NULL;
    pthread_mutex_unlock(&lock);
    pthread_join(thread, NULL);
    if (a) dlclose(a);
    if (b) dlclose(b);
    return 0;
}
