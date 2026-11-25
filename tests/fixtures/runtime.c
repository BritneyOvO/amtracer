#define _GNU_SOURCE
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

extern uint64_t amtracer_runtime_point(void);
static uintptr_t original, alias;
static volatile sig_atomic_t faults;

static void ill(int sig, siginfo_t *info, void *opaque)
{
    (void)sig;
    (void)info;
    ucontext_t *context = opaque;
    uintptr_t pc = context->uc_mcontext.pc;
    if (pc != original && pc != alias)
        _exit(90);
    faults++;
    context->uc_mcontext.regs[0] = 999;
    context->uc_mcontext.pc = pc + 4;
}

static int decrypt(uintptr_t pc, uint32_t value)
{
    if (mprotect((void *)pc, 4096, PROT_READ | PROT_WRITE)) return -1;
    *(uint32_t *)pc = 0xd2800000 | (value << 5); /* MOV X0,#value */
    __builtin___clear_cache((char *)pc, (char *)pc + 4096);
    return mprotect((void *)pc, 4096, PROT_READ | PROT_EXEC);
}

int main(void)
{
    struct sigaction action = { .sa_sigaction = ill, .sa_flags = SA_SIGINFO };
    char line[1024], path[1024];
    unsigned long start, end, offset = 0;
    original = (uintptr_t)amtracer_runtime_point;
    if ((original & 4095) || sysconf(_SC_PAGESIZE) != 4096) return 1;
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGILL, &action, NULL)) return 2;
    FILE *maps = fopen("/proc/self/maps", "r");
    if (!maps) return 3;
    int found = 0;
    while (fgets(line, sizeof(line), maps)) {
        if (sscanf(line, "%lx-%lx %*s %lx", &start, &end, &offset) == 3 &&
            start <= original && original < end) {
            offset += original - start;
            found = 1;
            break;
        }
    }
    fclose(maps);
    if (!found) return 4;
    int fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 5;
    void *mapped = mmap(NULL, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, offset);
    if (mapped == MAP_FAILED) return 6;
    alias = (uintptr_t)mapped;
    uint32_t disk;
    if (pread(fd, &disk, 4, offset) != 4 || disk != 0x74959469) return 7;
    if (decrypt(original, 42) || decrypt(alias, 77)) return 8;
    ssize_t length = readlink("/proc/self/exe", path, sizeof(path) - 1);
    if (length < 0) return 9;
    path[length] = 0;
    printf("{\"pid\":%d,\"point\":\"0x%" PRIxPTR "\",\"alias\":\"0x%" PRIxPTR
           "\",\"file_offset\":\"0x%lx\",\"path\":\"%s\"}\n",
           getpid(), original, alias, offset, path);
    fflush(stdout);
    while (fgets(line, sizeof(line), stdin)) {
        if (!strncmp(line, "quit", 4)) break;
        unsigned rounds = 0, failures = 0;
        if (sscanf(line, "run %u", &rounds) == 1) {
            if (rounds > 10000) return 10;
            for (unsigned i = 0; i < rounds; i++) {
                failures += amtracer_runtime_point() != 42;
                failures += ((uint64_t (*)(void))alias)() != 77;
            }
        }
        printf("{\"failures\":%u,\"faults\":%d,\"calls\":%u,\"word\":\"%08x\",\"alias_word\":\"%08x\"}\n",
               failures, faults, rounds * 2, *(uint32_t *)original, *(uint32_t *)alias);
        fflush(stdout);
    }
    if (pread(fd, &disk, 4, offset) != 4 || disk != 0x74959469) return 11;
    if (munmap(mapped, 4096) || close(fd)) return 12;
    return faults ? 13 : 0;
}
