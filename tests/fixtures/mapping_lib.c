#include <sys/syscall.h>
#include <unistd.h>

__attribute__((noinline, visibility("default")))
long mapping_call(void) {
    volatile long result = syscall(SYS_getpid);
    return result;
}
