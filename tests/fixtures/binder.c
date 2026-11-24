#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/android/binder.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* An invalid private handle exercises transactions without contacting a service. */
int main(void) {
    int fd = open("/dev/binder", O_RDWR | O_CLOEXEC);
    if (fd < 0) { perror("binder open"); return 1; }
    unsigned char parcel[320] = {0};
    /* Android 13 writeInterfaceToken: strict policy, work source, SYST, String16. */
    const uint32_t header[] = {0x80000000U, 0xffffffffU, 0x53595354U, 14};
    memcpy(parcel, header, sizeof(header));
    const uint16_t token[] = {'a','m','t','r','a','c','e','r','.','I','T','e','s','t',0};
    memcpy(parcel + sizeof(header), token, sizeof(token));
    memset(parcel + 48, 0x5a, sizeof(parcel) - 48);
    printf("{\"pid\":%d}\n", getpid());
    fflush(stdout);
    /* The test starts the trace before releasing this gate. */
    if (getchar() == EOF) return 1;
    for (unsigned i = 0; i < 6; i++) {
        struct {
            uint32_t command;
            struct binder_transaction_data transaction;
        } __attribute__((packed)) request = {0};
        uint32_t response[64] = {0};
        request.command = BC_TRANSACTION;
        request.transaction.target.handle = 0x7ffffffeU;
        request.transaction.code = 0x414d5400U + i;
        request.transaction.flags = i & 1 ? TF_ONE_WAY : 0;
        request.transaction.data_size = sizeof(parcel);
        request.transaction.data.ptr.buffer = (uintptr_t)parcel;
        struct binder_write_read operation = {
            .write_size = sizeof(request),
            .write_buffer = (uintptr_t)&request,
            .read_size = sizeof(response),
            .read_buffer = (uintptr_t)response,
        };
        if (ioctl(fd, BINDER_WRITE_READ, &operation) < 0 || operation.write_consumed != sizeof(request)) {
            perror("binder transaction"); return 1;
        }
        usleep(100000);
    }
    sleep(2);
    close(fd);
    return 0;
}
