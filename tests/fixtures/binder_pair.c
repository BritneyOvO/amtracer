#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/android/binder.h>
#include <linux/android/binderfs.h>
#include <stdbool.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>

#define SYNC_CODE 0x414d5401U
#define ONEWAY_CODE 0x414d5402U
#define STOP_CODE 0x414d54feU

struct command_transaction {
    uint32_t command;
    struct binder_transaction_data transaction;
} __attribute__((packed));

struct command_buffer_free {
    uint32_t command;
    binder_uintptr_t buffer;
} __attribute__((packed));

struct device_ready {
    pid_t pid;
    int error;
};

static char service_path[128];

static void cleanup_service(int signal_number)
{
    (void)unlink(service_path);
    _exit(128 + signal_number);
}

static void *map_binder(int fd)
{
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0 || page_size >= (1 << 19)) {
        errno = EINVAL;
        return MAP_FAILED;
    }
    size_t map_size = (1U << 20) - (size_t)page_size * 2;
    return mmap(NULL, map_size, PROT_READ, MAP_PRIVATE | MAP_NORESERVE, fd, 0);
}

static int write_read(int fd, const void *write_data, size_t write_size,
                      void *read_data, size_t read_size,
                      binder_size_t *read_consumed)
{
    struct binder_write_read operation = {
        .write_size = write_size,
        .write_buffer = (binder_uintptr_t)write_data,
        .read_size = read_size,
        .read_buffer = (binder_uintptr_t)read_data,
    };
    if (ioctl(fd, BINDER_WRITE_READ, &operation) < 0)
        return -1;
    if (operation.write_consumed != write_size) {
        errno = EIO;
        return -1;
    }
    if (read_consumed)
        *read_consumed = operation.read_consumed;
    return 0;
}

static int send_command(int fd, const void *command, size_t size)
{
    return write_read(fd, command, size, NULL, 0, NULL);
}

static int free_buffer(int fd, binder_uintptr_t buffer)
{
    struct command_buffer_free command = {
        .command = BC_FREE_BUFFER,
        .buffer = buffer,
    };
    return send_command(fd, &command, sizeof(command));
}

static int parse_one_command(const unsigned char *data, size_t size,
                             size_t *offset, uint32_t *command,
                             struct binder_transaction_data *transaction)
{
    if (*offset + sizeof(*command) > size)
        return 0;
    memcpy(command, data + *offset, sizeof(*command));
    *offset += sizeof(*command);
    if (*command == BR_TRANSACTION_SEC_CTX) {
        struct binder_transaction_data_secctx transaction_secctx;
        if (*offset + sizeof(transaction_secctx) > size)
            return -1;
        memcpy(&transaction_secctx, data + *offset, sizeof(transaction_secctx));
        *transaction = transaction_secctx.transaction_data;
        *offset += sizeof(transaction_secctx);
    } else if (*command == BR_TRANSACTION || *command == BR_REPLY) {
        if (*offset + sizeof(*transaction) > size)
            return -1;
        memcpy(transaction, data + *offset, sizeof(*transaction));
        *offset += sizeof(*transaction);
    } else if (*command == BR_ERROR) {
        if (*offset + sizeof(int32_t) > size)
            return -1;
        *offset += sizeof(int32_t);
    }
    return 1;
}

static int server_loop(int fd)
{
    unsigned char input[4096];
    char reply_data[] = "reply-ok";
    for (;;) {
        struct binder_write_read operation = {
            .read_size = sizeof(input),
            .read_buffer = (binder_uintptr_t)input,
        };
        if (ioctl(fd, BINDER_WRITE_READ, &operation) < 0)
            return -1;
        size_t offset = 0;
        while (offset < operation.read_consumed) {
            uint32_t command = 0;
            struct binder_transaction_data transaction = {0};
            int parsed = parse_one_command(input, operation.read_consumed,
                                           &offset, &command, &transaction);
            if (parsed <= 0) {
                errno = EPROTO;
                return -1;
            }
            if (command != BR_TRANSACTION)
                continue;
            if (transaction.code != STOP_CODE &&
                !(transaction.flags & TF_ONE_WAY)) {
                struct command_transaction reply = {
                    .command = BC_REPLY,
                    .transaction = {
                        .target.ptr = transaction.target.ptr,
                        .cookie = transaction.cookie,
                        .code = transaction.code,
                        .data_size = sizeof(reply_data),
                        .data.ptr.buffer = (binder_uintptr_t)reply_data,
                    },
                };
                if (send_command(fd, &reply, sizeof(reply)) < 0 ||
                    free_buffer(fd, transaction.data.ptr.buffer) < 0)
                    return -1;
            } else if (free_buffer(fd, transaction.data.ptr.buffer) < 0) {
                return -1;
            }
            if (transaction.code == STOP_CODE) {
                uint32_t exit_looper = BC_EXIT_LOOPER;
                return send_command(fd, &exit_looper, sizeof(exit_looper));
            }
        }
    }
}

static void service_process(int ready_fd)
{
    struct binderfs_device device = {0};
    struct device_ready ready = {.pid = getpid()};
    int control = open("/dev/binderfs/binder-control", O_RDWR | O_CLOEXEC);
    if (control < 0) {
        ready.error = errno;
        (void)write(ready_fd, &ready, sizeof(ready));
        _exit(1);
    }
    (void)snprintf(device.name, sizeof(device.name), "amtracer-pair-%d", getpid());
    if (ioctl(control, BINDER_CTL_ADD, &device) < 0) {
        ready.error = errno;
        (void)write(ready_fd, &ready, sizeof(ready));
        _exit(1);
    }
    (void)snprintf(service_path, sizeof(service_path), "/dev/binderfs/%s", device.name);
    int fd = open(service_path, O_RDWR | O_CLOEXEC);
    if (fd < 0 || ioctl(fd, BINDER_SET_CONTEXT_MGR, 0) < 0) {
        ready.error = errno;
        (void)write(ready_fd, &ready, sizeof(ready));
        if (fd >= 0)
            close(fd);
        (void)unlink(service_path);
        _exit(1);
    }
    void *mapping = map_binder(fd);
    if (mapping == MAP_FAILED) {
        ready.error = errno;
        (void)write(ready_fd, &ready, sizeof(ready));
        close(fd);
        (void)unlink(service_path);
        _exit(1);
    }
    (void)signal(SIGTERM, cleanup_service);
    uint32_t enter_looper = BC_ENTER_LOOPER;
    if (send_command(fd, &enter_looper, sizeof(enter_looper)) < 0) {
        ready.error = errno;
        (void)write(ready_fd, &ready, sizeof(ready));
        munmap(mapping, (1U << 20) - (size_t)sysconf(_SC_PAGESIZE) * 2);
        close(fd);
        (void)unlink(service_path);
        _exit(1);
    }
    (void)write(ready_fd, &ready, sizeof(ready));
    close(ready_fd);
    if (server_loop(fd) < 0)
        perror("binder service loop");
    munmap(mapping, (1U << 20) - (size_t)sysconf(_SC_PAGESIZE) * 2);
    close(fd);
    close(control);
    (void)unlink(service_path);
    _exit(0);
}

static int send_sync(int fd, struct binder_transaction_data *transaction)
{
    struct command_transaction request = {
        .command = BC_TRANSACTION,
        .transaction = *transaction,
    };
    unsigned char response[4096];
    bool write_pending = true;
    for (;;) {
        binder_size_t consumed = 0;
        if (write_read(fd, write_pending ? &request : NULL,
                       write_pending ? sizeof(request) : 0,
                       response, sizeof(response), &consumed) < 0)
            return -1;
        write_pending = false;
        size_t offset = 0;
        while (offset < consumed) {
            uint32_t command = 0;
            struct binder_transaction_data result = {0};
            int parsed = parse_one_command(response, consumed, &offset,
                                           &command, &result);
            if (parsed <= 0) {
                errno = EPROTO;
                return -1;
            }
            if (command == BR_REPLY) {
                char reply[sizeof("reply-ok")];
                if (result.data_size != sizeof(reply)) {
                    errno = EPROTO;
                    return -1;
                }
                memcpy(reply, (const void *)(uintptr_t)result.data.ptr.buffer,
                       sizeof(reply));
                int status = strcmp(reply, "reply-ok") == 0 ? 0 : EPROTO;
                if (free_buffer(fd, result.data.ptr.buffer) < 0)
                    return -1;
                if (status) {
                    errno = status;
                    return -1;
                }
                return 0;
            }
            if (command == BR_ERROR || command == BR_FAILED_REPLY ||
                command == BR_DEAD_REPLY) {
                errno = EIO;
                return -1;
            }
        }
    }
}

static int send_oneway(int fd, uint32_t code, const void *data, size_t size)
{
    struct command_transaction request = {
        .command = BC_TRANSACTION,
        .transaction = {
            .target.handle = 0,
            .code = code,
            .flags = TF_ONE_WAY,
            .data_size = size,
            .data.ptr.buffer = (binder_uintptr_t)data,
        },
    };
    return send_command(fd, &request, sizeof(request));
}

int main(void)
{
    int ready_pipe[2];
    if (pipe(ready_pipe) < 0)
        return 1;
    pid_t service = fork();
    if (service < 0)
        return 1;
    if (service == 0) {
        close(ready_pipe[0]);
        service_process(ready_pipe[1]);
    }
    close(ready_pipe[1]);
    struct device_ready ready = {0};
    if (read(ready_pipe[0], &ready, sizeof(ready)) != sizeof(ready) || ready.error) {
        errno = ready.error ? ready.error : EIO;
        perror("create private Binder service");
        (void)waitpid(service, NULL, 0);
        return 1;
    }
    close(ready_pipe[0]);
    char path[128];
    (void)snprintf(path, sizeof(path), "/dev/binderfs/amtracer-pair-%d", ready.pid);
    int fd = open(path, O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        perror("open private Binder device");
        (void)kill(service, SIGTERM);
        (void)waitpid(service, NULL, 0);
        return 1;
    }
    void *mapping = map_binder(fd);
    if (mapping == MAP_FAILED) {
        perror("map private Binder client");
        close(fd);
        (void)kill(service, SIGTERM);
        (void)waitpid(service, NULL, 0);
        return 1;
    }

    printf("{\"pid\":%d,\"service_pid\":%d,\"device\":\"%s\"}\n",
           getpid(), ready.pid, path);
    fflush(stdout);
    char command[16];
    if (!fgets(command, sizeof(command), stdin)) {
        munmap(mapping, (1U << 20) - (size_t)sysconf(_SC_PAGESIZE) * 2);
        close(fd);
        (void)kill(service, SIGTERM);
        (void)waitpid(service, NULL, 0);
        return 1;
    }

    unsigned char parcel[64] = {0};
    const uint32_t header[] = {0x80000000U, 0xffffffffU, 0x53595354U, 14};
    const uint16_t token[] = {'a','m','t','r','a','c','e','r','.','I','T','e','s','t',0};
    memcpy(parcel, header, sizeof(header));
    memcpy(parcel + sizeof(header), token, sizeof(token));
    struct binder_transaction_data request = {
        .target.handle = 0,
        .code = SYNC_CODE,
        .data_size = 48,
        .data.ptr.buffer = (binder_uintptr_t)parcel,
    };
    if (send_sync(fd, &request) < 0) {
        perror("synchronous Binder transaction");
        munmap(mapping, (1U << 20) - (size_t)sysconf(_SC_PAGESIZE) * 2);
        close(fd);
        (void)kill(service, SIGTERM);
        (void)waitpid(service, NULL, 0);
        return 1;
    }
    if (send_oneway(fd, ONEWAY_CODE, parcel, 48) < 0 ||
        send_oneway(fd, STOP_CODE, NULL, 0) < 0) {
        perror("oneway Binder transaction");
        munmap(mapping, (1U << 20) - (size_t)sysconf(_SC_PAGESIZE) * 2);
        close(fd);
        (void)kill(service, SIGTERM);
        (void)waitpid(service, NULL, 0);
        return 1;
    }
    munmap(mapping, (1U << 20) - (size_t)sysconf(_SC_PAGESIZE) * 2);
    close(fd);
    int status = 0;
    if (waitpid(service, &status, 0) != service || !WIFEXITED(status) || WEXITSTATUS(status)) {
        fprintf(stderr, "Binder service failed\n");
        return 1;
    }
    if (!fgets(command, sizeof(command), stdin)) {
        return 1;
    }
    return 0;
}
