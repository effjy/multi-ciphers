/* CSPRNG: prefer the getrandom(2) syscall, fall back to /dev/urandom. */
#include "random.h"
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/syscall.h>

int mc_random_bytes(void *buf, size_t len) {
    unsigned char *p = (unsigned char *)buf;
    size_t got = 0;

#ifdef SYS_getrandom
    while (got < len) {
        long r = syscall(SYS_getrandom, p + got, len - got, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            break; /* fall through to urandom */
        }
        got += (size_t)r;
    }
    if (got == len) return 0;
#endif

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    while (got < len) {
        ssize_t r = read(fd, p + got, len - got);
        if (r < 0) { if (errno == EINTR) continue; close(fd); return -1; }
        if (r == 0) { close(fd); return -1; }
        got += (size_t)r;
    }
    close(fd);
    return 0;
}
