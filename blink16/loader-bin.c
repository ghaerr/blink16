/*
 * boot block binary loader for 8086 emulator
 *
 * Greg Haerr
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "8086.h"
#include "exe.h"

static void loadError(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);
    exit(1);
}

int checkStackBinary(struct exe *e)
{
    return 0;
}

int handleSyscallBinary(struct exe *e, int intno)
{
    return 0;
}

void loadExecutableBinary(struct exe *e, const char *path, int argc, char **argv, char **envp)
{
    struct stat sbuf;

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        loadError("Can't open %s\n", path);
    if (fstat(fd, &sbuf) < 0)
        loadError("Can't stat %s\n", path);
    size_t filesize = sbuf.st_size;
    Word loadSegment = 0x07c0;
    int loadOffset = loadSegment << 4;
    if (filesize > RAMSIZE - loadOffset)
        loadError("Not enough memory to load %s, needs %d bytes have %d\n",
            path, filesize, RAMSIZE);
    if (read(fd, &ram[loadOffset], filesize) != filesize)
        loadError("Error reading executable: %s\n", path);
    close(fd);

    setES(0x0000);
    setShadowFlags(0, ES, 0x10000, fRead|fWrite);
    setES(0x1000);
    setShadowFlags(0, ES, 0x10000, fRead|fWrite);
    setES(0xB000);
    setShadowFlags(0, ES, 0x20000, fRead|fWrite);

    setES(0x0000);
    setDS(0x0000);
    setSS(0x0000);
    setSP(0x0000);
    setCS(0x0000);
    setIP(0x7c00);
    setAX(0x0000);
    setBX(0x0000);
    setCX(0x0000);
    setDX(0x0000);
    setBP(0x0000);
    setSI(0x0000);
    setDI(0x0000);
    setFlags(0xF202);   /* Interrupts enabled and 8086 reserved bits on */

    e->handleSyscall = handleSyscallBinary;
    e->checkStack = checkStackBinary;
}
