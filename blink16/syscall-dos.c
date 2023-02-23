/* MSDOS system calls for 8086 emulator */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "8086.h"
#include "exe.h"

#if BLINK16
#include "blink/machine.h"
#define f_verbose   0
#else
extern int f_verbose;
#endif

extern  Word loadSegment;

static char* pathBuffers[2];
static int* fileDescriptors;
static int fileDescriptorCount = 6;

static void* alloc(size_t bytes)
{
    void* r = malloc(bytes);
    if (r == 0) {
        runtimeError("Out of memory\n");
    }
    return r;
}

static void init()
{
    pathBuffers[0] = (char*)alloc(0x10000);
    pathBuffers[1] = (char*)alloc(0x10000);

    fileDescriptors = (int*)alloc(6*sizeof(int));
    fileDescriptors[0] = STDIN_FILENO;
    fileDescriptors[1] = STDOUT_FILENO;
    fileDescriptors[2] = STDERR_FILENO;
    fileDescriptors[3] = STDOUT_FILENO;
    fileDescriptors[4] = STDOUT_FILENO;
    fileDescriptors[5] = -1;
}

static char* initString(Word offset, int seg, int write, int buffer, int bytes)
{
    for (int i = 0; i < bytes; ++i) {
        char p;
        if (write) {
            p = pathBuffers[buffer][i];
            ram[physicalAddress(offset + i, seg, true)] = p;
        }
        else {
            p = ram[physicalAddress(offset + i, seg, false)];
            pathBuffers[buffer][i] = p;
        }
        if (p == 0 && bytes == 0x10000)
            break;
    }
    if (!write)
        pathBuffers[buffer][0xffff] = 0;
    return pathBuffers[buffer];
}

static char* dsdxparms(int write, int bytes)
{
    return initString(dx(), DS, write, 0, bytes);
}

static char *dsdx()
{
    return dsdxparms(false, 0x10000);
}

static int dosError(int e)
{
    if (e == ENOENT)
        return 2;
    runtimeError("%s\n", strerror(e));
    return 0;
}

static int getDescriptor()
{
    for (int i = 0; i < fileDescriptorCount; ++i)
        if (fileDescriptors[i] == -1)
            return i;
    int newCount = fileDescriptorCount << 1;
    int* newDescriptors = (int*)alloc(newCount*sizeof(int));
    for (int i = 0; i < fileDescriptorCount; ++i)
        newDescriptors[i] = fileDescriptors[i];
    free(fileDescriptors);
    int oldCount = fileDescriptorCount;
    fileDescriptorCount = newCount;
    fileDescriptors = newDescriptors;
    return oldCount;
}

int checkStackDOS(struct exe *e)
{
    return (e->t_stackLow && ((DWord)ss() << 4) + sp() <= e->t_stackLow);
}

static int SysExit(struct exe *e, int rc)
{
    if (f_verbose) printf("EXIT %d\n", rc);
    exit(rc);
    return -1;
}

static int SysWrite(struct exe *e, int fd, char *buf, size_t n)
{
#if BLINK16
    extern ssize_t ptyWrite(int fd, char *buf, int len);
    SetWriteAddr(g_machine, physicalAddress(dx(), DS, false), n);
    return ptyWrite(fd, buf, n);
#else
    return write(fd, buf, n);
#endif
}

int handleSyscallDOS(struct exe *e, int intno)
{
        int fileDescriptor;
        char *p, *addr;
        DWord data;
        static int once = 0;

        if (!once) {
            init();
            once = 1;
        }
                switch (intno << 8 | ah()) {
                    case 0x1a00:
                        data = es();
                        setES(0);
                        setDX(readWordSeg(0x046c, ES));
                        setCX(readWordSeg(0x046e, ES));
                        setAL(readByte(0x0470, ES));
                        setES(data);
                        break;
                    case 0x2109:
                        addr = dsdx();
                        p = strchr(addr, '$');
                        if (p) SysWrite(e, STDOUT_FILENO, addr, p-addr);
                        break;
                    case 0x2130:
                        setAX(0x1403);
                        setBX(0xff00);
                        setCX(0);
                        break;
                    case 0x2139:
                        if (mkdir(dsdx(), 0700) == 0)
                            setCF(false);
                        else {
                            setCF(true);
                            setAX(dosError(errno));
                        }
                        break;
                    case 0x213a:
                        if (rmdir(dsdx()) == 0)
                            setCF(false);
                        else {
                            setCF(true);
                            setAX(dosError(errno));
                        }
                        break;
                    case 0x213b:
                        if (chdir(dsdx()) == 0)
                            setCF(false);
                        else {
                            setCF(true);
                            setAX(dosError(errno));
                        }
                        break;
                    case 0x213c:
                        fileDescriptor = creat(dsdx(), 0700);
                        if (fileDescriptor != -1) {
                            setCF(false);
                            int guestDescriptor = getDescriptor();
                            setAX(guestDescriptor);
                            fileDescriptors[guestDescriptor] = fileDescriptor;
                        }
                        else {
                            setCF(true);
                            setAX(dosError(errno));
                        }
                        break;
                    case 0x213d:
                        fileDescriptor = open(dsdx(), al() & 3, 0700);
                        if (fileDescriptor != -1) {
                            setCF(false);
                            setAX(getDescriptor());
                            fileDescriptors[ax()] = fileDescriptor;
                        }
                        else {
                            setCF(true);
                            setAX(dosError(errno));
                        }
                        break;
                    case 0x213e:
                        fileDescriptor = fileDescriptors[bx()];
                        if (fileDescriptor == -1) {
                            setCF(true);
                            setAX(6);  // Invalid handle
                            break;
                        }
                        if (fileDescriptor >= 5 &&
                            close(fileDescriptor) != 0) {
                            setCF(true);
                            setAX(dosError(errno));
                        }
                        else {
                            fileDescriptors[bx()] = -1;
                            setCF(false);
                        }
                        break;
                    case 0x213f:
                        fileDescriptor = fileDescriptors[bx()];
                        if (fileDescriptor == -1) {
                            setCF(true);
                            setAX(6);  // Invalid handle
                            break;
                        }
                        data = read(fileDescriptor, pathBuffers[0], cx());
                        dsdxparms(true, cx());
                        if (data == (DWord)-1) {
                            setCF(true);
                            setAX(dosError(errno));
                        }
                        else {
                            setCF(false);
                            setAX(data);
                        }
                        break;
                    case 0x2140:
                        fileDescriptor = fileDescriptors[bx()];
                        if (fileDescriptor == -1) {
                            setCF(true);
                            setAX(6);  // Invalid handle
                            break;
                        }
                        data = SysWrite(e, fileDescriptor, dsdxparms(false, cx()), cx());
                        if (data == (DWord)-1) {
                            setCF(true);
                            setAX(dosError(errno));
                        }
                        else {
                            setCF(false);
                            setAX(data);
                        }
                        break;
                    case 0x2141:
                        if (unlink(dsdx()) == 0)
                            setCF(false);
                        else {
                            setCF(true);
                            setAX(dosError(errno));
                        }
                        break;
                    case 0x2142:
                        fileDescriptor = fileDescriptors[bx()];
                        if (fileDescriptor == -1) {
                            setCF(true);
                            setAX(6);  // Invalid handle
                            break;
                        }
                        data = lseek(fileDescriptor, (cx() << 16) + dx(),
                            al());
                        if (data != (DWord)-1) {
                            setCF(false);
                            setDX(data >> 16);
                            setAX(data);
                        }
                        else {
                            setCF(true);
                            setAX(dosError(errno));
                        }
                        break;
                    case 0x2144:
                        if (al() != 0)
                            runtimeError("Unknown IOCTL 0x%02x", al());
                        fileDescriptor = fileDescriptors[bx()];
                        if (fileDescriptor == -1) {
                            setCF(true);
                            setAX(6);  // Invalid handle
                            break;
                        }
                        data = isatty(fileDescriptor);
                        if (data == 1) {
                            setDX(0x80);
                            setCF(false);
                        }
                        else {
                            if (errno == ENOTTY) {
                                setDX(0);
                                setCF(false);
                            }
                            else {
                                setAX(dosError(errno));
                                setCF(true);
                            }
                        }
                        break;
                    case 0x2147:
                        if (getcwd(pathBuffers[0], 64) != 0) {
                            setCF(false);
                            initString(si(), DS, true, 0, 0x10000);
                        }
                        else {
                            setCF(true);
                            setAX(dosError(errno));
                        }
                        break;
                    case 0x214a:
                        // Only allow attempts to "resize" the PSP segment,
                        // and check that CS:IP and SS:SP do not overshoot the
                        // segment end
                        if (es() == loadSegment - 0x10) {
                            DWord memEnd = (DWord)(es() + bx()) << 4;
                            if (physicalAddress(getIP(), CS, false) < memEnd &&
                                physicalAddress(sp() - 1, SS, true) < memEnd) {
                                setCF(false);
                                break;
                            }
                        }
                        runtimeError("Bad attempt to resize DOS memory "
                            "block: int 0x21, ah = 0x4a, bx = 0x%04x, "
                            "es = 0x%04x", (unsigned)bx(), (unsigned)es());
                        break;
                    case 0x214c:
                        //printf("*** Cycles: %i\n", ios);
                        SysExit(e, 0);
                        break;
                    case 0x2156:
                        if (rename(dsdx(), initString(di(), ES, false, 1, 0x10000)) == 0)
                            setCF(false);
                        else {
                            setCF(true);
                            setAX(dosError(errno));
                        }
                        break;
                    case 0x2157:
                        switch (al()) {
                            case 0x00:
                                fileDescriptor = fileDescriptors[bx()];
                                if (fileDescriptor == -1) {
                                    setCF(true);
                                    setAX(6);  // Invalid handle
                                    break;
                                }
                                setCX(0x0000); // Return a "reasonable" file
                                setDX(0x0021); // time and file date
                                setCF(false);
                                break;
                            default:
                                runtimeError("Unknown DOS call: int 0x21, "
                                    "ax = 0x%04x", (unsigned)ax());
                        }
                        break;
                    default:
                        runtimeError("Unknown DOS/BIOS call: int 0x%02x, "
                            "ah = 0x%02x", intno, (unsigned)ah());
                        return 0;
                }
                return 1;
}
