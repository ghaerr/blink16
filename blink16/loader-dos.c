/* DOS executable loader for 8086 emulator */
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

extern int f_verbose;
Word loadSegment;       // FIXME remove as global

static void loadError(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);
    exit(1);
}

static void write_environ(int argc, char **argv, char **envp)
{
    int envSegment = loadSegment - 0x10 - 0x0c;
    char *filename = argv[0];
    int i;

    /* prepare environment segment */
    setES(envSegment);
    setShadowFlags(0, ES, 0xc0, fRead);
    writeByte(0x00, 0, ES);            // No environment for now
    writeWord(0x0001, 1, ES);
    for (i = 0; filename[i] != 0; ++i) {
        writeByte(filename[i], i + 3, ES);
        if (i + 4 >= 0xc0)
            loadError("Program name too long\n");
    }
    writeWord(0x0000, i + 3, ES);

    /* prepare PSP */
    setES(loadSegment - 0x10);
    setShadowFlags(0, ES, 0x0100, fRead);
    writeWord(0x9fff, 2, ES);
    writeWord(envSegment, 0x2c, ES);
    i = 0x81;
    for (int a = 2; a < argc; ++a) {
        if (a > 2)
            writeByte(' ', i++, ES);

        char* arg = argv[a];
        int quote = strchr(arg, ' ') != 0;
        if (quote)
            writeByte('\"', i++, ES);

        for (; *arg != 0; ++arg) {
            if (*arg == '\"')
                writeByte('\\', i++, ES);
            writeByte(*arg, i++, ES);
        }
        if (quote)
            writeByte('\"', i++, ES);
        if (i > 0xff)
            loadError("Arguments too long\n");
    }
    writeByte('\r', i, ES);
    writeByte(i - 0x81, 0x80, ES);
}

static void load_bios_values(void)
{
    // Fill up parts of the interrupt vector table, the BIOS clock tick count,
    // and parts of the BIOS ROM area with stuff, for the benefit of the far
    // pointer tests.
    setES(0x0000);
    setShadowFlags(0x0080, ES, 0x0004, fRead);
    writeWord(0x0000, 0x0080, ES);
    writeWord(0xFFFF, 0x0082, ES);
    setShadowFlags(0x0400, ES, 0x00FF, fRead);
    writeWord(0x0058, 0x046C, ES);
    writeWord(0x000C, 0x046E, ES);
    writeByte(0x00, 0x0470, ES);
    setES(0xF000);
    setShadowFlags(0xFF00, ES, 0x0100, fRead);
    for (int i = 0; i < 0x100; i += 2)
        writeWord(0xF4F4, 0xFF00 + i, ES);
    // We need some variety in the ROM BIOS content...
    writeByte(0xEA, 0xFFF0, ES);
    writeWord(0xFFF0, 0xFFF1, ES);
    writeWord(0xF000, 0xFFF3, ES);
}

void loadExecutableDOS(struct exe *e, const char *path, int argc, char **argv, char **envp)
{
    struct stat sbuf;

    int fd = open(path, O_RDONLY);
    if (fd < 0)
        loadError("Can't open %s\n", path);
    if (fstat(fd, &sbuf) < 0)
        loadError("Can't stat %s\n", path);
    size_t filesize = sbuf.st_size;

    loadSegment = 0x1000;
    int loadOffset = loadSegment << 4;
    if (filesize > RAMSIZE - loadOffset)
        loadError("Not enough memory to load %s, needs %d bytes have %d\n",
            path, filesize, RAMSIZE);
    if (read(fd, &ram[loadOffset], filesize) != filesize)
        loadError("Error reading executable: %s\n", path);
    close(fd);

    write_environ(argc, argv, envp);
    struct image_dos_header *hdr = (struct image_dos_header *)&ram[loadOffset];
    if (filesize >= 2 && hdr->e_magic == DOSMAGIC) {  // .exe file?
        if (filesize < 0x21)
            loadError("%s is too short to be an .exe file\n", path);
        Word bytesInLastBlock = hdr->e_cblp;
        int exeLength = ((hdr->e_cp - (bytesInLastBlock == 0 ? 0 : 1)) << 9)
            + bytesInLastBlock;
        Word headerParagraphs = hdr->e_cparhdr;
        Word headerLength = headerParagraphs << 4;
        if (exeLength > filesize || headerLength > filesize || headerLength > exeLength)
            loadError("%s is corrupt\n", path);
        Word imageSegment = loadSegment + headerParagraphs;
        struct dos_reloc *r = (struct dos_reloc *)&ram[loadOffset+hdr->e_lfarlc];
        for (int i = 0; i < hdr->e_crlc; ++i) {
            Word offset = r->r_offset;
            setCS(imageSegment + r->r_seg);
            writeWord(readWord(offset, CS) + imageSegment, offset, CS);
            r++;
        }
        setES(imageSegment);
        setShadowFlags(0, ES, exeLength - headerLength, fRead|fWrite);
        setES(loadSegment - 0x10);
        setDS(loadSegment - 0x10);
        setIP(hdr->e_ip);
        setCS(hdr->e_cs + imageSegment);
        Word ss = hdr->e_ss + imageSegment;
        setSS(ss);
        setSP(hdr->e_sp);
        e->t_stackLow = (((exeLength - headerLength + 15) >> 4) + imageSegment) << 4;
        if (e->t_stackLow < ((DWord)ss << 4) + 0x10)
            e->t_stackLow = ((DWord)ss << 4) + 0x10;
        if (e->t_stackLow > ((DWord)ss << 4) + sp()) /* disable for test.exe stub */
            e->t_stackLow = 0;
    } else {
        if (filesize > 0xff00)
            loadError("%s is too long to be a .com file\n", path);
        setES(loadSegment);
        setShadowFlags(0, ES, filesize, fRead|fWrite);
        setES(loadSegment - 0x10);
        setDS(loadSegment);
        setSS(loadSegment);
        setSP(0xFFFE);
        setCS(loadSegment);
        setIP(0x0100);
        e->t_stackLow = ((DWord)loadSegment << 4) + filesize;
    }
    // Some testcases copy uninitialized stack data, so mark as initialized
    // any locations that could possibly be stack.
    //if (a < ((DWord)loadSegment << 4) - 0x100 && running)
         //bad = true;
    setShadowFlags(0, SS, sp(), fRead|fWrite);
#if 0
    if (sp()) {
        Word d = 0;
        if (((DWord)ss() << 4) < stackLow)
            d = stackLow - ((DWord)ss() << 4);
        while (d < sp()) {
            writeByte(0, d, SS);
            ++d;
        }
    } else {
        Word d = 0;
        if (((DWord)ss() << 4) < stackLow)
            d = stackLow - ((DWord)ss() << 4);
        do {
            writeByte(0, d, SS);
            ++d;
        } while (d != 0);
    }
#endif
    load_bios_values();

    if (f_verbose) printf("CS:IP %04x:%04x DS %04x SS:SP %04x:%04x\n",
        cs(), getIP(), ds(), ss(), sp());
    setES(loadSegment - 0x10);
    setAX(0x0000);
    setBX(0x0000);
    setCX(0x0000);
    setDX(0x0000);
    setBP(0x091C);
    setSI(0x0100);
    setDI(0xFFFE);
    setFlags(0xF202);   /* Interrupts enabled and 8086 reserved bits on */

    e->handleSyscall = handleSyscallDOS;
    e->checkStack = checkStackDOS;
}
