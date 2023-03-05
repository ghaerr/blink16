/*
 * ELKS symbol table support
 *
 * July 2022 Greg Haerr
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdint.h>
#include "syms.h"

#if __ia16__
#define ALLOC(s,n)    ((int)(s = sbrk(n)) != -1)
#else
#define ALLOC(s,n)    ((s = malloc(n)) !=  NULL)
#endif

#define MAGIC       0x0301  /* magic number for ELKS executable progs */

/* read symbol table from executable into memory */
unsigned char * noinstrument sym_read_exe_symbols(struct exe *e, char *path)
{
    int fd;
    unsigned char *s;

    if (e->syms) return e->syms;
    if ((fd = open(path, O_RDONLY)) < 0) {
#if __ia16__
        char fullpath[128];
        sprintf(fullpath, "/bin/%s", path);     // FIXME use PATH
        if ((fd = open(fullpath, O_RDONLY)) < 0)
#endif
                return NULL;
    }
    errno = 0;
    if (read(fd, &e->aout, sizeof(e->aout)) != sizeof(e->aout)
        || ((e->aout.type & 0xFFFF) != MAGIC)
        || e->aout.syms == 0
#if __ia16__
        || e->aout.syms > 32767
#endif
        || (!ALLOC(s, (int)e->aout.syms))
        || (lseek(fd, -(int)e->aout.syms, SEEK_END) < 0)
        || (read(fd, s, (int)e->aout.syms) != (int)e->aout.syms)) {
                int e = errno;
                close(fd);
                errno = e;
                return NULL;
    }
    close(fd);
    e->syms = s;
    return s;
}

/* read symbol table file into memory */
unsigned char * noinstrument sym_read_symbols(struct exe *e, char *path)
{
    int fd;
    unsigned char *s;
    struct stat sbuf;

    if (e->syms) return e->syms;
    if ((fd = open(path, O_RDONLY)) < 0)
        return NULL;
    errno = 0;
    if (fstat(fd, &sbuf) < 0
        || sbuf.st_size == 0
#if __ia16__
        || sbuf.st_size > 32767
#endif
        || (!ALLOC(s, (int)sbuf.st_size))
        || (read(fd, s, (int)sbuf.st_size) != (int)sbuf.st_size)) {
                int e = errno;
                close(fd);
                errno = e;
                return NULL;
    }
    close(fd);
    e->syms = s;
    return s;
}

/* dealloate symbol table file in memory */
void noinstrument sym_free(struct exe *e)
{
#ifndef __ia16__        // FIXME ELKS uses sbrk()
    if (e->syms)
        free(e->syms);
#endif
    e->syms = NULL;
}

static int noinstrument type_text(unsigned char *p)
{
    return (p[TYPE] == 'T' || p[TYPE] == 't' || p[TYPE] == 'W');
}

static int noinstrument type_ftext(unsigned char *p)
{
    return (p[TYPE] == 'F' || p[TYPE] == 'f');
}

static int noinstrument type_data(unsigned char *p)
{
    return (p[TYPE] == 'D' || p[TYPE] == 'd' ||
            p[TYPE] == 'B' || p[TYPE] == 'b' ||
            p[TYPE] == 'V');
}

// FIXME rewrite as iterator function
unsigned char * noinstrument sym_next_text_entry(struct exe *e, unsigned char *entry)
{
    unsigned char *p = entry? symNext(entry): e->syms;
    for ( ; p; p = symNext(p)) {
        if (type_text(p))
            return p;
        if (entry)      /* done after last text entry */
            break;
     }
     return 0;
}

/* return symbol address */
addr_t noinstrument sym_address(struct exe *e, const char *name)
{
    unsigned char *p, *lastp;
    int len;

    p = e->syms;
    if (!p) return -1;

    len = strlen(name);
    do {
        if (symLen(p) == len && !strncmp(symName(p), name, len))
            return symAddr(p);
        p = symNext(p);
    } while (p);
    return symAddr(lastp);
}

/* map .text address to function start address */
addr_t  noinstrument sym_fn_start_address(struct exe *e, addr_t addr)
{
    unsigned char *p, *lastp;

    if (!e->syms) return -1;

    lastp = e->syms;
    for (p = symNext(lastp); ; lastp = p, p = symNext(p)) {
        if (!type_text(p) || ((unsigned short)addr < symAddr(p)))
            break;
    }
    return symAddr(lastp);
}

/* convert address to symbol string */
static char * noinstrument sym_string(struct exe *e, addr_t addr, int exact,
    int (*istype)(unsigned char *p))
{
    unsigned char *p, *lastp;
    static char buf[64];

    if (!e->syms) {
hex:
        sprintf(buf, "%.4x", (unsigned int)addr);
        return buf;
    }

    lastp = e->syms;
    while (!istype(lastp)) {
        lastp = symNext(lastp);
        if (!lastp[TYPE])
            goto hex;
    }
    for (p = symNext(lastp); ; lastp = p, p = symNext(p)) {
        if (!istype(p) || ((unsigned short)addr < symAddr(p)))
            break;
    }
    int lastaddr = symAddr(lastp);
    if (exact && addr - lastaddr) {
        sprintf(buf, "%.*s+%xh", lastp[SYMLEN], lastp+SYMBOL,
                                (unsigned int)addr - lastaddr);
    } else sprintf(buf, "%.*s", lastp[SYMLEN], lastp+SYMBOL);
    return buf;
}

/* convert .text address to symbol */
char * noinstrument sym_text_symbol(struct exe *e, addr_t addr, int exact)
{
    return sym_string(e, addr, exact, type_text);
}

/* convert .fartext address to symbol */
char * noinstrument sym_ftext_symbol(struct exe *e, addr_t addr, int exact)
{
    return sym_string(e, addr, exact, type_ftext);
}

/* convert .data address to symbol */
char * noinstrument sym_data_symbol(struct exe *e, addr_t addr, int exact)
{
    return sym_string(e, addr, exact, type_data);
}

#if 0
static int noinstrument type_any(unsigned char *p)
{
    return p[TYPE] != '\0';
}

/* convert (non-segmented local IP) address to symbol */
char * noinstrument sym_symbol(struct exe *e, addr_t addr, int exact)
{
    return sym_string(e, addr, exact, type_any);
}
#endif
