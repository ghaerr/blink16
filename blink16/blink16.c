/* blink changes for 8086 only blink16 */
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include "blink/machine.h"
#include "blink/endian.h"
#include "blink/assert.h"
#include "blink/loader.h"
#include "blink/dis.h"
#include "blink/util.h"

#include "8086.h"
#include "disasm.h"
#include "discolor.h"
#include "syms.h"

static char f_asmout = 0;
static struct dis dis8086;
static struct exe exe8086;

void runtimeError(const char *msg, ...)
{
    va_list args;
    va_start(args, msg);
    vfprintf(stderr, msg, args);
    va_end(args);
    fprintf(stderr, "\nCS:IP = %04x:%04x\n", cs(), getIP());
    exit(1);
}

void SetReadAddr(struct Machine *m, i64 addr, u32 size) {
  if (size) {
    m->readaddr = addr;
    m->readsize = size;
  }
}

void SetWriteAddr(struct Machine *m, i64 addr, u32 size) {
  if (size) {
    m->writeaddr = addr;
    m->writesize = size;
  }
}

u8 *LookupAddress(struct Machine *m, i64 virt)
{
    if (virt < 0 || virt >= RAMSIZE)
        return 0;
    return ram + virt;
}

static int nextbyte_mem(int cs, int ip)
{
    unsigned int offset = (cs << 4) + ip;

    if (offset >= RAMSIZE) return 0;
    return ram[offset] & 0xff;
}

long Dis(struct Dis *d, struct Machine *m, i64 addr, i64 ip, int lines)
{
    int i, nextip;

    d->m = m;
    if (lines > d->ops.n) {
        if (d->ops.p) {
            for (i=0; i<d->ops.n; i++) {
                if (d->ops.p[i].s)
                    free(d->ops.p[i].s);
            }
            free(d->ops.p);
        }
        d->ops.n = lines;
        d->ops.p = calloc(lines * sizeof(struct DisOp), 1);
        unassert(d->ops.p);
    }
    d->ops.i = lines;
    nextip = ip;
    dis8086.e = &exe8086;
    for (i=0; i<lines; i++) {
        addr_t fnstart = sym_fn_start_address(&exe8086, nextip);
        if (d->ops.p[i].s) {
            free(d->ops.p[i].s);
            d->ops.p[i].s = 0;
        }
        if (fnstart == nextip) {
            d->ops.p[i].cs = cs();
            d->ops.p[i].ip = nextip;
            d->ops.p[i].size = 0;
            char *p = d->buf;
            if (!(d->noraw & 2)) p += sprintf(p, "%04hx:", (unsigned short)cs());
            if (!(d->noraw & 4)) p += sprintf(p, "%04hx ", (unsigned short)nextip);
            if (d->noraw & 8) p += sprintf(p, "           ");
            p = highStart(p, g_high.label);
            p = stpcpy(p, sym_text_symbol(&exe8086, nextip, 1));
            p = highEnd(p);
            *p++ = ':';
            *p = '\0';
            d->ops.p[i].s = strdup(d->buf);
            if (++i >= lines)
                break;
            /* else fall through */
        }
        disasm(&dis8086, cs(), nextip, nextbyte_mem, ds(), 0);
        d->ops.p[i].cs = cs();
        d->ops.p[i].ip = nextip;
        d->ops.p[i].size = dis8086.oplen;
        nextip += dis8086.oplen;
    }
    m->oplen = 0;
    return 0;
}

// use lmr
long DisFind(struct Dis *d, i64 addr)
{
    int i;
    addr -= cs() << 4;
    for (i=0; i<d->ops.i; i++) {
        if (!d->ops.p[i].s && d->ops.p[i].ip == addr && d->ops.p[i].cs == cs()) {
            d->m->xedd->length = d->ops.p[i].size;
            return i;
        }
    }
    return -1;
}

const char *DisGetLine(struct Dis *d, struct Machine *m, int i)
{
    static char line[sizeof(d->buf)];

    if (d->ops.p[i].s)
        return d->ops.p[i].s;
    int flags = fDisCS | fDisIP | fDisInst;
    if (d->noraw & 2) flags &= ~fDisCS;
    if (d->noraw & 4) flags &= ~fDisIP;
    if (d->noraw & 8) flags |= fDisBytes;
    disasm(&dis8086, cs(), d->ops.p[i].ip, nextbyte_mem, ds(), flags);
    strcpy(line, colorInst(&dis8086, dis8086.buf));
    return line;
}

static void copyRegisters(struct Machine *m)
{
    Put16(m->ax, ax());
    Put16(m->bx, bx());
    Put16(m->cx, cx());
    Put16(m->dx, dx());
    Put16(m->si, si());
    Put16(m->di, di());
    Put16(m->sp, sp());
    Put16(m->bp, bp());
    m->cs.base = (m->cs.sel = cs()) << 4;
    m->ss.base = (m->ss.sel = ss()) << 4;
    m->ds.base = (m->ds.sel = ds()) << 4;
    m->es.base = (m->es.sel = es()) << 4;
    m->flags = getFlags();
}

void LoadProgram(struct Machine *m, char *prog, char **args, char **vars)
{
    int n;
    struct stat sbuf;

    int ac = 0;
    for (char **av = args; *av; av++) ac++;
    initMachine(&exe8086);
    if (endswith(prog, ".exe"))
        loadExecutableDOS(&exe8086, prog, ac, args, vars);
    else loadExecutableElks(&exe8086, prog, ac, args, vars);
    sym_read_exe_symbols(&exe8086, prog);
    copyRegisters(m);
    exe8086.textseg = cs();
    m->cs.base = (m->cs.sel = cs()) << 4;
    m->ip = getIP();
    m->system->codestart = m->ip;
    m->system->codesize = sbuf.st_size - exe8086.aout.hlen;
    initExecute();
}

struct System *NewSystem(void)
{
    static struct System s;

    //InitFds(&s->fds);
    return &s;
}

_Thread_local struct Machine *g_machine;

struct Machine *NewMachine(struct System *system, struct Machine *parent)
{
    static struct Machine m;
    static struct XedDecodedInst x;

    m.system = system;
    m.xedd = &x;
    g_machine = &m;
    return &m;
}

void ExecuteInstruction(struct Machine *m)
{
    //disasm(&dis8086, cs(), m->ip, nextbyte_mem, ds(), 0);
    //m->ip += dis8086.oplen;
    executeInstruction();
    if (!isRepeating())
        m->ip = getIP();
    m->oplen = 0;
    copyRegisters(m);
}

i64 GetPc(struct Machine *m)
{
    return (cs() << 4) + m->ip;
}

bool GetParity(u8 b) {
  b ^= b >> 4;
  b ^= b >> 2;
  b ^= b >> 1;
  return ~b & 1;
}
