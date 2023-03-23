/*
 * 8086 emulator
 *
 * Emulator orginally from Andrew Jenner's reenigne project
 * DOS enhancements by TK Chia
 * ELKS executable support by Greg Haerr
 * Heavily rewritten and disassembler added by Greg Haerr
 */
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "8086.h"
#include "disasm.h"
#include "exe.h"        /* required for handleInterrupt/checkStack */

#if BLINK16
#include "blink/machine.h"
#endif

/* emulator globals */
Word registers[12];
Byte* byteRegisters[8];
Byte ram[RAMSIZE];
int f_verbose;

static Byte shadowRam[RAMSIZE];
static bool doShadowCheck;
static bool useMemory;
static Word address;
static Word ip;
static Byte opcode;
static Word flags;
static Byte modRM;
static int segment;
static int segmentOverride;
static bool wordSize;
static bool sourceIsRM;
static DWord data;
static DWord destination;
static DWord source;
static Word residue;
static int aluOperation;
static Word savedIP;
static Word savedCS;
static bool running;
static bool prefix;
static bool repeating;
static int rep;
//static int ios;
static struct exe *ep;

static inline Word rw(void)          { return registers[opcode & 7]; }
static inline void setRW(Word value) { registers[opcode & 7] = value; }
static inline void setRB(Byte value) { *byteRegisters[opcode & 7] = value; }

void initMachine(struct exe *e)
{
    memset(ram, 0, sizeof(ram));
    memset(shadowRam, 0, sizeof(shadowRam));
    ep = e;          /* saved passed struct exe * for handleInterrupt() */

    segment = 0;
    segmentOverride = -1;
    prefix = false;
    repeating = false;
    running = false;
    doShadowCheck = true;

    setCX(0x00FF);      /* must be 0x00FF as for big endian test below */
    Byte* byteData = (Byte*)&registers[0];
    int bigEndian = (byteData[2] == 0 ? 1 : 0);
    int byteNumbers[8] = {0, 2, 4, 6, 1, 3, 5, 7};
    for (int i = 0 ; i < 8; ++i)
        byteRegisters[i] = &byteData[byteNumbers[i] ^ bigEndian];
}

void initExecute(void)
{
    running = true;
}

#define CF  0x0001
#define PF  0x0004
#define AF  0x0010
#define ZF  0x0040
#define SF  0x0080
#define TF  0x0100
#define IF  0x0200
#define DF  0x0400
#define OF  0x0800

static void farJump();
static void push(Word value);

static void performInterrupt(struct exe *e, int intno)
{
    if (canHandleInterrupt(e, intno))
        handleInterrupt(e, intno);
    else {
        push(flags);
        push(cs());
        push(ip);
        flags &= ~(IF | TF);
        setCS(0x0000);
        savedIP = readWord((intno << 2) + 0, CS);
        savedCS = readWord((intno << 2) + 2, CS);
        if (!savedIP && !savedCS)
            runtimeError("INT 0x%02x vector not set\n", intno);
        farJump();
    }
}

static void divideOverflow(void)
{
    performInterrupt(ep, INT0_DIV_ERROR);
    data = source = 1;
}

void setShadowCheck(bool on)
{
    doShadowCheck = on;
}

void setShadowFlags(Word offset, int seg, int len, int flags)
{
    DWord a = ((DWord)registers[8 + seg] << 4) + offset;
    int i;

    if (f_verbose)
        printf("setShadow %04x:%04x len %05x to %x\n",
            registers[8+seg], offset, len, flags);
    for (i=0; i<len; i++) {
        if (a < RAMSIZE)
            shadowRam[a++] = flags;
    }
}

DWord physicalAddress(Word offset, int seg, int write)
{
    Word segmentAddress;
    DWord a;
    int flags;
    static char *segname[4] = { "ES", "CS", "SS", "DS" };

    //ios++;
    if (seg == -1) {
        seg = segment;
        if (segmentOverride != -1)
            seg = segmentOverride;
    }
    segmentAddress = registers[8 + seg];
    a = (((DWord)segmentAddress << 4) + offset) /*& 0xfffff*/;
    if (a >= RAMSIZE)
        runtimeError("Accessing address outside RAM %s %04x:%04x\n",
            segname[seg], segmentAddress, offset);

    if (!doShadowCheck)
        return a;
    flags = shadowRam[a];
    if (write && running && !(flags & fWrite))
        runtimeError("Writing disallowed address %s %04x:%04x\n",
            segname[seg], segmentAddress, offset);
    if (!write && !(flags & fRead))
        runtimeError("Reading uninitialized address %s %04x:%04x\n",
            segname[seg], segmentAddress, offset);
    if (running)
        shadowRam[a] |= fRead;
    return a;
}

Byte readByte(Word offset, int seg)
{
    DWord a = physicalAddress(offset, seg, false);
#if BLINK16
    if (seg != CS) SetReadAddr(g_machine, a, 1);
#endif
    return ram[a];
}

Word readWord(Word offset, int seg)
{
    DWord a = physicalAddress(offset, seg, false);
    Word r = ram[a];
#if BLINK16
    if (seg != CS) SetReadAddr(g_machine, a, 2);
#endif
    return r | (ram[physicalAddress(offset + 1, seg, false)] << 8);
}

void writeByte(Byte value, Word offset, int seg)
{
    DWord a = physicalAddress(offset, seg, true);
    ram[a] = value;
#if BLINK16
    if (seg != CS) SetWriteAddr(g_machine, a, 1);
#endif
}

void writeWord(Word value, Word offset, int seg)
{
    DWord a = physicalAddress(offset, seg, true);
    ram[a] = value;
    ram[physicalAddress(offset + 1, seg, true)] = value >> 8;
#if BLINK16
    if (seg != CS) SetWriteAddr(g_machine, a, 2);
#endif
}

static Word readwb(Word offset, int seg)
{
    return wordSize ? readWord(offset, seg) : readByte(offset, seg);
}

static void writewb(Word value, Word offset, int seg)
{
    if (wordSize)
        writeWord(value, offset, seg);
    else
        writeByte((Byte)value, offset, seg);
}
static Byte fetchByte() { Byte b = readByte(ip, CS); ++ip; return b; }
static Word fetchWord() { Word w = fetchByte(); w += fetchByte() << 8; return w; }
static Word fetch(bool wordSize)
{
    if (wordSize)
        return fetchWord();
    return fetchByte();
}
static Word signExtend(Byte data) { return data + (data < 0x80 ? 0 : 0xff00); }
static int modRMReg() { return (modRM >> 3) & 7; }
static void doJump(Word newIP)
{
    ip = newIP;
}
static void jumpShort(Byte data, bool jump)
{
    if (jump)
        doJump(ip + signExtend(data));
}
bool isRepeating(void) { return repeating; }
Word getIP(void) { return ip; }
Word getFlags(void) { return flags; }
void setIP(Word w) { ip = w; }
void setFlags(Word w) { flags = w; }
void setCF(bool cf) { flags = (flags & ~1) | (cf ? 1 : 0); }
static void setAF(bool af) { flags = (flags & ~0x10) | (af ? 0x10 : 0); }
static void clearCA() { setCF(false); setAF(false); }
static void setOF(bool of) { flags = (flags & ~0x800) | (of ? 0x800 : 0); }
static void clearCAO() { clearCA(); setOF(false); }
static void setPF()
{
    static Byte table[0x100] = {
        4, 0, 0, 4, 0, 4, 4, 0, 0, 4, 4, 0, 4, 0, 0, 4,
        0, 4, 4, 0, 4, 0, 0, 4, 4, 0, 0, 4, 0, 4, 4, 0,
        0, 4, 4, 0, 4, 0, 0, 4, 4, 0, 0, 4, 0, 4, 4, 0,
        4, 0, 0, 4, 0, 4, 4, 0, 0, 4, 4, 0, 4, 0, 0, 4,
        0, 4, 4, 0, 4, 0, 0, 4, 4, 0, 0, 4, 0, 4, 4, 0,
        4, 0, 0, 4, 0, 4, 4, 0, 0, 4, 4, 0, 4, 0, 0, 4,
        4, 0, 0, 4, 0, 4, 4, 0, 0, 4, 4, 0, 4, 0, 0, 4,
        0, 4, 4, 0, 4, 0, 0, 4, 4, 0, 0, 4, 0, 4, 4, 0,
        0, 4, 4, 0, 4, 0, 0, 4, 4, 0, 0, 4, 0, 4, 4, 0,
        4, 0, 0, 4, 0, 4, 4, 0, 0, 4, 4, 0, 4, 0, 0, 4,
        4, 0, 0, 4, 0, 4, 4, 0, 0, 4, 4, 0, 4, 0, 0, 4,
        0, 4, 4, 0, 4, 0, 0, 4, 4, 0, 0, 4, 0, 4, 4, 0,
        4, 0, 0, 4, 0, 4, 4, 0, 0, 4, 4, 0, 4, 0, 0, 4,
        0, 4, 4, 0, 4, 0, 0, 4, 4, 0, 0, 4, 0, 4, 4, 0,
        0, 4, 4, 0, 4, 0, 0, 4, 4, 0, 0, 4, 0, 4, 4, 0,
        4, 0, 0, 4, 0, 4, 4, 0, 0, 4, 4, 0, 4, 0, 0, 4};
    flags = (flags & ~4) | table[data & 0xff];
}
static void setZF()
{
    flags = (flags & ~0x40) |
        ((data & (!wordSize ? 0xff : 0xffff)) == 0 ? 0x40 : 0);
}
static void setSF()
{
    flags = (flags & ~0x80) |
        ((data & (!wordSize ? 0x80 : 0x8000)) != 0 ? 0x80 : 0);
}
static void setPZS() { setPF(); setZF(); setSF(); }
static void bitwise(Word value) { data = value; clearCAO(); setPZS(); }
static void test(Word d, Word s)
{
    destination = d;
    source = s;
    bitwise(destination & source);
}
static bool cf() { return (flags & 1) != 0; }
static bool pf() { return (flags & 4) != 0; }
static bool af() { return (flags & 0x10) != 0; }
static bool zf() { return (flags & 0x40) != 0; }
static bool sf() { return (flags & 0x80) != 0; }
static void setIF(bool intf) { flags = (flags & ~0x200) | (intf ? 0x200 : 0); }
static void setDF(bool df) { flags = (flags & ~0x400) | (df ? 0x400 : 0); }
static bool df() { return (flags & 0x400) != 0; }
static bool of() { return (flags & 0x800) != 0; }
static int stringIncrement()
{
    int r = (wordSize ? 2 : 1);
    return !df() ? r : -r;
}
static Word lodS()
{
    address = si();
    setSI(si() + stringIncrement());
    segment = DS;
    return readwb(address, -1);
}
static void doRep(bool compare)
{
    if (rep == 1 && !compare)
        runtimeError("REPNE prefix with non-compare string instruction");
    if (rep == 0 || cx() == 0)
        return;
    setCX(cx() - 1);
    repeating = cx() != 0 && (!compare || zf() != (rep == 1));
}
static Word lodDIS()
{
    address = di();
    setDI(di() + stringIncrement());
    return readwb(address, ES);
}
static void stoS(Word data)
{
    address = di();
    setDI(di() + stringIncrement());
    writewb(data, address, ES);
}
#define o(c)
/***void o(char c)
{
    while (oCycle < ios) {
        ++oCycle;
        printf(" ");
    }
    ++oCycle;
    printf("%c", c);
}***/
static void push(Word value)
{
    o('{');
    setSP(sp() - 2);
    if (ep->checkStack(ep))
        runtimeError("Stack overflow SS:SP = %04x:%04x\n", ss(), sp());
    writeWord(value, sp(), SS);
}
static Word pop() {
    Word r = readWord(sp(), SS);
    setSP(sp() + 2);
    o('}');
    return r;
}
void setCA() { setCF(true); setAF(true); }
static void doAF() { setAF(((data ^ source ^ destination) & 0x10) != 0); }
static void doCF() { setCF((data & (!wordSize ? 0x100 : 0x10000)) != 0); }
static void setCAPZS() { setPZS(); doAF(); doCF(); }
static void setOFAdd()
{
    Word t = (data ^ source) & (data ^ destination);
    setOF((t & (!wordSize ? 0x80 : 0x8000)) != 0);
}
static void add() { data = destination + source; setCAPZS(); setOFAdd(); }
static void setOFSub()
{
    Word t = (destination ^ source) & (data ^ destination);
    setOF((t & (!wordSize ? 0x80 : 0x8000)) != 0);
}
static void sub() { data = destination - source; setCAPZS(); setOFSub(); }
static void setOFRotate()
{
    setOF(((data ^ destination) & (!wordSize ? 0x80 : 0x8000)) != 0);
}
static void doALUOperation()
{
    switch (aluOperation) {
        case 0: add(); o('+'); break;
        case 1: bitwise(destination | source); o('|'); break;
        case 2: source += cf() ? 1 : 0; add(); o('a'); break;
        case 3: source += cf() ? 1 : 0; sub(); o('B'); break;
        case 4: test(destination, source); o('&'); break;
        case 5: sub(); o('-'); break;
        case 7: sub(); o('?'); break;
        case 6: bitwise(destination ^ source); o('^'); break;
    }
}
static void divide()
{
    bool negative = false;
    bool dividendNegative = false;
    if (modRMReg() == 7) {
        if ((destination & 0x80000000) != 0) {
            destination = (unsigned)-(signed)destination;
            negative = !negative;
            dividendNegative = true;
        }
        if ((source & 0x8000) != 0) {
            source = (unsigned)-(signed)source & 0xffff;
            negative = !negative;
        }
    }
    data = destination / source;
    DWord product = data * source;
    // ISO C++ 2003 does not specify a rounding mode, but the x86 always
    // rounds towards zero.
    if (product > destination) {
        --data;
        product -= source;
    }
    residue = destination - product;
    if (negative)
        data = (unsigned)-(signed)data;
    if (dividendNegative)
        residue = (unsigned)-(signed)residue;
}
static Word* modRMRW() { return &registers[modRMReg()]; }
static Byte* modRMRB() { return byteRegisters[modRMReg()]; }
static Word getReg()
{
    if (!wordSize)
        return *modRMRB();
    return *modRMRW();
}
static Word getAccum() { return !wordSize ? al() : ax(); }
static void setAccum() { if (!wordSize) setAL(data); else setAX(data);  }
static void setReg(Word value)
{
    if (!wordSize)
        *modRMRB() = (Byte)value;
    else
        *modRMRW() = value;
}
static Word ea()
{
    modRM = fetchByte();
    useMemory = true;
    switch (modRM & 7) {
        case 0: segment = DS; address = bx() + si(); break;
        case 1: segment = DS; address = bx() + di(); break;
        case 2: segment = SS; address = bp() + si(); break;
        case 3: segment = SS; address = bp() + di(); break;
        case 4: segment = DS; address =        si(); break;
        case 5: segment = DS; address =        di(); break;
        case 6: segment = SS; address = bp();        break;
        case 7: segment = DS; address = bx();        break;
    }
    switch (modRM & 0xc0) {
        case 0x00:
            if ((modRM & 0xc7) == 6) {
                segment = 3;
                address = fetchWord();
            }
            break;
        case 0x40: address += signExtend(fetchByte()); break;
        case 0x80: address += fetchWord(); break;
        case 0xc0:
            useMemory = false;
            address = modRM & 7;
    }
    return address;
}
static Word readEA2()
{
    if (!useMemory) {
        if (wordSize)
            return registers[address];
        return *byteRegisters[address];
    }
    return readwb(address, -1);
}
static Word readEA() { address = ea(); return readEA2(); }
static void finishWriteEA(Word data)
{
    if (!useMemory) {
        if (wordSize)
            registers[address] = data;
        else
            *byteRegisters[address] = (Byte)data;
    }
    else
        writewb(data, address, -1);
}
static void writeEA(Word data) { ea(); finishWriteEA(data); }
static void farLoad()
{
    if (!useMemory)
        runtimeError("This instruction needs a memory address");
    savedIP = readWord(address, -1);
    savedCS = readWord(address + 2, -1);
}
static void farJump()
{
    if (!savedCS && !savedIP)
        runtimeError("Far jump to 0:0\n");
    setCS(savedCS);
    doJump(savedIP);
}

static void farCall() { push(cs()); push(ip); farJump(); }
static void call(Word address) { push(ip); doJump(address); }
static Word incdec(bool decrement)
{
    source = 1;
    if (!decrement) {
        data = destination + source;
        setOFAdd();
    }
    else {
        data = destination - source;
        setOFSub();
    }
    doAF();
    setPZS();
    return data;
}

/* execute a single repetition of instruction */
void executeInstruction(void)
{
    if (!repeating) {
        if (!prefix) {
            segmentOverride = -1;
            rep = 0;
        }
        prefix = false;
        opcode = fetchByte();
    }
    if (rep != 0 && (opcode < 0xa4 || opcode >= 0xb0 || opcode == 0xa8 || opcode == 0xa9))
        runtimeError("REP prefix with non-string instruction");
    wordSize = ((opcode & 1) != 0);
    sourceIsRM = ((opcode & 2) != 0);
    int operation = (opcode >> 3) & 7;
    bool jump;

    switch (opcode) {
            case 0x00: case 0x01: case 0x02: case 0x03:
            case 0x08: case 0x09: case 0x0a: case 0x0b:
            case 0x10: case 0x11: case 0x12: case 0x13:
            case 0x18: case 0x19: case 0x1a: case 0x1b:
            case 0x20: case 0x21: case 0x22: case 0x23:
            case 0x28: case 0x29: case 0x2a: case 0x2b:
            case 0x30: case 0x31: case 0x32: case 0x33:
            case 0x38: case 0x39: case 0x3a: case 0x3b:  // alu rmv,rmv
                data = readEA();
                if (!sourceIsRM) {
                    destination = data;
                    source = getReg();
                }
                else {
                    destination = getReg();
                    source = data;
                }
                aluOperation = operation;
                doALUOperation();
                if (aluOperation != 7) {
                    if (!sourceIsRM)
                        finishWriteEA(data);
                    else
                        setReg(data);
                }
                break;
            case 0x04: case 0x05: case 0x0c: case 0x0d:
            case 0x14: case 0x15: case 0x1c: case 0x1d:
            case 0x24: case 0x25: case 0x2c: case 0x2d:
            case 0x34: case 0x35: case 0x3c: case 0x3d:  // alu accum,i
                destination = getAccum();
                source = !wordSize ? fetchByte() : fetchWord();
                aluOperation = operation;
                doALUOperation();
                if (aluOperation != 7)
                    setAccum();
                break;
            case 0x06: case 0x0e: case 0x16: case 0x1e:  // PUSH segreg
                push(registers[operation + 8]);
                break;
            case 0x07: case 0x17: case 0x1f:  // POP segreg
                registers[operation + 8] = pop();
                break;
            case 0x26: case 0x2e: case 0x36: case 0x3e:  // segment override
                segmentOverride = operation - 4;
                o("e%ZE"[segmentOverride]);
                prefix = true;
                break;
            case 0x27:              // DAA
            case 0x2f:              // DAS
                if (af() || (al() & 0x0f) > 9) {
                    data = al() + (opcode == 0x27 ? 6 : -6);
                    setAL(data);
                    setAF(true);
                    if ((data & 0x100) != 0)
                        setCF(true);
                }
                setCF(cf() || al() > 0x9f);
                if (cf())
                    setAL(al() + (opcode == 0x27 ? 0x60 : -0x60));
                wordSize = false;
                data = al();
                setPZS();
                o(opcode == 0x27 ? 'y' : 'Y');
                break;
            case 0x37:              // AAA
            case 0x3f:              // AAS
                if (af() || (al() & 0xf) > 9) {
                    setAL(al() + (opcode == 0x37 ? 6 : -6));
                    setAH(ah() + (opcode == 0x37 ? 1 : -1));
                    setCA();
                }
                else
                    clearCA();
                setAL(al() & 0x0f);
                o(opcode == 0x37 ? 'A' : 'u');
                break;
            case 0x40: case 0x41: case 0x42: case 0x43:
            case 0x44: case 0x45: case 0x46: case 0x47:
            case 0x48: case 0x49: case 0x4a: case 0x4b:
            case 0x4c: case 0x4d: case 0x4e: case 0x4f:  // incdec rw
                destination = rw();
                wordSize = true;
                setRW(incdec((opcode & 8) != 0));
                o((opcode & 8) != 0 ? 'i' : 'd');
                break;
            case 0x50: case 0x51: case 0x52: case 0x53:
            case 0x54: case 0x55: case 0x56: case 0x57:  // PUSH rw
                push(rw());
                break;
            case 0x58: case 0x59: case 0x5a: case 0x5b:
            case 0x5c: case 0x5d: case 0x5e: case 0x5f:  // POP rw
                setRW(pop());
                break;
            case 0x60: case 0x61: case 0x62: case 0x63:
            case 0x64: case 0x65: case 0x66: case 0x67:
            case 0x68: case 0x69: case 0x6a: case 0x6b:
            case 0x6c: case 0x6d: case 0x6e: case 0x6f:
            case 0xc0: case 0xc1: case 0xc8: case 0xc9:  // invalid
            case 0xf1:
            case 0xd8: case 0xd9: case 0xda: case 0xdb:
            case 0xdc: case 0xdd: case 0xde: case 0xdf:  // escape
            case 0x0f:  // POP CS
                handleInterrupt(ep, kMachineUndefinedInstruction);
                break;
            case 0x9b:  // WAIT
            case 0xf0:  // LOCK
                break;
            case 0xf4:  // HLT
                break;  // FIXME possible interrupt?
            case 0xe4: case 0xe5:   // IN ib
                (void)fetchByte();
                //FIXME implement, returns -1 for now
                data = -1; setAccum();
                break;
            case 0xe6: case 0xe7:   // OUT ib
                (void)fetchByte();
                //FIXME implement
                break;
            case 0xec: case 0xed:   // IN dx
                //FIXME implement, returns -1 for now
                data = -1; setAccum();
                break;
            case 0xee: case 0xef:   // OUT dx
                //FIXME implement
                break;
            case 0x70: case 0x71: case 0x72: case 0x73:
            case 0x74: case 0x75: case 0x76: case 0x77:
            case 0x78: case 0x79: case 0x7a: case 0x7b:
            case 0x7c: case 0x7d: case 0x7e: case 0x7f:  // Jcond cb
                switch (opcode & 0x0e) {
                    case 0x00: jump = of(); break;
                    case 0x02: jump = cf(); break;
                    case 0x04: jump = zf(); break;
                    case 0x06: jump = cf() || zf(); break;
                    case 0x08: jump = sf(); break;
                    case 0x0a: jump = pf(); break;
                    case 0x0c: jump = sf() != of(); break;
                    default:   jump = sf() != of() || zf(); break;
                }
                jumpShort(fetchByte(), jump == ((opcode & 1) == 0));
                o("MK[)=J(]GgpP<.,>"[opcode & 0xf]);
                break;
            case 0x80: case 0x81: case 0x82: case 0x83:  // alu rmv,iv
                destination = readEA();
                data = fetch(opcode == 0x81);
                if (opcode != 0x83)
                    source = data;
                else
                    source = signExtend(data);
                aluOperation = modRMReg();
                doALUOperation();
                if (aluOperation != 7)
                    finishWriteEA(data);
                break;
            case 0x84: case 0x85:  // TEST rmv,rv
                data = readEA();
                test(data, getReg());
                o('t');
                break;
            case 0x86: case 0x87:  // XCHG rmv,rv
                data = readEA();
                finishWriteEA(getReg());
                setReg(data);
                o('x');
                break;
            case 0x88: case 0x89:  // MOV rmv,rv
                ea();
                finishWriteEA(getReg());
                o('m');
                break;
            case 0x8a: case 0x8b:  // MOV rv,rmv
                setReg(readEA());
                o('m');
                break;
            case 0x8c:  // MOV rmw,segreg
                ea();
                wordSize = 1;
                finishWriteEA(registers[modRMReg() + 8]);
                o('m');
                break;
            case 0x8d:  // LEA
                address = ea();
                if (!useMemory)
                    runtimeError("LEA needs a memory address");
                setReg(address);
                o('l');
                break;
            case 0x8e:  // MOV segreg,rmw
                wordSize = 1;
                data = readEA();
                registers[modRMReg() + 8] = data;
                o('m');
                break;
            case 0x8f:  // POP rmw
                writeEA(pop());
                break;
            case 0x90: case 0x91: case 0x92: case 0x93:
            case 0x94: case 0x95: case 0x96: case 0x97:  // XCHG AX,rw
                data = ax();
                setAX(rw());
                setRW(data);
                o(";xxxxxxx"[opcode & 7]);
                break;
            case 0x98:  // CBW
                setAX(signExtend(al()));
                o('b');
                break;
            case 0x99:  // CWD
                setDX((ax() & 0x8000) == 0 ? 0x0000 : 0xffff);
                o('w');
                break;
            case 0x9a:  // CALL cp
                savedIP = fetchWord();
                savedCS = fetchWord();
                o('c');
                farCall();
                break;
            case 0x9c:  // PUSHF
                o('U');
                push((flags & 0x0fd7) | 0xf000);
                break;
            case 0x9d:  // POPF
                o('O');
                flags = pop() | 2;
                break;
            case 0x9e:  // SAHF
                flags = (flags & 0xff02) | ah();
                o('s');
                break;
            case 0x9f:  // LAHF
                setAH(flags & 0xd7);
                o('L');
                break;
            case 0xa0: case 0xa1:  // MOV accum,xv
                segment = DS;
                data = readwb(fetchWord(), -1);
                setAccum();
                o('m');
                break;
            case 0xa2: case 0xa3:  // MOV xv,accum
                segment = DS;
                writewb(getAccum(), fetchWord(), -1);
                o('m');
                break;
            case 0xa4: case 0xa5:  // MOVSv
                if (rep == 0 || cx() != 0)
                    stoS(lodS());
                doRep(false);
                o('4' + (opcode & 1));
                break;
            case 0xa6: case 0xa7:  // CMPSv
                if (rep == 0 || cx() != 0) {
                    destination = lodS();
                    source = lodDIS();
                    sub();
                }
                doRep(true);
                o('0' + (opcode & 1));
                break;
            case 0xa8: case 0xa9:  // TEST accum,iv
                data = fetch(wordSize);
                test(getAccum(), data);
                o('t');
                break;
            case 0xaa: case 0xab:  // STOSv
                if (rep == 0 || cx() != 0)
                    stoS(getAccum());
                doRep(false);
                o('8' + (opcode & 1));
                break;
            case 0xac: case 0xad:  // LODSv
                if (rep == 0 || cx() != 0) {
                    data = lodS();
                    setAccum();
                }
                doRep(false);
                o('2' + (opcode & 1));
                break;
            case 0xae: case 0xaf:  // SCASv
                if (rep == 0 || cx() != 0) {
                    destination = getAccum();
                    source = lodDIS();
                    sub();
                }
                doRep(true);
                o('6' + (opcode & 1));
                break;
            case 0xb0: case 0xb1: case 0xb2: case 0xb3:
            case 0xb4: case 0xb5: case 0xb6: case 0xb7:
                setRB(fetchByte());
                o('m');
                break;
            case 0xb8: case 0xb9: case 0xba: case 0xbb:
            case 0xbc: case 0xbd: case 0xbe: case 0xbf:  // MOV rv,iv
                setRW(fetchWord());
                o('m');
                break;
            case 0xc2: case 0xc3: case 0xca: case 0xcb:  // RET
                savedIP = pop();
                savedCS = (opcode & 8) == 0 ? cs() : pop();
                if (!wordSize)
                    setSP(sp() + fetchWord());
                o('R');
                farJump();
                break;
            case 0xc4: case 0xc5:  // LES/LDS
                ea();
                farLoad();
                *modRMRW() = savedIP;
                registers[8 + (!wordSize ? 0 : 3)] = savedCS;
                o("NT"[opcode & 1]);
                break;
            case 0xc6: case 0xc7:  // MOV rmv,iv
                ea();
                finishWriteEA(fetch(wordSize));
                o('m');
                break;
            case 0xcc:  // INT 3
                performInterrupt(ep, INT3_BREAKPOINT);
                break;
            case 0xcd:
                performInterrupt(ep, fetchByte());
                o('$');
                break;
            case 0xce:  // INTO
                performInterrupt(ep, INT4_OVERFLOW);
                break;
            case 0xcf:  // IRET
                o('I');
                doJump(pop());
                setCS(pop());
                flags = pop() | 0xF002;
                if (!cs() && !ip) runtimeError("IRET to 0:0!\n");
                break;
            case 0xd0: case 0xd1: case 0xd2: case 0xd3:  // rot rmv,n
                data = readEA();
                if ((opcode & 2) == 0)
                    source = 1;
                else
                    source = cl();
                while (source != 0) {
                    destination = data;
                    switch (modRMReg()) {
                        case 0:  // ROL
                            data <<= 1;
                            doCF();
                            data |= (cf() ? 1 : 0);
                            setOFRotate();
                            break;
                        case 1:  // ROR
                            setCF((data & 1) != 0);
                            data >>= 1;
                            if (cf())
                                data |= (!wordSize ? 0x80 : 0x8000);
                            setOFRotate();
                            break;
                        case 2:  // RCL
                            data = (data << 1) | (cf() ? 1 : 0);
                            doCF();
                            setOFRotate();
                            break;
                        case 3:  // RCR
                            data >>= 1;
                            if (cf())
                                data |= (!wordSize ? 0x80 : 0x8000);
                            setCF((destination & 1) != 0);
                            setOFRotate();
                            break;
                        case 4:  // SHL
                        case 6:
                            data <<= 1;
                            doCF();
                            setOFRotate();
                            setPZS();
                            break;
                        case 5:  // SHR
                            setCF((data & 1) != 0);
                            data >>= 1;
                            setOFRotate();
                            setAF(true);
                            setPZS();
                            break;
                        case 7:  // SAR
                            setCF((data & 1) != 0);
                            data >>= 1;
                            if (!wordSize)
                                data |= (destination & 0x80);
                            else
                                data |= (destination & 0x8000);
                            setOFRotate();
                            setAF(true);
                            setPZS();
                            break;
                    }
                    --source;
                }
                finishWriteEA(data);
                o("hHfFvVvW"[modRMReg()]);
                break;
            case 0xd4:  // AAM
                data = fetchByte();
                if (data == 0)
                    divideOverflow();
                setAH(al() / data);
                setAL(al() % data);
                wordSize = true;
                setPZS();
                o('n');
                break;
            case 0xd5:  // AAD
                data = fetchByte();
                setAL(al() + ah()*data);
                setAH(0);
                setPZS();
                o('k');
                break;
            case 0xd6:  // SALC
                setAL(cf() ? 0xff : 0x00);
                o('S');
                break;
            case 0xd7:  // XLATB
                setAL(readByte(bx() + al(), -1));
                o('@');
                break;
            case 0xe0: case 0xe1: case 0xe2:  // LOOPc cb
                setCX(cx() - 1);
                jump = (cx() != 0);
                switch (opcode) {
                    case 0xe0: if (zf()) jump = false; break;
                    case 0xe1: if (!zf()) jump = false; break;
                }
                o("Qqo"[opcode & 3]);
                jumpShort(fetchByte(), jump);
                break;
            case 0xe3:  // JCXZ cb
                o('z');
                jumpShort(fetchByte(), cx() == 0);
                break;
            case 0xe8:  // CALL cw
                data = fetchWord();
                o('c');
                call(ip + data);
                break;
            case 0xe9:  // JMP cw
                o('j');
                data = fetchWord();
                doJump(ip + data);
                break;
            case 0xea:  // JMP cp
                o('j');
                savedIP = fetchWord();
                savedCS = fetchWord();
                farJump();
                break;
            case 0xeb:  // JMP cb
                o('j');
                jumpShort(fetchByte(), true);
                break;
            case 0xf2:  // REPNZ
            case 0xf3:  // REPZ
                o('r');
                rep = opcode == 0xf2 ? 1 : 2;
                prefix = true;
                break;
            case 0xf5:  // CMC
                o('\"');
                flags ^= 1;
                break;
            case 0xf6: case 0xf7:  // math rmv
                data = readEA();
                switch (modRMReg()) {
                    case 0: case 1:  // TEST rmv,iv
                        test(data, fetch(wordSize));
                        o('t');
                        break;
                    case 2:  // NOT iv
                        finishWriteEA(~data);
                        o('~');
                        break;
                    case 3:  // NEG iv
                        source = data;
                        destination = 0;
                        sub();
                        finishWriteEA(data);
                        o('_');
                        break;
                    case 4: case 5:  // MUL rmv, IMUL rmv
                        source = data;
                        destination = getAccum();
                        data = destination;
                        setSF();
                        setPF();
                        data *= source;
                        setAX(data);
                        if (!wordSize) {
                            if (modRMReg() == 4)
                                setCF(ah() != 0);
                            else {
                                if ((source & 0x80) != 0)
                                    setAH(ah() - destination);
                                if ((destination & 0x80) != 0)
                                    setAH(ah() - source);
                                setCF(ah() ==
                                    ((al() & 0x80) == 0 ? 0 : 0xff));
                            }
                        }
                        else {
                            setDX(data >> 16);
                            if (modRMReg() == 4) {
                                data |= dx();
                                setCF(dx() != 0);
                            }
                            else {
                                if ((source & 0x8000) != 0)
                                    setDX(dx() - destination);
                                if ((destination & 0x8000) != 0)
                                    setDX(dx() - source);
                                data |= dx();
                                setCF(dx() ==
                                    ((ax() & 0x8000) == 0 ? 0 : 0xffff));
                            }
                        }
                        setZF();
                        setOF(cf());
                        o("*#"[opcode & 1]);
                        break;
                    case 6: case 7:  // DIV rmv, IDIV rmv
                        source = data;
                        if (source == 0)
                            divideOverflow();
                        if (!wordSize) {
                            destination = ax();
                            if (modRMReg() == 6) {
                                divide();
                                if (data > 0xff)
                                    divideOverflow();
                            }
                            else {
                                destination = ax();
                                if ((destination & 0x8000) != 0)
                                    destination |= 0xffff0000;
                                source = signExtend(source);
                                divide();
                                if (data > 0x7f && data < 0xffffff80)
                                    divideOverflow();
                            }
                            setAH((Byte)residue);
                            setAL(data);
                        }
                        else {
                            destination = (dx() << 16) + ax();
                            divide();
                            if (modRMReg() == 6) {
                                if (data > 0xffff)
                                    divideOverflow();
                            }
                            else {
                                if (data > 0x7fff && data < 0xffff8000)
                                    divideOverflow();
                            }
                            setDX(residue);
                            setAX(data);
                        }
                        o("/\\"[opcode & 1]);
                        break;
                }
                break;
            case 0xf8: case 0xf9:  // STC/CLC
                setCF(wordSize);
                o("\'`"[opcode & 1]);
                break;
            case 0xfa: case 0xfb:  // STI/CLI
                setIF(wordSize);
                o("!:"[opcode & 1]);
                break;
            case 0xfc: case 0xfd:  // STD/CLD
                setDF(wordSize);
                o("CD"[opcode & 1]);
                break;
            case 0xfe: case 0xff:  // misc
                ea();
                if ((!wordSize && modRMReg() >= 2 && modRMReg() <= 6) ||
                    modRMReg() == 7) {
                        runtimeError("Invalid instruction %02x %02x", opcode, modRM);
                }
                switch (modRMReg()) {
                    case 0: case 1:  // incdec rmv
                        destination = readEA2();
                        finishWriteEA(incdec(modRMReg() != 0));
                        o("id"[modRMReg() & 1]);
                        break;
                    case 2:  // CALL rmv
                        o('c');
                        call(readEA2());
                        break;
                    case 3:  // CALL mp
                        o('c');
                        farLoad();
                        farCall();
                        break;
                    case 4:  // JMP rmw
                        o('j');
                        doJump(readEA2());
                        break;
                    case 5:  // JMP mp
                        o('j');
                        farLoad();
                        farJump();
                        break;
                    case 6:  // PUSH rmw
                        push(readEA2());
                        break;
                }
                break;
    }
}
