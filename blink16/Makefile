# Blink16 Makefile
#

BLINK16_SOURCE = \
    blinkenlights16.c           \
    blink16.c                   \
    disasm.c                    \
    syms.c                      \
    dissim.c                    \
    discolor.c                  \
    8086.c                      \
    loader-elks.c               \
    syscall-elks.c              \
    loader-dos.c                \
    syscall-dos.c               \

BLINK_SOURCE = \
    ../blink/commandv.c                  \
    ../blink/pty.c                       \
    ../blink/panel.c                     \
    ../blink/buffer.c                    \
    ../blink/readansi.c                  \
    ../blink/tpenc.c                     \
    ../blink/getopt.c                    \
    ../blink/cp437.c                     \
    ../blink/vasprintf.c                 \
    ../blink/strwidth.c                  \
    ../blink/message.c                   \
    ../blink/lines.c                     \
    ../blink/stats.c                     \
    ../blink/log.c                       \
    ../blink/errfd.c                     \
    ../blink/cga.c                       \
    ../blink/mda.c                       \
    ../blink/compress.c                  \
    ../blink/assert.c                    \
    ../blink/abort.c                     \
    ../blink/formatint64thousands.c      \
    ../blink/errno.c                     \
    ../blink/endswith.c                  \

all: blink16

blink16: $(BLINK16_SOURCE) $(BLINK_SOURCE)
	gcc -DBLINK16=1 -I.. -Os -o $@ $^ -lz

clean:
	rm -f blink16
