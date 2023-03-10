#include "test/asm/mac.inc"
.globl	_start
_start:	mov	$10,%r15
"test jit too":

//	rol w/o flags
//	make -j8 o//blink o//test/asm/rorx.elf
//	o//blink/blinkenlights o//test/asm/rorx.elf

	mov	$7,%eax			# extended features
	xor	%ecx,%ecx
	cpuid
	bt	$8,%ebx			# bmi2
	jnc	"test not possible"

	.test	"rorx 1"
	stc
	mov	$0xf0000fff,%eax	# input value
	mov	$0x31337133,%ebx	# random data
	rorx	$4*2,%eax,%ebx
	.c
	cmp	$0xf0000fff,%eax	# unchanged
	.e
	cmp	$0xfff0000f,%ebx	# output value
	.e

	.test	"rorx $0 does nothing"
	stc
	mov	$0xf0000fff,%eax	# input value
	mov	$0x31337133,%ebx	# random data
	rorx	$0,%eax,%ebx
	.c
	cmp	$0xf0000fff,%eax	# unchanged
	.e
	cmp	$0xf0000fff,%ebx	# output value
	.e

	dec	%r15
	jnz	"test jit too"
"test succeeded":
	.exit
"test not possible":
	.exit
