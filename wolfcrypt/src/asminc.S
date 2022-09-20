#ifndef __APPLE__
#define ASM_NAME(name) name
#define FUNCTION_ALIGN .align	16
#define TEXT_START .text
#else
#define ASM_NAME(name) _##name
#define FUNCTION_ALIGN .p2align	4
#define TEXT_START .section	__TEXT,__text
#endif

#ifdef __ELF__
#define FUNCTION(name) \
	TEXT_START; \
	.globl	ASM_NAME(name); \
	.type	ASM_NAME(name),@function; \
	FUNCTION_ALIGN; \
ASM_NAME(name):
#define FUNCTION_END(name) .size	ASM_NAME(name),.-ASM_NAME(name)
#define CALL(name) callq ASM_NAME(name)@plt
#else
#define FUNCTION(name) \
	TEXT_START; \
	.globl	ASM_NAME(name); \
	FUNCTION_ALIGN; \
ASM_NAME(name):
#define FUNCTION_END(name)
#define CALL(name) callq ASM_NAME(name)
#endif

