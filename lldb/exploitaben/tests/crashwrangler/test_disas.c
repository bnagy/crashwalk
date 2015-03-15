#define nlist_t int
#define mach_header_t int

#include <stdio.h>
#include <mach/machine.h>

extern char *ppc_disassemble( char *sect, unsigned long left);
extern char *i386_disassemble( char *sect, unsigned long left, cpu_type_t cputype);


int main() {
	
	int opcode;
	
	
	printf("PPC:\n");
	opcode = 0xbfc1fff8;  //stmw    r30,(r1) ppc
	printf("%s", ppc_disassemble((char*) &opcode, 4));  
	opcode = 0x3c5f0000; //addis r2, r31, 0
	printf("%s", ppc_disassemble((char*) &opcode, 4));  
	opcode = 0x88420004;  //lbz r2, 4(r2)
	printf("%s", ppc_disassemble((char*) &opcode, 4)); 
	opcode = 0x4e800020; //blr
	printf("%s", ppc_disassemble((char*) &opcode, 4)); 
	opcode = 0x4bff87a2;   //ba __memcpy.. knowing that it's ba is good enough
	printf("%s", ppc_disassemble((char*) &opcode, 4)); 

	printf("\n");
	
	
//CPU_TYPE_I386 or CPU_TYPE_X86_64	

#if defined (__i386__) || defined (__x86_64__)
	char opcode2[] =	"\x0f\xb7\x42\x04"; //movzwl 4(%edx),%eax
	char opcode3[] =	"\x8d\x83\x62\x00\x00\x00"; //	lea    98(%ebx),%eax
	char opcode4[] =	"\xc7\x44\x24\x40\x00\x00\x00\x00";  //  movl   $0x0,64(%esp) 
	char opcode5[] =	"\xe8\x98\xad"; //call printf  .. knowing it's a call is good enough
	char opcode6[] =	"\xc7\x00\x0c\x00\x00\x00"; //movl   $0xc,(%eax)
	char opcode7[] =	"\xc7\x00\x0c\x00\x00\x00\x55\x66\x33\x44\x22\x10\x23\xfc\xbc\xae\xed\xda"; //movl   $0xc,(%eax)
	char opcode8[] =	"\x00\x30\x06\x00\x10\x00"; //addb %dh,(%eax)
	//trying to disassemble intel on ppc usually causes a crash.
	printf("Intel 32:\n");
	printf("%s", i386_disassemble((char*) opcode2, sizeof(opcode2),CPU_TYPE_I386)); 
	printf("%s", i386_disassemble((char*) opcode3, sizeof(opcode3),CPU_TYPE_I386)); 
	printf("%s", i386_disassemble((char*) opcode4, sizeof(opcode4),CPU_TYPE_I386)); 
	printf("%s", i386_disassemble((char*) opcode5, sizeof(opcode5),CPU_TYPE_I386)); 
	printf("%s", i386_disassemble((char*) opcode6, sizeof(opcode6),CPU_TYPE_I386)); 
	printf("%s", i386_disassemble((char*) opcode7, sizeof(opcode7),CPU_TYPE_I386)); 	
	printf("%s", i386_disassemble((char*) opcode8, sizeof(opcode8),CPU_TYPE_I386)); 
	printf("\n");

#endif
#if defined (__x86_64__)
	char opcode9[] = "\x48\x8b\x05\x18\xcd\x00\x00"; //mov    0xcd18(%rip),%rax 
	char opcode10[] = "\x48\x8b\x10" ; //mov    (%rax),%rdx
	char opcode11[] = "\xe8\x3d\x04\x00\x00"; //callq  0x10002a74a <dyld_stub_puts>
	char opcode12[] = "\x74\x05" ; //je 0x10002a70c
	char opcode13[] = "\x48\x8d\x3d\xab\x9b\x00\x00"; //lea    0x9bab(%rip),%rdi 
	
	printf("Intel 64:\n");
	printf("%s", i386_disassemble((char*) opcode9, sizeof(opcode9),CPU_TYPE_X86_64)); 
	printf("%s", i386_disassemble((char*) opcode10, sizeof(opcode10),CPU_TYPE_X86_64)); 
	printf("%s", i386_disassemble((char*) opcode11, sizeof(opcode11),CPU_TYPE_X86_64)); 
	printf("%s", i386_disassemble((char*) opcode12, sizeof(opcode12),CPU_TYPE_X86_64)); 
	printf("%s", i386_disassemble((char*) opcode13, sizeof(opcode13),CPU_TYPE_X86_64)); 

	printf("\n");

#endif

}
