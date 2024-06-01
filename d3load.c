#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <malloc.h>
#include "winload.h"

extern char cmdline[];

typedef enum
{
  JIT_NOACTION = 0,
  JIT_REGISTER_FN,
  JIT_UNREGISTER_FN
} jit_actions_t;

struct jit_code_entry
{
  struct jit_code_entry *next_entry;
  struct jit_code_entry *prev_entry;
  const char *symfile_addr;
  uint64_t symfile_size;
};

struct jit_descriptor
{
  uint32_t version;
  /* This type should be jit_actions_t, but we use uint32_t
     to be explicit about the bitwidth.  */
  uint32_t action_flag;
  struct jit_code_entry *relevant_entry;
  struct jit_code_entry *first_entry;
};

/* GDB puts a breakpoint in this function.  */
void __attribute__((noinline)) __jit_debug_register_code() { };

/* Make sure to specify the version statically, because the
   debugger may check the version before we can set it.  */
struct jit_descriptor __jit_debug_descriptor = { 1, 0, 0, 0 };

struct jit_code_entry entry;

static void add_symfile(void *obj, int objsize)
{
	entry.prev_entry = NULL;
	entry.next_entry = __jit_debug_descriptor.first_entry;
	if (entry.next_entry)
		entry.next_entry->prev_entry = &entry;
	entry.symfile_addr = obj;
	entry.symfile_size = objsize;
	__jit_debug_descriptor.first_entry = &entry;
	__jit_debug_descriptor.relevant_entry = &entry;
	__jit_debug_descriptor.action_flag = JIT_REGISTER_FN;
	__jit_debug_register_code();
}

void *mapfile(const char *filename, void *base, int *psize) {
	int fd;
	off_t size;
	void *ret;

	if ((fd = open(filename, O_RDONLY)) == -1) {
		perror("open");
		return NULL;
	}
	if ((size = lseek(fd, 0, SEEK_END)) == (off_t)-1 ||
		lseek(fd, 0, SEEK_SET) == (off_t)-1) {
		perror("lseek");
		close(fd);
		return NULL;
	}
	if (!(ret = mmap(base, size, PROT_READ, MAP_PRIVATE, fd, 0))) {
		perror("mmap");
		close(fd);
		return NULL;
	}
	if (psize)
		*psize = (int)size;
	return ret;
}

void do_sym(const char *filename) {
	void *obj;
	int objsize;
	if ((obj = mapfile(filename, NULL, &objsize)))
		add_symfile(obj, objsize);
}

__attribute__((noinline)) void pre_entry() {
}

void patch_jmp(uintptr_t addr, void *val) {
	uint8_t *p = (uint8_t *)addr;
	*p = 0xe9;
	*((uint32_t *)(p + 1)) = (uintptr_t)val - addr - 5;
}

void *xmalloc(int size) {
	void *ret = calloc(1, size);
	if (!ret)
		abort();
	return ret;
}

#if 0
void orgmychkstk();
asm(
"\n orgmychkstk:"
"\n push       %ecx"
"\n cmp        $0x1000,%eax"
"\n lea        8(%esp),%ecx"
"\n jc         lab_0056de50"
"\n lab_0056de3c:"
"\n sub        $0x1000,%ecx"
"\n sub        $0x1000,%eax"
"\n orb        $0,(%ecx)"
"\n cmp        $0x1000,%eax"
"\n jnc        lab_0056de3c"
"\n lab_0056de50:"
"\n sub        %eax,%ecx"
"\n mov        %esp,%eax"
"\n or         $0,(%ecx)"
"\n mov        %ecx,%esp"
"\n mov        (%eax),%ecx"
"\n mov        4(%eax),%eax"
"\n push       %eax"
"\n ret"
);
#endif

void mychkstk();
asm(
"\n mychkstk:"
"\n push       %ecx"
"\n sub $8,%eax"
"\n cmp        $0x1000,%eax"
//"\n lea        8(%esp),%ecx"
"\n mov %esp,%ecx"
"\n jc         lab_0056de50"
"\n lab_0056de3c:"
"\n sub        $0x1000,%esp"
"\n sub        $0x1000,%eax"
"\n orl        $0,0xffc(%esp)"
"\n cmp        $0x1000,%eax"
"\n jnc        lab_0056de3c"
"\n lab_0056de50:"
"\n sub        %eax,%esp"
"\n mov        %ecx,%eax"
"\n orl        $0,0xffc(%esp)"
//"\n mov        %ecx,%esp"
"\n mov        (%eax),%ecx"
"\n mov        4(%eax),%eax"
"\n push       %eax"
"\n ret"
);

int main(int argc, char **argv) {
	mod_init();
	struct mod *mod = mod_load("../../pkg/descent3/MAIN.EXE", 0);
	do_sym("../../tmp/doom/MAIN.EXE_dbg");

	strcpy(cmdline, "MAIN.EXE -launched -nonetwork -nointro -nosound -nomusic -pilot a");

	//*(char *)0x505e16 = 0x90; *(char *)0x505e17 = 0xe9; // disable direct input keyb
	*(char *)0x503d60 = 0x33; *(char *)0x503d60 = 0xc0; *(char *)0x503d60 = 0xc3; // disable direct input?

	*(char *)0x0055fda3 = 0xeb; // disable ui framerate limit
	memcpy((char *)0x555c20, "\xc2\x04\x00", 3); // disable delay
	*(char *)0x4d0521 = 0xeb; // disable postlevelresults delay
	*(char *)0x4d05cd = 0xeb; // disable postlevelresults delay 2
	patch_jmp(0x57164d, malloc);
	patch_jmp(0x56fe25, free);
	patch_jmp(0x571c05, realloc);
	patch_jmp(0x5716d9, calloc);
	patch_jmp(0x571d3d, malloc_usable_size);
	patch_jmp(0x56d952, xmalloc); // actually operator new
	patch_jmp(0x56de30, mychkstk); 
	//*(short *)0x56dfba = 0x9090; *(char *)0x56dfc9 = 0xeb; // deopt strlen for valgrind
	//*(char *)0x0056e8bb = 0xeb; *(char *)0x056e8d7 = 0xeb; // deopt strncpy for valgrind
	patch_jmp(0x056dfb0, strlen);
	patch_jmp(0x056e8a0, strncpy);
	*(int *)0x4fbf66 = 0x90909090; *(char *)(0x4fbf66+4) = 0x90; // disable src=dst strncpy
	patch_jmp(0x56dec0, strcpy);
	patch_jmp(0x56ded0, strcat);
	patch_jmp(0x56e300, strstr);
	patch_jmp(0x56ebe0, strchr);

	pre_entry();

	void (*entry)() = (void *)mod_get_entry(mod);
	entry();
	
	return 0;
}
