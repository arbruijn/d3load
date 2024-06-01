#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <malloc.h>

#include <GL/gl.h>
#include <SDL2/SDL.h>
#undef APIENTRY

#include "lwindef.h"
#include "lntimage.h"
#include "lwinnt.h"
#include "heap.h"

#include "wtype.h"

#include "funs.h"

#include "winload.h"
#define stricmp strcasecmp

#define ELMS(x) (sizeof(x)/sizeof(x)[0])

int tls_vars = 1;
unsigned tls_vals[32];
int last_error;
char cmdline[256];

const char *wsockord[] = {
NULL,
"accept",
"bind",
"closesocket",
"connect",
"getpeername",
"getsockname",
"getsockopt",
"htonl",
"htons",
"inet_addr",
"inet_ntoa",
"ioctlsocket",
"listen",
"ntohl",
"ntohs",
"recv",
"recvfrom",
"select",
"send",
"sendto",
"setsockopt",
"shutdown",
"socket"
};

unsigned myGetStdHandle(unsigned type) { return HFILE_OFS + 1; }
unsigned myWriteFile(unsigned hFile, unsigned buf, unsigned size, unsigned pret, unsigned ovl) {
	//printf("WriteFile %x %x %x %x %x\n", hFile, buf, size, pret, ovl);
	if ((hFile & ~HFILE_MASK) != HFILE_OFS)
		return 0;
	int ret = write(hFile & HFILE_MASK, (void *)buf, size);
	if (pret && ret >= 0)
		*(unsigned *)pret = ret;
	return ret >= 0;
}
unsigned myVirtualAlloc(unsigned lpAddress, unsigned dwSize, unsigned flAllocationType, unsigned flProtect) {
	if (lpAddress)
		return flAllocationType == 0x1000 ? lpAddress : 0;
	return (unsigned)memalign(4096, dwSize);
}
unsigned myIsBadWritePtr(unsigned a, unsigned b) { return 0; }
unsigned myIsBadReadPtr(unsigned a, unsigned b) { return 0; }
unsigned myHeapValidate(unsigned a, unsigned b, unsigned c) { return 1; }
char * myGetCommandLineA() { return cmdline; }
unsigned myGetVersion() { return 4; }
uintptr_t find_fun(const char *name);
unsigned myGetProcAddress(unsigned lib, char *name) {
	printf("getprocaddr %x %s\n", lib, (char *)name);
	return lib == 1 ? (unsigned)find_fun(name) : lib >= 4096 ? mod_find((struct mod *)lib, name) : 0;
}
extern struct mod *mod_list;
unsigned myGetModuleHandleA(unsigned name) { printf("getmodhan %s\n", (char *)name); return name ? 1 : (unsigned)mod_list; }
unsigned myGetCurrentThreadId() { return 0; }
unsigned myTlsSetValue(unsigned n, unsigned val) { if (n >= tls_vars) { last_error = ERROR_INVALID_PARAMETER; return 0; } tls_vals[n] = val; return 1; }
unsigned myTlsAlloc() { if (tls_vars == ELMS(tls_vals)) return TLS_OUT_OF_INDEXES; return tls_vars++; }
unsigned myTlsFree(unsigned v) { if (v == tls_vars - 1) tls_vars--; return 1; }
unsigned mySetLastError(unsigned err) { last_error = err; return 0; }
unsigned myTlsGetValue(unsigned n) { if (n < tls_vars) { last_error = 0; return tls_vals[n]; } last_error = ERROR_INVALID_PARAMETER; return 0; }
unsigned myGetLastError() { return last_error; }
unsigned myDebugBreak() { return 0; }
unsigned myInterlockedDecrement(unsigned a) { return 0; }
unsigned myOutputDebugStringA(unsigned msg) { printf("OutputDebugString: %s\n", (char *)msg); return 0; }
unsigned myLoadLibraryA(const char * name) {
	printf("loadlib %s\n", name);
	if (strcmp(name, "opengl32.dll") == 0)
		return 1;
	if (name[0] && name[1] == ':') {
		char path[256];
		convpath(path, name);
		return (unsigned)mod_load(path, 1);
	}
	return 0;
}
unsigned myInterlockedIncrement(unsigned a) { return 0; }
unsigned myGetModuleFileNameA(unsigned a, unsigned b, unsigned c) { return 0; }
unsigned myExitProcess(unsigned code) { exit(code); return 0; }
unsigned myTerminateProcess(unsigned a, unsigned b) { return 0; }
unsigned myGetCurrentProcess() { return 0; }
unsigned myInitializeCriticalSection(unsigned a) { return 0; }
unsigned myDeleteCriticalSection(unsigned a) { return 0; }
unsigned myEnterCriticalSection(unsigned a) { return 0; }
unsigned myLeaveCriticalSection(unsigned a) { return 0; }
unsigned myRtlUnwind(unsigned a, unsigned b, unsigned c, unsigned d) { return 0; }
unsigned myHeapAlloc(unsigned heap, unsigned flags, unsigned size) { unsigned ptr = (unsigned)malloc(size); heap_add((struct heap *)heap, ptr); return ptr; }
unsigned myHeapReAlloc(unsigned a, unsigned b, unsigned c, unsigned d) { return 0; }
unsigned myHeapFree(unsigned heap, unsigned b, unsigned ptr) { if (!heap_del((struct heap *)heap, ptr)) return 0; free((void *)ptr); return 1; }
unsigned myVirtualFree(unsigned ptr, unsigned b, unsigned free_type) { if (free_type == MEM_RELEASE) free((void *)ptr); return 1; }
unsigned myGetEnvironmentVariableA(unsigned a, unsigned b, unsigned c) { return 0; }
unsigned myGetVersionExA(OSVERSIONINFOA *v) { v->dwPlatformId = 2; v->dwMajorVersion = 4; v->dwMinorVersion = 0; v->dwBuildNumber = 0; v->szCSDVersion[0] = 0; return 1; }
unsigned myHeapDestroy(unsigned heap) { heap_free_all((struct heap *)heap); heap_done((struct heap *)heap); return 1; }
unsigned myHeapCreate(unsigned a, unsigned b, unsigned c) { return (unsigned)heap_create(); }
unsigned myGetCPInfo(unsigned a, unsigned b) { return 0; }
unsigned myGetACP() { return 1252; }
unsigned myGetOEMCP() { return 437; }
unsigned mySetHandleCount(unsigned a) { return 0; }
unsigned myGetFileType(unsigned a) { /*printf("GetFileType %x\n", a);*/ return 1; }
unsigned myGetStartupInfoA(unsigned info) { memset((void *)info, 0, 17 * 4); return 0; }
unsigned myFreeEnvironmentStringsA(unsigned a) { return 0; }
unsigned myFreeEnvironmentStringsW(unsigned a) { return 0; }
unsigned myWideCharToMultiByte(unsigned a, unsigned b, unsigned srcn, unsigned srclen, unsigned destn, unsigned destlen, unsigned x, unsigned y) {
	uint16_t *src = (uint16_t *)srcn;
	uint8_t *dest = (uint8_t *)destn, *p = dest;
	if (srclen == 0xffffffff) { uint16_t *ps = src; while (*ps++) {} srclen = ps - src; }
	if (!dest)
		return srclen;
	while (srclen-- && destlen--) *p++ = *src++;
	return p - dest;
}
unsigned myGetEnvironmentStrings() { static uint8_t strs[] = {0, 0}; return (unsigned)&strs; }
unsigned myGetEnvironmentStringsW() { static uint16_t strs[] = {0, 0}; return (unsigned)&strs; }
unsigned mySetFilePointer(unsigned hFile, unsigned lDistanceToMove, unsigned *pDistanceToMoveHigh, unsigned dwMoveMethod) {
	if ((hFile & ~HFILE_MASK) != HFILE_OFS)
		return 0;
	off_t pos = lseek(hFile & HFILE_MASK,
		lDistanceToMove | (pDistanceToMoveHigh ? (off_t)*pDistanceToMoveHigh << 32 : 0),
		dwMoveMethod);
	if (pos == (off_t)-1)
		return INVALID_FILE_SIZE;
	if (pDistanceToMoveHigh)
		*pDistanceToMoveHigh = pos >> 32;
	return (unsigned)pos;
}
unsigned myMultiByteToWideChar(unsigned a, unsigned b, unsigned c, unsigned d, unsigned e, unsigned f) { return 0; }
unsigned myGetStringTypeA(unsigned a, unsigned b, unsigned c, unsigned d, unsigned e) { return 0; }
unsigned myGetStringTypeW(unsigned a, unsigned b, unsigned c, unsigned d, unsigned e) { return 0; }
unsigned myLCMapStringA(unsigned a, unsigned b, unsigned c, unsigned d, unsigned e, unsigned f) { return 0; }
unsigned myLCMapStringW(unsigned a, unsigned b, unsigned c, unsigned d, unsigned e, unsigned f) { return 0; }
unsigned myRaiseException(unsigned dwExceptionCode, unsigned dwExceptionFlags,
	unsigned nNumberOfArguments, unsigned lpArguments) {
	printf("RaiseException %x %x %x %x\n", dwExceptionCode, dwExceptionFlags,
		nNumberOfArguments, lpArguments);
	abort();
	return 0;
}
unsigned mySetStdHandle(unsigned a, unsigned b) { return 0; }
unsigned myFlushFileBuffers(unsigned a) { return 0; }
unsigned myCloseHandle(unsigned a) {
	//printf("CloseHandle %x\n", a);
	if ((a & ~HFILE_MASK) == HFILE_OFS)
		close(a & HFILE_MASK);
	return 0;
}

struct {
	const char *name;
	int args;
	void *fun;
} funs[] = {
	{"GetStdHandle", 1, myGetStdHandle},
	{"WriteFile", 5, myWriteFile},
	{"VirtualAlloc", 4, myVirtualAlloc},
	{"IsBadWritePtr", 2, myIsBadWritePtr},
	{"IsBadReadPtr", 2, myIsBadReadPtr},
	{"HeapValidate", 3, myHeapValidate},
	{"GetCommandLineA", 0, myGetCommandLineA},
	{"GetVersion", 0, myGetVersion},
	{"GetProcAddress", 2, myGetProcAddress},
	{"GetModuleHandleA", 1, myGetModuleHandleA},
	{"GetCurrentThreadId", 0, myGetCurrentThreadId},
	{"TlsSetValue", 2, myTlsSetValue},
	{"TlsAlloc", 0, myTlsAlloc},
	{"TlsFree", 1, myTlsFree},
	{"SetLastError", 1, mySetLastError},
	{"TlsGetValue", 1, myTlsGetValue},
	{"GetLastError", 0, myGetLastError},
	{"DebugBreak", 0, myDebugBreak},
	{"InterlockedDecrement", 1, myInterlockedDecrement},
	{"OutputDebugStringA", 1, myOutputDebugStringA},
	{"LoadLibraryA", 1, myLoadLibraryA},
	{"InterlockedIncrement", 1, myInterlockedIncrement},
	{"GetModuleFileNameA", 3, myGetModuleFileNameA},
	{"ExitProcess", 1, myExitProcess},
	{"TerminateProcess", 2, myTerminateProcess},
	{"GetCurrentProcess", 0, myGetCurrentProcess},
	{"InitializeCriticalSection", 1, myInitializeCriticalSection},
	{"DeleteCriticalSection", 1, myDeleteCriticalSection},
	{"EnterCriticalSection", 1, myEnterCriticalSection},
	{"LeaveCriticalSection", 1, myLeaveCriticalSection},
	{"RtlUnwind", 4, myRtlUnwind},
	{"HeapAlloc", 3, myHeapAlloc},
	{"HeapReAlloc", 4, myHeapReAlloc},
	{"HeapFree", 3, myHeapFree},
	{"VirtualFree", 3, myVirtualFree},
	{"GetEnvironmentVariableA", 3, myGetEnvironmentVariableA},
	{"GetVersionExA", 1, myGetVersionExA},
	{"HeapDestroy", 1, myHeapDestroy},
	{"HeapCreate", 3, myHeapCreate},
	{"GetCPInfo", 2, myGetCPInfo},
	{"GetACP", 0, myGetACP},
	{"GetOEMCP", 0, myGetOEMCP},
	{"SetHandleCount", 1, mySetHandleCount},
	{"GetFileType", 1, myGetFileType},
	{"GetStartupInfoA", 1, myGetStartupInfoA},
	{"FreeEnvironmentStringsA", 1, myFreeEnvironmentStringsA},
	{"FreeEnvironmentStringsW", 1, myFreeEnvironmentStringsW},
	{"WideCharToMultiByte", 8, myWideCharToMultiByte},
	{"GetEnvironmentStrings", 0, myGetEnvironmentStrings},
	{"GetEnvironmentStringsW", 0, myGetEnvironmentStringsW},
	{"SetFilePointer", 4, mySetFilePointer},
	{"MultiByteToWideChar", 6, myMultiByteToWideChar},
	{"GetStringTypeA", 5, myGetStringTypeA},
	{"GetStringTypeW", 5, myGetStringTypeW},
	{"LCMapStringA", 6, myLCMapStringA},
	{"LCMapStringW", 6, myLCMapStringW},
	{"RaiseException", 4, myRaiseException},
	{"SetStdHandle", 2, mySetStdHandle},
	{"FlushFileBuffers", 1, myFlushFileBuffers},
	{"CloseHandle", 1, myCloseHandle},
#include "defs.h"
};

#define FUN_COUNT (sizeof(funs) / sizeof(funs[0]))
void *funwraps[FUN_COUNT];
void *wrap_code;
int wrap_code_size;

int create_wrappers() {
	uint8_t *code;
	int size = 0;
	for (int i = 0; i < FUN_COUNT; i++)
		if (funs[i].args)
			size += 3 /* align */ + 4 * funs[i].args + 5 /* call */ + 3 /* esp */ + 3 /* ret */ + 4 /* 3+1 ebp */;
	if (!(wrap_code = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0)))
		return -1;
	wrap_code_size = size;
	code = wrap_code;
	for (int i = 0; i < FUN_COUNT; i++) {
		if (!funs[i].args) {
			funwraps[i] = funs[i].fun;
			continue;
		}
		if ((uintptr_t)code & 3)
			code += 4 - ((uintptr_t)code & 3);
		funwraps[i] = code;
		*code++ = 0x55; *code++ = 0x89; *code++ = 0xe5;
		for (int j = 0; j < funs[i].args; j++) {
			*code++ = 0xff;
			*code++ = 0x74;
			*code++ = 0x24;
			*code++ = funs[i].args * 4 + 4;
		}
		unsigned a = (unsigned)funs[i].fun - (unsigned)code - 5;
		*code++ = 0xe8;
		*code++ = a;
		*code++ = a >> 8;
		*code++ = a >> 16;
		*code++ = a >> 24;
		*code++ = 0x83;
		*code++ = 0xc4;
		*code++ = funs[i].args * 4;
		*code++ = 0x5d;
		*code++ = 0xc2;
		*code++ = funs[i].args * 4;
		*code++ = 0;
	}
	return 0;
}

void *readfile(const char *filename, unsigned *psize) {
	FILE *f;
	void *ptr = NULL;
	IMAGE_DOS_HEADER dos;
	IMAGE_NT_HEADERS nt;
	
	if (!(f = fopen(filename, "rb"))) {
		perror(filename);
		return NULL;
	}
	
	fseek(f, 0, SEEK_END);
	int size = ftell(f);
	fseek(f, 0, SEEK_SET);

	if (fread(&dos, 1, sizeof(dos), f) != sizeof(dos))
		goto read_err;
	if (dos.e_magic != 0x5a4d)
		goto read_err;
	fseek(f, dos.e_lfanew, SEEK_SET);
	if (fread(&nt, 1, sizeof(nt), f) != sizeof(nt))
		goto read_err;
	if (nt.Signature != 0x4550)
		goto read_err;
	if ((unsigned)size > nt.OptionalHeader.SizeOfImage)
		size = nt.OptionalHeader.SizeOfImage;
	//if (!(ptr = memalign(0x1000, nt.OptionalHeader.SizeOfImage))) {
	if (!(ptr = mmap((void *)0x400000, nt.OptionalHeader.SizeOfImage, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0))) {
		perror("memalign");
		return NULL;
	}
	if (psize)
		*psize = nt.OptionalHeader.SizeOfImage;
	fseek(f, 0, SEEK_SET);	
	if (fread(ptr, 1, size, f) != size)
		goto read_err;
	fclose(f);
	return ptr;
read_err:
	perror(filename);
	fclose(f);
	if (ptr)
		free(ptr);
	return NULL;
}

void image_setup_sections(IMAGE_NT_HEADERS *ntHdr, void *pFile, void *pBase) {
	PIMAGE_SECTION_HEADER firstSect = (IMAGE_SECTION_HEADER *)((char *)ntHdr + sizeof(IMAGE_NT_HEADERS));
	for (int sectIdx = ntHdr->FileHeader.NumberOfSections - 1; sectIdx >= 0; sectIdx--) {
		PIMAGE_SECTION_HEADER sect = firstSect + sectIdx;
		#ifdef LOG
		printf("sect %x fileptr %x memptr %x filesize %x memsize %x\n",
			sectIdx, sect->PointerToRawData, sect->VirtualAddress,
			sect->SizeOfRawData, sect->Misc.VirtualSize);
		#endif
		if (sect->VirtualAddress != sect->PointerToRawData)
			memmove((char *)pBase + sect->VirtualAddress,
				(char *)pFile + sect->PointerToRawData, sect->SizeOfRawData);
		if (sect->Misc.VirtualSize > sect->SizeOfRawData)
			memset((char *)pBase + sect->VirtualAddress + sect->SizeOfRawData, 0,
				sect->Misc.VirtualSize - sect->SizeOfRawData);
	}
}

void image_reloc(IMAGE_NT_HEADERS *ntHdr, void *pBase) {
	IMAGE_DATA_DIRECTORY *reloc_dir = &ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	IMAGE_BASE_RELOCATION *reloc = (IMAGE_BASE_RELOCATION *)((char *)pBase + reloc_dir->VirtualAddress);
	IMAGE_BASE_RELOCATION *reloc_end = (IMAGE_BASE_RELOCATION *)((char *)pBase + reloc_dir->VirtualAddress + reloc_dir->Size);
	
	DWORD delta = (DWORD)pBase - ntHdr->OptionalHeader.ImageBase;
	while (reloc < reloc_end) {
		DWORD va = reloc->VirtualAddress, size = reloc->SizeOfBlock;
		if (!size)
			abort();
		WORD *p = (WORD *)(reloc + 1), *pe = (WORD *)((char *)reloc + size);
		while (p < pe) {
			WORD val = *p++;
			void *dest = (void *)((char *)pBase + va + (val & 0xfff));
			val >>= 12;
			if (val == IMAGE_REL_BASED_HIGHLOW)
				*(DWORD *)dest += delta;
			else if (val == IMAGE_REL_BASED_LOW)
				*(WORD *)dest += delta & 0xffff;
			else if (val == IMAGE_REL_BASED_HIGH)
				*(WORD *)dest += delta >> 16;
		}
		reloc = (IMAGE_BASE_RELOCATION *)pe;
	}
}

uintptr_t find_fun(const char *name) {
	for (unsigned i = 0; i < FUN_COUNT; i++)
		if (strcmp(name, funs[i].name) == 0)
			return (uintptr_t)funwraps[i];
	printf("not found %s\n", name);
	return 0;
}

void image_import(IMAGE_NT_HEADERS *ntHdr, void *pBase) {
	IMAGE_DATA_DIRECTORY *dir = &ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	IMAGE_IMPORT_DESCRIPTOR *imp = (IMAGE_IMPORT_DESCRIPTOR *)((char *)pBase + dir->VirtualAddress);
	for (; imp->Name; imp++) {
		const char *libName = (const char *)pBase + imp->Name;
		//printf("import %s\n", libName);
		#if 0
		HMODULE lib = LoadLibrary(libName);
		if (!lib) {
			error(libName);
			return 0;
		}
		#endif
		PIMAGE_THUNK_DATA src, dst;
		dst = (IMAGE_THUNK_DATA *)((char *)pBase + imp->FirstThunk);
		if (imp->OriginalFirstThunk)
			src = (IMAGE_THUNK_DATA *)((char *)pBase + imp->OriginalFirstThunk);
		else
			src = dst;
		for (; src->u1.AddressOfData; src++, dst++) {
			const char *name;
			if (IMAGE_SNAP_BY_ORDINAL(src->u1.Ordinal)) {
				name = (char *)IMAGE_ORDINAL(src->u1.Ordinal);
				if (strcmp(libName,"WSOCK32.dll") == 0 && (src->u1.Ordinal & 0xffff) < ELMS(wsockord))
					dst->u1.Function = find_fun(wsockord[src->u1.Ordinal & 0xffff]);
				else
					printf("missing ordinal %s %x\n", libName, src->u1.Ordinal);
			} else {
				PIMAGE_IMPORT_BY_NAME pImport = (IMAGE_IMPORT_BY_NAME *)((char *)pBase + src->u1.AddressOfData);
				name = (char *)pImport->Name;
				//printf("import function %s\n", name);
				//dst->u1.Function = 0; //NULL; //(DWORD)GetProcAddress(lib, name);
				dst->u1.Function = find_fun(name);
			}
			if (!dst->u1.Function) {
				printf("\t{\"%s\", my%s, 0},\n", name, name);
				//error(name);
				//return 0;
			}
		}
	}
}

struct mod {
	void *mem;
	unsigned memsize;
	unsigned entry;
	IMAGE_EXPORT_DIRECTORY *exports;	
	int refcount;
	struct mod *next;
	char *filename;
	int is_dll;
};
struct mod *mod_list;

unsigned mod_get_entry(struct mod *mod) {
	return mod->entry;
}

void mod_done() {
	if (!wrap_code)
		return;
	munmap(wrap_code, wrap_code_size);
	wrap_code = NULL;
	wrap_code_size = 0;
}

#include <sys/syscall.h>
#include <asm/ldt.h>
int ldt_modify(int n, void *base, int len) {
	struct user_desc ldt_entry;
	memset(&ldt_entry, 0, sizeof(ldt_entry));
	ldt_entry.entry_number = n;
	ldt_entry.base_addr = (unsigned long)base;
	ldt_entry.limit = len;
	ldt_entry.seg_32bit = 0x1;
	ldt_entry.contents = 0x0;
	ldt_entry.read_exec_only = 0x0;
	ldt_entry.limit_in_pages = 0x0;
	ldt_entry.seg_not_present = 0x0;
	ldt_entry.useable = 0x1;
	if (syscall( __NR_modify_ldt, 1, &ldt_entry, sizeof(ldt_entry)) == -1)
		return -1;
	return 0;
}

void mod_init() {
	ldt_modify(1, &tls_vals, sizeof(tls_vals));
	asm("mov %0,%%fs" : : "r" (8 | 7));
	create_wrappers();
	InitKeyMap();
	atexit(mod_done);
}

unsigned modfun_call(unsigned fun, int argc, ...) {
	va_list vp;
	va_start(vp, argc);
	#if 0
	R_ESP -= argc * 4;
	for (int i = 0; i < argc; i++)
		*(unsigned *)(R_ESP + i * 4) = va_arg(vp, unsigned);
	unsigned ret = emucall(emu, fun);
	#endif
	va_end(vp);
	return 0;
}

struct mod *mod_load(const char *filename, int is_dll) {
	void *pFile, *pBase;
	struct mod *mod;

	for (mod = mod_list; mod; mod = mod->next)
		if (stricmp(mod->filename, filename) == 0) {
			mod->refcount++;
			return mod;
		}
	
	if (!(mod = (struct mod *)malloc(sizeof(*mod))))
		return 0;
	mod->filename = strdup(filename);
	mod->is_dll = is_dll;
	mod->refcount = 1;
	mod->next = mod_list;
	mod_list = mod;

	if (!(pFile = readfile(filename, &mod->memsize))) {
		mod_free(mod);
		return 0;
	}

	IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER *)pFile;
	IMAGE_NT_HEADERS *ntHdr = (IMAGE_NT_HEADERS *)((char *)pFile + pDosHeader->e_lfanew);

	pBase = pFile;
	image_setup_sections(ntHdr, pFile, pBase);
	image_reloc(ntHdr, pBase);
	image_import(ntHdr, pBase);
	
	mod->mem = pBase;
	mod->entry = (unsigned)pBase + ntHdr->OptionalHeader.AddressOfEntryPoint;

	IMAGE_DATA_DIRECTORY *export_data = &ntHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (export_data->Size) {
		IMAGE_EXPORT_DIRECTORY *export_dir = (IMAGE_EXPORT_DIRECTORY *)((char *)pBase + export_data->VirtualAddress);
		mod->exports = export_dir;
		for (ULONG i = 0; i < export_dir->NumberOfNames; i++) {
			unsigned f = ((uint16_t *)((char *)pBase + export_dir->AddressOfNameOrdinals))[i];
			unsigned addr = ((unsigned *)((char *)pBase + export_dir->AddressOfFunctions))[f];
			printf("%s %d %x %x\n", (char *)pBase + ((unsigned *)((char *)pBase + export_dir->AddressOfNames))[i], f, addr, (unsigned)pBase + addr);
		}
	}

	//void (*entry)() = (void *)mod->entry;
	//entry();

	if (is_dll)
		if (!call_std3((void *)mod->entry, (unsigned)mod->mem, DLL_PROCESS_ATTACH, 0)) {
			mod_free(mod);
			return NULL;
		}

	return mod;
}

void mod_free(struct mod *mod) {
	if (!mod)
		return;
	if (--mod->refcount)
		return;
	for (struct mod **cur = &mod_list; *cur; *cur = (*cur)->next)
		if (*cur == mod) {
			*cur = mod->next;
			break;
		}
	if (mod->is_dll && mod->entry)
		call_std3((void *)mod->entry, (unsigned)mod->mem, DLL_PROCESS_DETACH, 0);
	if (mod->mem)
		munmap(mod->mem, mod->memsize);
	free(mod->filename);
	free(mod);
}

unsigned mod_find(struct mod *mod, const char *name) {
	IMAGE_EXPORT_DIRECTORY *export_dir = mod->exports;
	char *base = (char *)mod->mem;
	unsigned *names = (unsigned *)(base + export_dir->AddressOfNames);
	for (ULONG i = 0; i < export_dir->NumberOfNames; i++) {
		if (strcmp(base + names[i], name) == 0) {
			unsigned f = ((uint16_t *)(base + export_dir->AddressOfNameOrdinals))[i];
			unsigned addr = ((unsigned *)(base + export_dir->AddressOfFunctions))[f];
			return (unsigned)base + addr;
		}
	}
	return 0;
}
