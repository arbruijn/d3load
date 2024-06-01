#define _GNU_SOURCE
#include <fcntl.h>
#include <errno.h>
#include <fnmatch.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

extern int last_error;
SDL_Window *window;
uint64_t cur_time;
void *keyb_hook;
int verbose;

#define HFILE_OFS 0x2dab0000
#define HFILE_MASK 0xffff
#define HKEY_OFS 0x1cad0000
static const char *reg_keys[] = {
	"Software\\Microsoft\\DirectX",
	"SOFTWARE\\Outrage\\Descent3",
	"SOFTWARE\\Outrage\\Descent3\\Version",
	"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Descent3 Mercenary",
	 };
static struct { HKEY key; const char *name, *value; int type; } reg_values[] = {
	{ (HKEY)HKEY_OFS, "Version", "4.3.0", REG_SZ },
	{ (HKEY)(HKEY_OFS + 1), "PreferredRenderer", "\2\0\0\0", REG_DWORD },
	{ (HKEY)(HKEY_OFS + 1), "ForceFeedbackGain", "\0\0\0\0", REG_DWORD }, // prevent uninit
	{ (HKEY)(HKEY_OFS + 1), "DetailObjectComp", "\0\0\0\0", REG_DWORD }, // prevent uninit
	{ (HKEY)(HKEY_OFS + 3), "UninstallString", "x", REG_SZ },
};
#define HKEY_MASK 0xffff
#define ELMS(x) (sizeof(x)/sizeof(x)[0])

extern uint32_t call_std3(void *fun, uint32_t p1, uint32_t p2, uint32_t p3);
asm(
".text\n"
"call_std3:\n"
" push 16(%esp)\n"
" push 16(%esp)\n"
" push 16(%esp)\n"
" call *16(%esp)\n"
" ret"
);

void convpath(char *dst, const char *src) {
	if (src[0] == 'h' && src[1] == ':') {
		strcpy(dst, "../../pkg/descent3");
		strcat(dst, src + 2);
	} else
		strcpy(dst, src);
	for (char *p = dst; *p; p++)
		if (*p == '\\')
			*p = '/';
}

#include "sdlkeymap.h"
void EventLoop() {
	SDL_Event evt;
	while (SDL_PollEvent(&evt) > 0) {
		switch (evt.type) {
			case SDL_KEYDOWN:
			case SDL_KEYUP: {
				int scanflags = (sdlkeymap[evt.key.keysym.scancode] << 16) |
					(evt.type == SDL_KEYUP ? 0x80000000 : 0);
				if (keyb_hook)
					call_std3(keyb_hook, 0, evt.key.keysym.sym, scanflags);
				break;
			}
		}
    }
}

BOOL mySetupComm(HANDLE hFile, uint32_t dwInQueue, uint32_t dwOutQueue) {
	if (verbose) printf("SetupComm %p %x %x\n", hFile, dwInQueue, dwOutQueue);
	return 0;
}
BOOL myEscapeCommFunction(HANDLE hFile, ESCAPE_COMM_FUNCTION dwFunc) {
	if (verbose) printf("EscapeCommFunction %p %x\n", hFile, dwFunc);
	return 0;
}
BOOL myGetCommState(HANDLE hFile, DCB* lpDCB) {
	if (verbose) printf("GetCommState %p %p\n", hFile, lpDCB);
	return 0;
}
BOOL myPurgeComm(HANDLE hFile, PURGE_COMM_FLAGS dwFlags) {
	if (verbose) printf("PurgeComm %p %x\n", hFile, dwFlags);
	return 0;
}
BOOL mySetCommMask(HANDLE hFile, COMM_EVENT_MASK dwEvtMask) {
	if (verbose) printf("SetCommMask %p %x\n", hFile, dwEvtMask);
	return 0;
}
BOOL mySetCommState(HANDLE hFile, DCB* lpDCB) {
	if (verbose) printf("SetCommState %p %p\n", hFile, lpDCB);
	return 0;
}
BOOL mySetCommTimeouts(HANDLE hFile, COMMTIMEOUTS* lpCommTimeouts) {
	if (verbose) printf("SetCommTimeouts %p %p\n", hFile, lpCommTimeouts);
	return 0;
}
int32_t myCompareStringW(uint32_t Locale, uint32_t dwCmpFlags, WCHAR* lpString1, int32_t cchCount1, WCHAR* lpString2, int32_t cchCount2) {
	if (verbose) printf("CompareStringW %x %x %p %x %p %x\n", Locale, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2);
	return 0;
}
int32_t myCompareStringA(uint32_t Locale, uint32_t dwCmpFlags, char* lpString1, int32_t cchCount1, char* lpString2, int32_t cchCount2) {
	if (verbose) printf("CompareStringA %x %x %p %x %p %x\n", Locale, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2);
	return 0;
}
PSTR mylstrcpyA(PSTR lpString1, PSTR lpString2) {
	//if (verbose) printf("lstrcpyA %p %p\n", lpString1, lpString2);
	return strcpy(lpString1, lpString2);
}
PSTR mylstrcatA(PSTR lpString1, PSTR lpString2) {
	//if (verbose) printf("lstrcatA %p %p\n", lpString1, lpString2);
	return strcat(lpString1, lpString2);
}
int32_t mylstrlenA(PSTR lpString) {
	//if (verbose) printf("lstrlenA %p\n", lpString);
	return strlen(lpString);
}
HRESULT myDirectDrawEnumerateA(LPDDENUMCALLBACKA lpCallback, void* lpContext) {
	if (verbose) printf("DirectDrawEnumerateA %x %p\n", lpCallback, lpContext);
	return 0;
}
HRESULT myDirectDrawCreate(Guid* lpGUID, IDirectDraw* lplpDD, IUnknown* pUnkOuter) {
	if (verbose) printf("DirectDrawCreate %p %p %p\n", lpGUID, lplpDD, pUnkOuter);
	return 0;
}
BOOL myBitBlt(HDC hdc, int32_t x, int32_t y, int32_t cx, int32_t cy, HDC hdcSrc, int32_t x1, int32_t y1, ROP_CODE rop) {
	if (verbose) printf("BitBlt %p %x %x %x %x %p %x %x %x\n", hdc, x, y, cx, cy, hdcSrc, x1, y1, rop);
	return 0;
}
CreatedHDC myCreateCompatibleDC(HDC hdc) {
	if (verbose) printf("CreateCompatibleDC %p\n", hdc);
	return 0;
}
BOOL myDeleteDC(CreatedHDC hdc) {
	if (verbose) printf("DeleteDC %x\n", hdc);
	return 0;
}
BOOL myDeleteObject(HGDIOBJ ho) {
	if (verbose) printf("DeleteObject %p\n", ho);
	return 0;
}
int32_t myGetDeviceCaps(HDC hdc, GET_DEVICE_CAPS_INDEX index) {
	if (verbose) printf("GetDeviceCaps %p %x\n", hdc, index);
	return 0;
}
HGDIOBJ myGetStockObject(GET_STOCK_OBJECT_FLAGS i) {
	if (verbose) printf("GetStockObject %x\n", i);
	return 0;
}
HGDIOBJ mySelectObject(HDC hdc, HGDIOBJ h) {
	if (verbose) printf("SelectObject %p %p\n", hdc, h);
	return 0;
}
BOOL myGetTextMetricsA(HDC hdc, TEXTMETRICA* lptm) {
	if (verbose) printf("GetTextMetricsA %p %p\n", hdc, lptm);
	return 0;
}
HBITMAP myCreateDIBSection(HDC hdc, BITMAPINFO* pbmi, DIB_USAGE usage, void** ppvBits, HANDLE hSection, uint32_t offset) {
	if (verbose) printf("CreateDIBSection %p %p %x %p %p %x\n", hdc, pbmi, usage, ppvBits, hSection, offset);
	return 0;
}
BOOL myTextOutA(HDC hdc, int32_t x, int32_t y, char* lpString, int32_t c) {
	if (verbose) printf("TextOutA %p %x %x %p %x\n", hdc, x, y, lpString, c);
	return 0;
}
BOOL myUpdateWindow(HWND hWnd) {
	if (verbose) printf("UpdateWindow %p\n", hWnd);
	return 0;
}
HDC myGetDC(HWND hWnd) {
	if (verbose) printf("GetDC %p\n", hWnd);
	return 0;
}
int32_t myReleaseDC(HWND hWnd, HDC hDC) {
	if (verbose) printf("ReleaseDC %p %p\n", hWnd, hDC);
	return 0;
}
HDC myBeginPaint(HWND hWnd, PAINTSTRUCT* lpPaint) {
	if (verbose) printf("BeginPaint %p %p\n", hWnd, lpPaint);
	return 0;
}
BOOL myEndPaint(HWND hWnd, PAINTSTRUCT* lpPaint) {
	if (verbose) printf("EndPaint %p %p\n", hWnd, lpPaint);
	return 0;
}
BOOL myInvalidateRect(HWND hWnd, RECT* lpRect, BOOL bErase) {
	if (verbose) printf("InvalidateRect %p %p %x\n", hWnd, lpRect, bErase);
	return 0;
}
BOOL mySetRect(RECT* lprc, int32_t xLeft, int32_t yTop, int32_t xRight, int32_t yBottom) {
	if (verbose) printf("SetRect %p %x %x %x %x\n", lprc, xLeft, yTop, xRight, yBottom);
	return 0;
}
DISP_CHANGE myChangeDisplaySettingsA(DEVMODEA* lpDevMode, CDS_TYPE dwFlags) {
	if (verbose) printf("ChangeDisplaySettingsA %p %x\n", lpDevMode, dwFlags);
	return 0;
}
BOOL myEnumDisplaySettingsA(PSTR lpszDeviceName, ENUM_DISPLAY_SETTINGS_MODE iModeNum, DEVMODEA* lpDevMode) {
	if (verbose) printf("EnumDisplaySettingsA %p %x %p\n", lpszDeviceName, iModeNum, lpDevMode);
	return 0;
}
int32_t myChoosePixelFormat(HDC hdc, PIXELFORMATDESCRIPTOR* ppfd) {
	if (verbose) printf("ChoosePixelFormat %p %p\n", hdc, ppfd);
	return 1;
}
int32_t myDescribePixelFormat(HDC hdc, int32_t iPixelFormat, uint32_t nBytes, PIXELFORMATDESCRIPTOR* ppfd) {
	if (verbose) printf("DescribePixelFormat %p %x %x %p\n", hdc, iPixelFormat, nBytes, ppfd);
	memset(ppfd, 0, nBytes);
	return 1;
}
BOOL mySetPixelFormat(HDC hdc, int32_t format, PIXELFORMATDESCRIPTOR* ppfd) {
	if (verbose) printf("SetPixelFormat %p %x %p\n", hdc, format, ppfd);
	return 1;
}
BOOL mySwapBuffers(HDC param0) {
	if (verbose) printf("SwapBuffers %p\n", param0);
	int no_wait = *(char*)0x6e6e55 != 0;
	static int last_no_wait;
	if (last_no_wait != no_wait) { SDL_GL_SetSwapInterval(no_wait ? 0 : 1); last_no_wait = no_wait; } 
	SDL_GL_SwapWindow(window);
	EventLoop();
	cur_time += 16667;
	return 0;
}
uint32_t mytimeGetTime() {
	if (verbose) printf("timeGetTime\n");
	return 0;
}
uint32_t mytimeGetDevCaps(TIMECAPS* ptc, uint32_t cbtc) {
	if (verbose) printf("timeGetDevCaps %p %x\n", ptc, cbtc);
	ptc->wPeriodMin = 1;
	ptc->wPeriodMax = 1;
	return 0;
}
uint32_t mytimeBeginPeriod(uint32_t uPeriod) {
	if (verbose) printf("timeBeginPeriod %x\n", uPeriod);
	return 0;
}
uint32_t mytimeEndPeriod(uint32_t uPeriod) {
	if (verbose) printf("timeEndPeriod %x\n", uPeriod);
	return 0;
}
uint32_t myjoyGetPosEx(uint32_t uJoyID, JOYINFOEX* pji) {
	if (verbose) printf("joyGetPosEx %x %p\n", uJoyID, pji);
	return 0;
}
BOOL myCreateDirectoryA(PSTR lpPathName, void* lpSecurityAttributes) {
	if (verbose) printf("CreateDirectoryA %s %p\n", lpPathName, lpSecurityAttributes);
	return 0;
}
HANDLE myCreateFileA(PSTR lpFileName, FILE_ACCESS_FLAGS dwDesiredAccess, FILE_SHARE_MODE dwShareMode, void* lpSecurityAttributes, FILE_CREATION_DISPOSITION dwCreationDisposition, FILE_FLAGS_AND_ATTRIBUTES dwFlagsAndAttributes, HANDLE hTemplateFile) {
	char path[256];

	convpath(path, lpFileName);
	if (verbose) printf("CreateFileA %s %x %x %p %x %x %p - %s\n", lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile,
		path);

	int flags = 0;
	if (dwCreationDisposition == CREATE_ALWAYS)
		flags |= O_CREAT | O_TRUNC;
	else if (dwCreationDisposition == CREATE_NEW)
		flags |= O_CREAT | O_EXCL;
	else if (dwCreationDisposition == OPEN_ALWAYS)
		flags |= O_CREAT;
	else if (dwCreationDisposition == TRUNCATE_EXISTING)
		flags |= O_TRUNC;
	if (dwDesiredAccess & GENERIC_WRITE)
		flags |= dwDesiredAccess & GENERIC_READ ? O_RDWR : O_WRONLY;
	else
		flags |= O_RDONLY;
	int fd = open(path, flags, 0666);
	if (fd == -1 && errno == ENOENT) {
		char *p = strrchr(path, '/');
		p = p ? p + 1 : path;
		for (; *p; p++)
			if (*p >= 'a' && *p <= 'z')
				*p -= 'a' - 'A';
		fd = open(path, flags, 0666);
	}
	if (fd == -1) {
		last_error = ERROR_FILE_NOT_FOUND;
		return INVALID_HANDLE_VALUE;
	}
	last_error = 0;
	return (HANDLE)(HFILE_OFS + fd);
}
BOOL myDeleteFileA(PSTR lpFileName) {
	if (verbose) printf("DeleteFileA %s\n", lpFileName);
	return 0;
}
BOOL myFileTimeToLocalFileTime(FILETIME* lpFileTime, FILETIME* lpLocalFileTime) {
	if (verbose) printf("FileTimeToLocalFileTime %p %p\n", lpFileTime, lpLocalFileTime);
	return 0;
}
struct finddata {
	DIR *dir;
	char *pattern;
};
#define HANDLE_NO_MORE ((HANDLE)-2)
void stat_to_find(struct stat *st, WIN32_FIND_DATAA *fd) {
	fd->dwFileAttributes = 0x20;
	fd->nFileSizeLow = (DWORD)st->st_size;
	fd->nFileSizeHigh = st->st_size >> 32;
}
BOOL myFindClose(HANDLE hFindFile) {
	if (verbose) printf("FindClose %p\n", hFindFile);
	if (hFindFile == INVALID_HANDLE_VALUE)
		return 0;
	if (hFindFile == HANDLE_NO_MORE)
		return 1;
	struct finddata *fd = (struct finddata *)hFindFile;
	if (!fd->dir || !fd->pattern)
		return 0;
	closedir(fd->dir);
	free(fd->pattern);
	fd->dir = NULL;
	fd->pattern = NULL;
	free(fd);
	return 1;
}
BOOL myFindNextFileA(HANDLE hFindFile, WIN32_FIND_DATAA* lpFindFileData) {
	if (verbose) printf("FindNextFileA %p %p\n", hFindFile, lpFindFileData);
	if (hFindFile == HANDLE_NO_MORE) {
		last_error = ERROR_NO_MORE_FILES;
		return 0;
	}
	if (hFindFile == INVALID_HANDLE_VALUE)
		return 0;
	struct finddata *fd = (struct finddata *)hFindFile;
	struct dirent *de;
	while ((de = readdir(fd->dir))) {
		if (fnmatch(fd->pattern, de->d_name, FNM_PATHNAME | FNM_CASEFOLD) == 0) {
			//struct stat *st;
			memset(lpFindFileData, 0, sizeof(*lpFindFileData));
			strcpy(lpFindFileData->cFileName, de->d_name);
			return 1;
		}
	}
	last_error = ERROR_NO_MORE_FILES;
	return 0;
}
HANDLE myFindFirstFileA(PSTR lpFileName, WIN32_FIND_DATAA* lpFindFileData) {
	char path[256], *p;
	struct finddata *fd;
	DIR *dir;

	convpath(path, lpFileName);
	if (verbose) printf("FindFirstFileA %p %p\n", lpFileName, lpFindFileData);
	if ((p = strrchr(path, '/')))
		p++;
	else
		p = path;
	if (!strchr(p, '?') && !strchr(p, '*')) {
		struct stat st;
		if (stat(path, &st)) {
			last_error = ERROR_FILE_NOT_FOUND;
			return INVALID_HANDLE_VALUE;
		}
		return HANDLE_NO_MORE;
	}
	if (p > path)
		p[-1] = 0;
	if (!(dir = opendir(p == path ? "." : path))) {
		last_error = ERROR_FILE_NOT_FOUND;
		return INVALID_HANDLE_VALUE;
	}
	if (!(fd = malloc(sizeof(*fd)))) {
		closedir(dir);
		return INVALID_HANDLE_VALUE;
	}
	fd->dir = dir;
	fd->pattern = strdup(p);
	myFindNextFileA((HANDLE)fd, lpFindFileData);
	return (HANDLE)fd;
}
BOOL myGetDiskFreeSpaceA(PSTR lpRootPathName, uint32_t* lpSectorsPerCluster, uint32_t* lpBytesPerSector, uint32_t* lpNumberOfFreeClusters, uint32_t* lpTotalNumberOfClusters) {
	if (verbose) printf("GetDiskFreeSpaceA %p %p %p %p %p\n", lpRootPathName, lpSectorsPerCluster, lpBytesPerSector, lpNumberOfFreeClusters, lpTotalNumberOfClusters);
	return 0;
}
uint32_t myGetDriveTypeA(PSTR lpRootPathName) {
	if (verbose) printf("GetDriveTypeA %p\n", lpRootPathName);
	return 0;
}
uint32_t myGetFileAttributesA(PSTR lpFileName) {
	if (verbose) printf("GetFileAttributesA %p\n", lpFileName);
	return 0;
}
uint32_t myGetFileSize(HANDLE hFile, uint32_t* lpFileSizeHigh) {
	if (verbose) printf("GetFileSize %p %p\n", hFile, lpFileSizeHigh);
	if (((uint32_t)hFile & ~HFILE_MASK) != HFILE_OFS) {
		last_error = ERROR_INVALID_HANDLE;
		return INVALID_FILE_SIZE;
	}
	int fd = (uint32_t)hFile & HFILE_MASK;
	off_t prev, size;
	if ((prev = lseek(fd, 0, SEEK_CUR)) == (off_t)-1 ||
		(size = lseek(fd, 0, SEEK_END)) == (off_t)-1 ||
		lseek(fd, prev, SEEK_SET) == (off_t)-1) {
		last_error = ERROR_SEEK_ON_DEVICE;
		return INVALID_FILE_SIZE;
	}
	if (lpFileSizeHigh)
		*lpFileSizeHigh = (uint32_t)(size >> 32);
	last_error = 0;
	return (uint32_t)size;
}
BOOL myGetFileTime(HANDLE hFile, FILETIME* lpCreationTime, FILETIME* lpLastAccessTime, FILETIME* lpLastWriteTime) {
	if (verbose) printf("GetFileTime %p %p %p %p\n", hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime);
	return 0;
}
uint32_t myGetFullPathNameA(PSTR lpFileName, uint32_t nBufferLength, char* lpBuffer, PSTR* lpFilePart) {
	if (verbose) printf("GetFullPathNameA %p %x %p %p\n", lpFileName, nBufferLength, lpBuffer, lpFilePart);
	return 0;
}
BOOL myReadFile(HANDLE hFile, void* lpBuffer, uint32_t nNumberOfBytesToRead, uint32_t* lpNumberOfBytesRead, OVERLAPPED* lpOverlapped) {
	//if (verbose) printf("ReadFile %p %p %x %p %p\n", hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
	if (((uint32_t)hFile & ~HFILE_MASK) != HFILE_OFS)
		return 0;
	int ret = read((uint32_t)hFile & HFILE_MASK, lpBuffer, nNumberOfBytesToRead);
	if (ret == -1)
		return 0;
	if (lpNumberOfBytesRead)
		*lpNumberOfBytesRead = ret;
	return 1;
}
BOOL mySetEndOfFile(HANDLE hFile) {
	if (verbose) printf("SetEndOfFile %p\n", hFile);
	return 0;
}
BOOL mySetFileAttributesA(PSTR lpFileName, FILE_FLAGS_AND_ATTRIBUTES dwFileAttributes) {
	if (verbose) printf("SetFileAttributesA %p %x\n", lpFileName, dwFileAttributes);
	return 0;
}
BOOL mySetFileTime(HANDLE hFile, FILETIME* lpCreationTime, FILETIME* lpLastAccessTime, FILETIME* lpLastWriteTime) {
	if (verbose) printf("SetFileTime %p %p %p %p\n", hFile, lpCreationTime, lpLastAccessTime, lpLastWriteTime);
	return 0;
}
BOOL myGetVolumeInformationA(PSTR lpRootPathName, char* lpVolumeNameBuffer, uint32_t nVolumeNameSize, uint32_t* lpVolumeSerialNumber, uint32_t* lpMaximumComponentLength, uint32_t* lpFileSystemFlags, char* lpFileSystemNameBuffer, uint32_t nFileSystemNameSize) {
	if (verbose) printf("GetVolumeInformationA %p %p %x %p %p %p %p %x\n", lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize);
	return 0;
}
uint32_t myGetTempFileNameA(PSTR lpPathName, PSTR lpPrefixString, uint32_t uUnique, char* lpTempFileName) {
	static int count = 0;
	if (verbose) printf("GetTempFileNameA %s %s %x %p\n", lpPathName, lpPrefixString, uUnique, lpTempFileName);
	++count;
	sprintf(lpTempFileName, "%s\\%s%04d.tmp", lpPathName, lpPrefixString, count);
	return count;
}
uint32_t myGetShortPathNameA(PSTR lpszLongPath, char* lpszShortPath, uint32_t cchBuffer) {
	if (verbose) printf("GetShortPathNameA %p %p %x\n", lpszLongPath, lpszShortPath, cchBuffer);
	return 0;
}
uint32_t myGetLogicalDriveStringsA(uint32_t nBufferLength, char* lpBuffer) {
	if (verbose) printf("GetLogicalDriveStringsA %x %p\n", nBufferLength, lpBuffer);
	return 0;
}
HRESULT myCoInitialize(void* pvReserved) {
	if (verbose) printf("CoInitialize %p\n", pvReserved);
	return 0;
}
void myCoUninitialize() {
	if (verbose) printf("CoUninitialize\n");
	return;
}
HRESULT myCoCreateInstance(Guid* rclsid, IUnknown* pUnkOuter, CLSCTX dwClsContext, Guid* riid, void** ppv) {
	if (verbose) printf("CoCreateInstance %p %p %x %p %p\n", rclsid, pUnkOuter, dwClsContext, riid, ppv);
	return 0;
}
BOOL myOpenClipboard(HWND hWndNewOwner) {
	if (verbose) printf("OpenClipboard %p\n", hWndNewOwner);
	return 0;
}
BOOL myCloseClipboard() {
	if (verbose) printf("CloseClipboard\n");
	return 0;
}
HANDLE mySetClipboardData(uint32_t uFormat, HANDLE hMem) {
	if (verbose) printf("SetClipboardData %x %p\n", uFormat, hMem);
	return 0;
}
BOOL myEmptyClipboard() {
	if (verbose) printf("EmptyClipboard\n");
	return 0;
}
int32_t myUnhandledExceptionFilter(void* ExceptionInfo) {
	if (verbose) printf("UnhandledExceptionFilter %p\n", ExceptionInfo);
	return 0;
}
LPTOP_LEVEL_EXCEPTION_FILTER mySetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter) {
	if (verbose) printf("SetUnhandledExceptionFilter %x\n", lpTopLevelExceptionFilter);
	return 0;
}
BOOL mySetEnvironmentVariableA(PSTR lpName, PSTR lpValue) {
	if (verbose) printf("SetEnvironmentVariableA %p %p\n", lpName, lpValue);
	return 0;
}
BOOL myFreeLibrary(HINSTANCE hLibModule) {
	if (verbose) printf("FreeLibrary %p\n", hLibModule);
	return 0;
}
uintptr_t myHeapSize(HeapHandle hHeap, HEAP_FLAGS dwFlags, void* lpMem) {
	if (verbose) printf("HeapSize %x %x %p\n", hHeap, dwFlags, lpMem);
	return 0;
}
uintptr_t myHeapCompact(HeapHandle hHeap, HEAP_FLAGS dwFlags) {
	if (verbose) printf("HeapCompact %x %x\n", hHeap, dwFlags);
	return 0;
}
BOOL myVirtualProtect(void* lpAddress, uintptr_t dwSize, PAGE_PROTECTION_FLAGS flNewProtect, void* lpflOldProtect) {
	if (verbose) printf("VirtualProtect %p %x %x %p\n", lpAddress, dwSize, flNewProtect, lpflOldProtect);
	return 0;
}
uintptr_t myVirtualQuery(void* lpAddress, void* lpBuffer, uintptr_t dwLength) {
	if (verbose) printf("VirtualQuery %p %p %x\n", lpAddress, lpBuffer, dwLength);
	return 0;
}
void* myMapViewOfFile(HANDLE hFileMappingObject, FILE_MAP dwDesiredAccess, uint32_t dwFileOffsetHigh, uint32_t dwFileOffsetLow, uintptr_t dwNumberOfBytesToMap) {
	if (verbose) printf("MapViewOfFile %p %x %x %x %x\n", hFileMappingObject, dwDesiredAccess, dwFileOffsetHigh, dwFileOffsetLow, dwNumberOfBytesToMap);
	return 0;
}
BOOL myUnmapViewOfFile(void* lpBaseAddress) {
	if (verbose) printf("UnmapViewOfFile %p\n", lpBaseAddress);
	return 0;
}
intptr_t myGlobalAlloc(GLOBAL_ALLOC_FLAGS uFlags, uintptr_t dwBytes) {
	if (verbose) printf("GlobalAlloc %x %x\n", uFlags, dwBytes);
	return 0;
}
BOOL myGlobalUnlock(intptr_t hMem) {
	if (verbose) printf("GlobalUnlock %x\n", hMem);
	return 0;
}
void* myGlobalLock(intptr_t hMem) {
	if (verbose) printf("GlobalLock %x\n", hMem);
	return 0;
}
intptr_t myGlobalFree(intptr_t hMem) {
	if (verbose) printf("GlobalFree %x\n", hMem);
	return 0;
}
HANDLE myCreateFileMappingA(HANDLE hFile, void* lpFileMappingAttributes, PAGE_PROTECTION_FLAGS flProtect, uint32_t dwMaximumSizeHigh, uint32_t dwMaximumSizeLow, PSTR lpName) {
	if (verbose) printf("CreateFileMappingA %p %p %x %x %x %p\n", hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
	return 0;
}
BOOL myIsBadCodePtr(FARPROC lpfn) {
	if (verbose) printf("IsBadCodePtr %p\n", lpfn);
	return 0;
}
BOOL myQueryPerformanceCounter(void* lpPerformanceCount) {
	if (verbose) printf("QueryPerformanceCounter %p\n", lpPerformanceCount);
	return 0;
}
BOOL myQueryPerformanceFrequency(void* lpFrequency) {
	if (verbose) printf("QueryPerformanceFrequency %p\n", lpFrequency);
	return 0;
}
LSTATUS myRegCloseKey(HKEY hKey) {
	if (verbose) printf("RegCloseKey %p\n", hKey);
	return 0;
}
LSTATUS myRegCreateKeyExA(HKEY hKey, PSTR lpSubKey, uint32_t Reserved, PSTR lpClass, REG_OPEN_CREATE_OPTIONS dwOptions, REG_SAM_FLAGS samDesired, void* lpSecurityAttributes, HKEY* phkResult, void* lpdwDisposition) {
	if (verbose) printf("RegCreateKeyExA %p %s %x %p %x %x %p %p %p\n", hKey, lpSubKey, Reserved, lpClass, dwOptions, samDesired, lpSecurityAttributes, phkResult, lpdwDisposition);
	return 0;
}
LSTATUS myRegOpenKeyA(HKEY hKey, PSTR lpSubKey, HKEY* phkResult) {
	if (verbose) printf("RegOpenKeyA %p %s %p\n", hKey, lpSubKey, phkResult);
	return ERROR_FILE_NOT_FOUND;
}
LSTATUS myRegOpenKeyExA(HKEY hKey, PSTR lpSubKey, uint32_t ulOptions, REG_SAM_FLAGS samDesired, HKEY* phkResult) {
	char buf[256];
	if (verbose) printf("RegOpenKeyExA %p %s %x %x %p\n", hKey, lpSubKey, ulOptions, samDesired, phkResult);
	if (((uint32_t)hKey & ~HKEY_MASK) == HKEY_OFS && ((uint32_t)hKey & HKEY_MASK) < ELMS(reg_keys)) {
		strcpy(buf, reg_keys[(uint32_t)hKey & HKEY_MASK]);
		strcat(buf, "\\");
		strcat(buf, lpSubKey);
		lpSubKey = buf;
	}
	for (int i = 0; i < ELMS(reg_keys); i++)
		if (strcmp(reg_keys[i], lpSubKey) == 0) {
			*phkResult = (HKEY)(HKEY_OFS + i);
			return 0;
		}
	return ERROR_FILE_NOT_FOUND;
}
LSTATUS myRegQueryValueExA(HKEY hKey, PSTR lpValueName, uint32_t* lpReserved, uint32_t* lpType, char* lpData, uint32_t* lpcbData) {
	if (verbose) printf("RegQueryValueExA %p %s %p %p %p %p\n", hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
	for (int i = 0; i < ELMS(reg_values); i++)
		if (reg_values[i].key == hKey && strcmp(reg_values[i].name, lpValueName) == 0) {
			int l = reg_values[i].type == REG_SZ ? strlen(reg_values[i].value) + 1 : 4;
			if (!lpcbData || !lpData)
				return 0;
			if (l <= *lpcbData) {
				*lpcbData = l;
				if (lpType)
					*lpType = reg_values[i].type;
				memcpy(lpData, reg_values[i].value, l);
				return 0;
			} else {
				*lpcbData = l;
				return ERROR_MORE_DATA;
			}
		}
	return ERROR_FILE_NOT_FOUND;
}
LSTATUS myRegSetValueExA(HKEY hKey, PSTR lpValueName, uint32_t Reserved, REG_VALUE_TYPE dwType, char* lpData, uint32_t cbData) {
	if (verbose) printf("RegSetValueExA %p %s %x %x %p %x\n", hKey, lpValueName, Reserved, dwType, lpData, cbData);
	return 0;
}
void myGetSystemInfo(void* lpSystemInfo) {
	if (verbose) printf("GetSystemInfo %p\n", lpSystemInfo);
	return;
}
void myGetSystemTime(SYSTEMTIME* lpSystemTime) {
	if (verbose) printf("GetSystemTime %p\n", lpSystemTime);
	memset(lpSystemTime, 0, sizeof(*lpSystemTime));
	lpSystemTime->wYear = 1980;
	lpSystemTime->wMonth = lpSystemTime->wDay = 1;
	return;
}
void myGetSystemTimeAsFileTime(FILETIME* lpSystemTimeAsFileTime) {
	if (verbose) printf("GetSystemTimeAsFileTime %p\n", lpSystemTimeAsFileTime);
	return;
}
void myGetLocalTime(SYSTEMTIME* lpSystemTime) {
	if (verbose) printf("GetLocalTime %p\n", lpSystemTime);
	memset(lpSystemTime, 0, sizeof(*lpSystemTime));
	lpSystemTime->wYear = 1980;
	lpSystemTime->wMonth = lpSystemTime->wDay = 1;
	return;
}
uint32_t myGetTickCount() {
	if (verbose) printf("GetTickCount\n");
	return cur_time / 1000;
}
void myGlobalMemoryStatus(MEMORYSTATUS* lpBuffer) {
	if (verbose) printf("GlobalMemoryStatus %p\n", lpBuffer);
	memset(lpBuffer, 0, sizeof(*lpBuffer));
	lpBuffer->dwAvailPhys = lpBuffer->dwTotalPhys = 1 << 30;
}
BOOL mySetEvent(HANDLE hEvent) {
	if (verbose) printf("SetEvent %p\n", hEvent);
	return 0;
}
BOOL myResetEvent(HANDLE hEvent) {
	if (verbose) printf("ResetEvent %p\n", hEvent);
	return 0;
}
uint32_t myWaitForSingleObject(HANDLE hHandle, uint32_t dwMilliseconds) {
	if (verbose) printf("WaitForSingleObject %p %x\n", hHandle, dwMilliseconds);
	return 0;
}
HANDLE myCreateMutexA(void* lpMutexAttributes, BOOL bInitialOwner, PSTR lpName) {
	if (verbose) printf("CreateMutexA %p %x %p\n", lpMutexAttributes, bInitialOwner, lpName);
	return (HANDLE)0x12340002;
}
HANDLE myCreateEventA(void* lpEventAttributes, BOOL bManualReset, BOOL bInitialState, PSTR lpName) {
	if (verbose) printf("CreateEventA %p %x %x %p\n", lpEventAttributes, bManualReset, bInitialState, lpName);
	return 0;
}
void mySleep(uint32_t dwMilliseconds) {
	if (verbose) printf("Sleep %x\n", dwMilliseconds);
	return;
}
uint32_t myGetCurrentProcessId() {
	if (verbose) printf("GetCurrentProcessId\n");
	return 0;
}
HANDLE myCreateThread(void* lpThreadAttributes, uintptr_t dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, void* lpParameter, THREAD_CREATION_FLAGS dwCreationFlags, uint32_t* lpThreadId) {
	if (verbose) printf("CreateThread %p %x %x %p %x %p\n", lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter, dwCreationFlags, lpThreadId);
	return 0;
}
BOOL mySetThreadPriority(HANDLE hThread, THREAD_PRIORITY nPriority) {
	if (verbose) printf("SetThreadPriority %p %x\n", hThread, nPriority);
	return 0;
}
void myExitThread(uint32_t dwExitCode) {
	if (verbose) printf("ExitThread %x\n", dwExitCode);
	return;
}
uint32_t myResumeThread(HANDLE hThread) {
	if (verbose) printf("ResumeThread %p\n", hThread);
	return 0;
}
BOOL myCreateProcessA(PSTR lpApplicationName, PSTR lpCommandLine, void* lpProcessAttributes, void* lpThreadAttributes, BOOL bInheritHandles, PROCESS_CREATION_FLAGS dwCreationFlags, void* lpEnvironment, PSTR lpCurrentDirectory, STARTUPINFOA* lpStartupInfo, void* lpProcessInformation) {
	if (verbose) printf("CreateProcessA %p %p %p %p %x %x %p %p %p %p\n", lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation);
	return 0;
}
HANDLE myOpenProcess(PROCESS_ACCESS_RIGHTS dwDesiredAccess, BOOL bInheritHandle, uint32_t dwProcessId) {
	if (verbose) printf("OpenProcess %x %x %x\n", dwDesiredAccess, bInheritHandle, dwProcessId);
	return 0;
}
uint32_t myWaitForInputIdle(HANDLE hProcess, uint32_t dwMilliseconds) {
	if (verbose) printf("WaitForInputIdle %p %x\n", hProcess, dwMilliseconds);
	return 0;
}
BOOL mySystemTimeToTzSpecificLocalTime(void* lpTimeZoneInformation, SYSTEMTIME* lpUniversalTime, SYSTEMTIME* lpLocalTime) {
	if (verbose) printf("SystemTimeToTzSpecificLocalTime %p %p %p\n", lpTimeZoneInformation, lpUniversalTime, lpLocalTime);
	return 0;
}
BOOL myFileTimeToSystemTime(FILETIME* lpFileTime, SYSTEMTIME* lpSystemTime) {
	if (verbose) printf("FileTimeToSystemTime %p %p\n", lpFileTime, lpSystemTime);
	return 0;
}
uint32_t myGetTimeZoneInformation(void* lpTimeZoneInformation) {
	if (verbose) printf("GetTimeZoneInformation %p\n", lpTimeZoneInformation);
	return 0;
}
BOOL myGetComputerNameA(char* lpBuffer, uint32_t* nSize) {
	if (verbose) printf("GetComputerNameA %p %p\n", lpBuffer, nSize);
	return 0;
}
BOOL myGetUserNameA(char* lpBuffer, uint32_t* pcbBuffer) {
	if (verbose) printf("GetUserNameA %p %p\n", lpBuffer, pcbBuffer);
	return 0;
}
BOOL myGetDeviceGammaRamp(HDC hdc, void* lpRamp) {
	if (verbose) printf("GetDeviceGammaRamp %p %p\n", hdc, lpRamp);
	return 0;
}
BOOL mySetDeviceGammaRamp(HDC hdc, void* lpRamp) {
	if (verbose) printf("SetDeviceGammaRamp %p %p\n", hdc, lpRamp);
	return 0;
}
HWND myGetActiveWindow() {
	if (verbose) printf("GetActiveWindow\n");
	return 0;
}
int16_t myGetKeyState(int32_t nVirtKey) {
	if (verbose) printf("GetKeyState %x\n", nVirtKey);
	return 0;
}
int16_t myGetAsyncKeyState(int32_t vKey) {
	if (verbose) printf("GetAsyncKeyState %x\n", vKey);
	return 0;
}
HICON myExtractIconA(HINSTANCE hInst, PSTR pszExeFileName, uint32_t nIconIndex) {
	if (verbose) printf("ExtractIconA %p %p %x\n", hInst, pszExeFileName, nIconIndex);
	return 0;
}
int32_t mywvsprintfA(PSTR param0, PSTR param1, char* arglist) {
	if (verbose) printf("wvsprintfA %p %p %p\n", param0, param1, arglist);
	return 0;
}
int32_t mywsprintfA(PSTR param0, PSTR param1) {
	if (verbose) printf("wsprintfA %p %p\n", param0, param1);
	return 0;
}
BOOL myTranslateMessage(MSG* lpMsg) {
	if (verbose) printf("TranslateMessage %p\n", lpMsg);
	return 0;
}
LRESULT myDispatchMessageA(MSG* lpMsg) {
	if (verbose) printf("DispatchMessageA %p\n", lpMsg);
	return 0;
}
BOOL myPeekMessageA(MSG* lpMsg, HWND hWnd, uint32_t wMsgFilterMin, uint32_t wMsgFilterMax, PEEK_MESSAGE_REMOVE_TYPE wRemoveMsg) {
	if (verbose) printf("PeekMessageA %p %p %x %x %x\n", lpMsg, hWnd, wMsgFilterMin, wMsgFilterMax, wRemoveMsg);
	return 0;
}
LRESULT mySendMessageA(HWND hWnd, uint32_t Msg, WPARAM wParam, LPARAM lParam) {
	if (verbose) printf("SendMessageA %p %x %x %x\n", hWnd, Msg, wParam, lParam);
	return 0;
}
LRESULT myDefWindowProcA(HWND hWnd, uint32_t Msg, WPARAM wParam, LPARAM lParam) {
	if (verbose) printf("DefWindowProcA %p %x %x %x\n", hWnd, Msg, wParam, lParam);
	return 0;
}
uint16_t myRegisterClassA(WNDCLASSA* lpWndClass) {
	if (verbose) printf("RegisterClassA %p\n", lpWndClass);
	return 0x1201;
}
BOOL myUnregisterClassA(PSTR lpClassName, HINSTANCE hInstance) {
	if (verbose) printf("UnregisterClassA %p %p\n", lpClassName, hInstance);
	return 0;
}
HWND myCreateWindowExA(WINDOW_EX_STYLE dwExStyle, PSTR lpClassName, PSTR lpWindowName, WINDOW_STYLE dwStyle, int32_t X, int32_t Y, int32_t nWidth, int32_t nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, void* lpParam) {
	if (verbose) printf("CreateWindowExA %x %p %p %x %x %x %x %x %p %p %p %p\n", dwExStyle, lpClassName, lpWindowName, dwStyle, X, Y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
	return 0;
}
BOOL myDestroyWindow(HWND hWnd) {
	if (verbose) printf("DestroyWindow %p\n", hWnd);
	return 0;
}
BOOL myShowWindow(HWND hWnd, SHOW_WINDOW_CMD nCmdShow) {
	if (verbose) printf("ShowWindow %p %x\n", hWnd, nCmdShow);
	return 0;
}
BOOL myMoveWindow(HWND hWnd, int32_t X, int32_t Y, int32_t nWidth, int32_t nHeight, BOOL bRepaint) {
	if (verbose) printf("MoveWindow %p %x %x %x %x %x\n", hWnd, X, Y, nWidth, nHeight, bRepaint);
	return 0;
}
BOOL mySetWindowPos(HWND hWnd, HWND hWndInsertAfter, int32_t X, int32_t Y, int32_t cx, int32_t cy, SET_WINDOW_POS_FLAGS uFlags) {
	if (verbose) printf("SetWindowPos %p %p %x %x %x %x %x\n", hWnd, hWndInsertAfter, X, Y, cx, cy, uFlags);
	return 0;
}
int32_t myGetSystemMetrics(SYSTEM_METRICS_INDEX nIndex) {
	if (verbose) printf("GetSystemMetrics %x\n", nIndex);
	return 0;
}
HMENU myGetSystemMenu(HWND hWnd, BOOL bRevert) {
	if (verbose) printf("GetSystemMenu %p %x\n", hWnd, bRevert);
	return 0;
}
BOOL myEnableMenuItem(HMENU hMenu, uint32_t uIDEnableItem, MENU_ITEM_FLAGS uEnable) {
	if (verbose) printf("EnableMenuItem %p %x %x\n", hMenu, uIDEnableItem, uEnable);
	return 0;
}
HWND myGetForegroundWindow() {
	if (verbose) printf("GetForegroundWindow\n");
	return 0;
}
BOOL mySetForegroundWindow(HWND hWnd) {
	if (verbose) printf("SetForegroundWindow %p\n", hWnd);
	return 0;
}
BOOL myGetClientRect(HWND hWnd, RECT* lpRect) {
	if (verbose) printf("GetClientRect %p %p\n", hWnd, lpRect);
	return 0;
}
BOOL myGetWindowRect(HWND hWnd, RECT* lpRect) {
	if (verbose) printf("GetWindowRect %p %p\n", hWnd, lpRect);
	return 0;
}
BOOL myAdjustWindowRect(RECT* lpRect, WINDOW_STYLE dwStyle, BOOL bMenu) {
	if (verbose) printf("AdjustWindowRect %p %x %x\n", lpRect, dwStyle, bMenu);
	return 0;
}
MESSAGEBOX_RESULT myMessageBoxA(HWND hWnd, PSTR lpText, PSTR lpCaption, MESSAGEBOX_STYLE uType) {
	if (verbose) printf("MessageBoxA %p %s %s %x\n", hWnd, lpText, lpCaption, uType);
	return 0;
}
int32_t myShowCursor(BOOL bShow) {
	if (verbose) printf("ShowCursor %x\n", bShow);
	return -1;
}
BOOL mySetCursorPos(int32_t X, int32_t Y) {
	if (verbose) printf("SetCursorPos %x %x\n", X, Y);
	return 0;
}
BOOL myGetCursorPos(POINT* lpPoint) {
	if (verbose) printf("GetCursorPos %p\n", lpPoint);
	memset(lpPoint, 0, sizeof(*lpPoint));
	return 0;
}
BOOL myCreateCaret(HWND hWnd, HBITMAP hBitmap, int32_t nWidth, int32_t nHeight) {
	if (verbose) printf("CreateCaret %p %p %x %x\n", hWnd, hBitmap, nWidth, nHeight);
	return 0;
}
BOOL myDestroyCaret() {
	if (verbose) printf("DestroyCaret\n");
	return 0;
}
BOOL myHideCaret(HWND hWnd) {
	if (verbose) printf("HideCaret %p\n", hWnd);
	return 0;
}
BOOL myShowCaret(HWND hWnd) {
	if (verbose) printf("ShowCaret %p\n", hWnd);
	return 0;
}
BOOL mySetCaretPos(int32_t X, int32_t Y) {
	if (verbose) printf("SetCaretPos %x %x\n", X, Y);
	return 0;
}
HWND myFindWindowA(PSTR lpClassName, PSTR lpWindowName) {
	if (verbose) printf("FindWindowA %p %p\n", lpClassName, lpWindowName);
	return 0;
}
int32_t myGetClassNameA(HWND hWnd, char* lpClassName, int32_t nMaxCount) {
	if (verbose) printf("GetClassNameA %p %p %x\n", hWnd, lpClassName, nMaxCount);
	return 0;
}
HHOOK mySetWindowsHookExA(WINDOWS_HOOK_ID idHook, HOOKPROC lpfn, HINSTANCE hmod, uint32_t dwThreadId) {
	if (verbose) printf("SetWindowsHookExA %x %p %p %x\n", idHook, lpfn, hmod, dwThreadId);
	if (idHook == 2)
		keyb_hook = lpfn;
	return (HHOOK)0x1234;
}
BOOL myUnhookWindowsHookEx(HHOOK hhk) {
	if (verbose) printf("UnhookWindowsHookEx %p\n", hhk);
	return 0;
}
LRESULT myCallNextHookEx(HHOOK hhk, int32_t nCode, WPARAM wParam, LPARAM lParam) {
	if (verbose) printf("CallNextHookEx %p %x %x %x\n", hhk, nCode, wParam, lParam);
	return 0;
}
uint32_t myGetCurrentDirectoryA(uint32_t nBufferLength, PSTR lpBuffer) {
	if (verbose) printf("GetCurrentDirectoryA %x %p\n", nBufferLength, lpBuffer);
	const char *dir = "h:\\";
	int l = strlen(dir) + 1;
	if (nBufferLength >= l)
		strcpy(lpBuffer, dir);
	return l;
}
uint32_t mySetCurrentDirectoryA(PSTR lpPathName) {
	if (verbose) printf("SetCurrentDirectoryA %s\n", lpPathName);
	return 1;
}

asm("ret_not_impl:\n mov $0x80004001, %eax\n ret $4");
extern int ret_not_impl();

struct di_vtbl_t {
	void *a, *b, *c;
} di_vtbl = { ret_not_impl, ret_not_impl, ret_not_impl };
void *di = &di_vtbl;

HRESULT myDirectInputCreateA(HINSTANCE hinst, uint32_t dwVersion, void **ppDI, void *punkOuter) {
	*ppDI = &di;
	return 0;
}

MMRESULT myjoyGetDevCapsA(uint32_t id, void *lpCaps, uint32_t uSize) {
	return MMSYSERR_NODRIVER;
}
SOCKET myaccept(SOCKET s, SOCKADDR* addr, int32_t* addrlen) {
	if (verbose) printf("accept %x %p %p\n", s, addr, addrlen);
	return 0;
}
int32_t mybind(SOCKET s, SOCKADDR* name, int32_t namelen) {
	if (verbose) printf("bind %x %p %x\n", s, name, namelen);
	return 0;
}
int32_t myclosesocket(SOCKET s) {
	if (verbose) printf("closesocket %x\n", s);
	return 0;
}
int32_t myconnect(SOCKET s, SOCKADDR* name, int32_t namelen) {
	if (verbose) printf("connect %x %p %x\n", s, name, namelen);
	return 0;
}
int32_t myioctlsocket(SOCKET s, int32_t cmd, uint32_t* argp) {
	if (verbose) printf("ioctlsocket %x %x %p\n", s, cmd, argp);
	return 0;
}
int32_t mygetpeername(SOCKET s, SOCKADDR* name, int32_t* namelen) {
	if (verbose) printf("getpeername %x %p %p\n", s, name, namelen);
	return 0;
}
int32_t mygetsockname(SOCKET s, SOCKADDR* name, int32_t* namelen) {
	if (verbose) printf("getsockname %x %p %p\n", s, name, namelen);
	return 0;
}
int32_t mygetsockopt(SOCKET s, int32_t level, int32_t optname, PSTR optval, int32_t* optlen) {
	if (verbose) printf("getsockopt %x %x %x %p %p\n", s, level, optname, optval, optlen);
	return 0;
}
uint32_t myhtonl(uint32_t hostlong) {
	if (verbose) printf("htonl %x\n", hostlong);
	return 0;
}
uint16_t myhtons(uint16_t hostshort) {
	if (verbose) printf("htons %x\n", hostshort);
	return 0;
}
uint32_t myinet_addr(PSTR cp) {
	if (verbose) printf("inet_addr %p\n", cp);
	return 0;
}
PSTR myinet_ntoa(IN_ADDR in) {
	if (verbose) printf("inet_ntoa %x\n", in);
	return 0;
}
int32_t mylisten(SOCKET s, int32_t backlog) {
	if (verbose) printf("listen %x %x\n", s, backlog);
	return 0;
}
uint32_t myntohl(uint32_t netlong) {
	if (verbose) printf("ntohl %x\n", netlong);
	return 0;
}
uint16_t myntohs(uint16_t netshort) {
	if (verbose) printf("ntohs %x\n", netshort);
	return 0;
}
int32_t myrecv(SOCKET s, PSTR buf, int32_t len, int32_t flags) {
	if (verbose) printf("recv %x %p %x %x\n", s, buf, len, flags);
	return 0;
}
int32_t myrecvfrom(SOCKET s, PSTR buf, int32_t len, int32_t flags, SOCKADDR* from, int32_t* fromlen) {
	if (verbose) printf("recvfrom %x %p %x %x %p %p\n", s, buf, len, flags, from, fromlen);
	return 0;
}
int32_t myselect(int32_t nfds, void* readfds, void* writefds, void* exceptfds, timeval* timeout) {
	if (verbose) printf("select %x %p %p %p %p\n", nfds, readfds, writefds, exceptfds, timeout);
	return 0;
}
int32_t mysend(SOCKET s, PSTR buf, int32_t len, SEND_FLAGS flags) {
	if (verbose) printf("send %x %p %x %x\n", s, buf, len, flags);
	return 0;
}
int32_t mysendto(SOCKET s, PSTR buf, int32_t len, int32_t flags, SOCKADDR* to, int32_t tolen) {
	if (verbose) printf("sendto %x %p %x %x %p %x\n", s, buf, len, flags, to, tolen);
	return 0;
}
int32_t mysetsockopt(SOCKET s, int32_t level, int32_t optname, PSTR optval, int32_t optlen) {
	if (verbose) printf("setsockopt %x %x %x %p %x\n", s, level, optname, optval, optlen);
	return 0;
}
int32_t myshutdown(SOCKET s, int32_t how) {
	if (verbose) printf("shutdown %x %x\n", s, how);
	return 0;
}
SOCKET mysocket(int32_t af, int32_t type, int32_t protocol) {
	if (verbose) printf("socket %x %x %x\n", af, type, protocol);
	return 0;
}
BOOL mywglCopyContext(HGLRC param0, HGLRC param1, uint32_t param2) {
	if (verbose) printf("wglCopyContext %p %p %x\n", param0, param1, param2);
	return 0;
}
HGLRC mywglCreateContext(HDC param0) {
	if (verbose) printf("wglCreateContext %p\n", param0);
	return (HGLRC)1;
}
HGLRC mywglCreateLayerContext(HDC param0, int32_t param1) {
	if (verbose) printf("wglCreateLayerContext %p %x\n", param0, param1);
	return 0;
}
BOOL mywglDeleteContext(HGLRC param0) {
	if (verbose) printf("wglDeleteContext %p\n", param0);
	return 0;
}
HGLRC mywglGetCurrentContext() {
	if (verbose) printf("wglGetCurrentContext\n");
	return 0;
}
HDC mywglGetCurrentDC() {
	if (verbose) printf("wglGetCurrentDC\n");
	return 0;
}
PROC mywglGetProcAddress(PSTR param0) {
	if (verbose) printf("wglGetProcAddress %s\n", param0);
	extern uintptr_t find_fun(const char *);
	return (PROC)find_fun(param0);
}
BOOL mywglMakeCurrent(HDC param0, HGLRC param1) {
	if (verbose) printf("wglMakeCurrent %p %p\n", param0, param1);
	if (window)
		return 0;
    SDL_SetHint(SDL_HINT_NO_SIGNAL_HANDLERS, "1");
    SDL_Init(SDL_INIT_VIDEO);
	window = SDL_CreateWindow("SDL",  SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED,
        640, 480, SDL_WINDOW_RESIZABLE | SDL_WINDOW_SHOWN | SDL_WINDOW_OPENGL);
	if (!window) {
		fprintf(stderr, "SDL_CreateWindow: %s\n", SDL_GetError());
		return 0;
	}
	if (window) {
		SDL_GL_CreateContext(window);
		//SDL_GL_SetSwapInterval(0);
	}
	return 1;
}
BOOL mywglShareLists(HGLRC param0, HGLRC param1) {
	if (verbose) printf("wglShareLists %p %p\n", param0, param1);
	return 0;
}
BOOL mywglUseFontBitmapsA(HDC param0, uint32_t param1, uint32_t param2, uint32_t param3) {
	if (verbose) printf("wglUseFontBitmapsA %p %x %x %x\n", param0, param1, param2, param3);
	return 0;
}
BOOL mywglUseFontBitmapsW(HDC param0, uint32_t param1, uint32_t param2, uint32_t param3) {
	if (verbose) printf("wglUseFontBitmapsW %p %x %x %x\n", param0, param1, param2, param3);
	return 0;
}
BOOL mywglUseFontOutlinesA(HDC param0, uint32_t param1, uint32_t param2, uint32_t param3, float param4, float param5, int32_t param6, GLYPHMETRICSFLOAT* param7) {
	if (verbose) printf("wglUseFontOutlinesA %p %x %x %x %f %f %x %p\n", param0, param1, param2, param3, param4, param5, param6, param7);
	return 0;
}
BOOL mywglUseFontOutlinesW(HDC param0, uint32_t param1, uint32_t param2, uint32_t param3, float param4, float param5, int32_t param6, GLYPHMETRICSFLOAT* param7) {
	if (verbose) printf("wglUseFontOutlinesW %p %x %x %x %f %f %x %p\n", param0, param1, param2, param3, param4, param5, param6, param7);
	return 0;
}
BOOL mywglDescribeLayerPlane(HDC param0, int32_t param1, int32_t param2, uint32_t param3, LAYERPLANEDESCRIPTOR* param4) {
	if (verbose) printf("wglDescribeLayerPlane %p %x %x %x %p\n", param0, param1, param2, param3, param4);
	return 0;
}
int32_t mywglSetLayerPaletteEntries(HDC param0, int32_t param1, int32_t param2, int32_t param3, uint32_t* param4) {
	if (verbose) printf("wglSetLayerPaletteEntries %p %x %x %x %p\n", param0, param1, param2, param3, param4);
	return 0;
}
int32_t mywglGetLayerPaletteEntries(HDC param0, int32_t param1, int32_t param2, int32_t param3, uint32_t* param4) {
	if (verbose) printf("wglGetLayerPaletteEntries %p %x %x %x %p\n", param0, param1, param2, param3, param4);
	return 0;
}
BOOL mywglRealizeLayerPalette(HDC param0, int32_t param1, BOOL param2) {
	if (verbose) printf("wglRealizeLayerPalette %p %x %x\n", param0, param1, param2);
	return 0;
}
BOOL mywglSwapLayerBuffers(HDC param0, uint32_t param1) {
	if (verbose) printf("wglSwapLayerBuffers %p %x\n", param0, param1);
	return 0;
}

void no_fun() {
}

void my__GetMainArgs() {}
void my_splitpath(const char *path, char *drive, char *dir, char *fname, char *ext) {
	const char *dre = path[0] && path[1] == ':' ? path + 2 : NULL;
	const char *dirs = dre ? dre : path;
	const char *dire1 = strrchr(dirs, '/');
	const char *dire2 = strrchr(dirs, '\\');
	const char *dire = (dire1 && dire2 && dire1 > dire2) || dire1 ? dire1 + 1 : dire2 ? dire2 + 1 : NULL;
	const char *fs = dire ? dire : dirs;
	const char *es = strrchr(fs, '.');
	const char *fe = es ? es : fs + strlen(fs);
	if (drive) {
		if (dre) {
			memcpy(drive, path, dre - path);
			drive[dre - path] = 0;
		} else
			*drive = 0;
	}
	if (dir) {
		if (dire) {
			memcpy(dir, dirs, dire - dirs);
			dir[dire - dirs] = 0;
		} else
			*dir = 0;
	}
	if (fname) {
		memcpy(fname, fs, fe - fs);
		fname[fe - fs] = 0;
	}
	if (ext)
		strcpy(ext, es ? es : "");
}

