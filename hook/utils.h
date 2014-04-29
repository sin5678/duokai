#ifndef _UTILS_H_
#define _UTILS_H_


VOID DbgPrint(PCHAR pcFormat,...);

#define dbg_msg(fmt, ...)  do{ \
    DbgPrint( "%s:%d::%s()"##fmt##"\n",\
    __FILE__,\
    __LINE__,\
    __FUNCTION__,\
    __VA_ARGS__);\
}while(0)
#define dbg_brk() do{__asm int 3}while(0)


#define ALIGN_DOWN(x, align) (x &~ (align - 1))
#define ALIGN_UP(x, align) ((x & (align - 1)) ? ALIGN_DOWN(x, align) + align:x)
#define RVA_TO_VA(B,O) ((PCHAR)(((PCHAR)(B)) + ((ULONG_PTR)(O))))
#define VA_TO_RVA(B,P) ((ULONG)(((PCHAR)(P)) - ((PCHAR)(B))))
#define MAKE_PTR(B,O,T) (T)(RVA_TO_VA(B,O))
#define RtlOffsetToPointer(B, O) ((PCHAR)(((PCHAR)(B)) + ((ULONG_PTR)(O))))

PVOID GetMyBase();
DWORD RvaToOffset(PIMAGE_NT_HEADERS pPE,DWORD dwRva);
VOID FixDWORD(BYTE *Data,DWORD Size,DWORD Old,DWORD New);
PIMAGE_SECTION_HEADER SearchSection(PVOID pvPEBase,LPCSTR lpName);
PVOID MapBinary(LPCSTR lpPath,DWORD dwFileAccess,DWORD dwFileFlags,DWORD dwPageAccess,DWORD dwMapAccess,PDWORD pdwSize);
BOOL SetFileDllFlag(LPCSTR lpPath);
BOOL FileWrite(LPCSTR lpName,DWORD dwFlags,LPCVOID pvBuffer,DWORD dwSize);
BOOL FileRead(LPCSTR lpFileName, PVOID *ppBuffer, DWORD *pdwSize);
BOOL CheckAdmin();
BOOL CheckUAC();
BOOL CheckWow64();
VOID HideDllPeb(LPCSTR lpDllName);
PVOID GetSystemInformation(SYSTEMINFOCLASS InfoClass);
DWORD CreateThreadAndWait(PVOID pvProc,PVOID pvContext,DWORD dwWait);
LPCSTR GetMachineGuid();
PCHAR GetStrValueStr(PCHAR pcBuffer,DWORD dwBufferLen,PCHAR pcStr,DWORD dwStrLen,PCHAR pcSep);
unsigned long Crc32(const unsigned char * buf, unsigned long len);
LONG DeleteRegKeyRecursive(HKEY RootKey,LPCSTR lpSubKey);
BOOL LoadImageFromMemory(PVOID pBuffer, PVOID *ppImage);
BOOLEAN ProcessImport(PVOID pvImageBase);
BOOL ProcessRelocs(PVOID pvImageBase, DWORD dwDelta);
PVOID GetExportEntry(PVOID ModuleBase, LPCSTR lpProcName);
UINT GetRand(UINT uMin, UINT uMax);
char *Wchar2Char(const WCHAR *str);
char *Wchar2UTF8(const WCHAR *str);
WCHAR *Char2Wchar(const char *str);
ULONG  GetStringBytesW(const WCHAR *str);
CHAR * UrlencodeW(const wchar_t* lpURL);
int __cdecl Wtoi(_In_z_ const wchar_t *_Str);
char *UrlEncode(char *str);
LPBYTE ReadAllFile(LPCWSTR fileName,LPDWORD fileSize);
__int64 GetSysTickCount64();
WCHAR* GetMachineID (_Inout_ WCHAR *retw);
WCHAR* GetWindowsBuildString(void);
WCHAR *GetFormatString(LPCWSTR formatstring, ...);
int WriteReg(HKEY MainKey,LPCTSTR Subkey,LPCTSTR Vname,DWORD Type, LPCTSTR  szBuf,DWORD dwData,int Mode);
int  ReadRegW(HKEY MainKey,LPCWSTR Subkey,LPCWSTR Vname,void *szData, DWORD dwSize);
int  ReadRegA(HKEY MainKey,LPCSTR Subkey,LPCSTR Vname,void *szData, DWORD dwSize);
BOOL IsAdmin(void);
int GetSysIpInfo(WCHAR *buff,int length);
int GetSysCpuString(WCHAR *RetBuf,int length);
void clean_charW(WCHAR  *str,WCHAR ch);
const char *TakeOutStringByChar(const char *Source,char *Dest, int buflen, char ch);
char* strtok_r(
    char *str, 
    const char *delim, 
    char **nextp);
char *url_decode(char *str);
char to_hex(char code);
#endif