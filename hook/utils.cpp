#include <intrin.h>
#include <windows.h>
#include <stdio.h>
#include <shlwapi.h>
#include <tchar.h>
#include <shlobj.h>
#include <imagehlp.h>

#include "ntdll.h"
#include "utils.h"

static UINT rand_val = 0;
UINT GetRand(UINT uMin, UINT uMax)
{
	if (!rand_val) rand_val = GetTickCount();
	rand_val = (rand_val * 214013L + 2531011L);

	return rand_val % (uMax - uMin + 1) + uMin;
}

PVOID GetMyBase()
{
	MEMORY_BASIC_INFORMATION MemoryBasicInfo;

	VirtualQuery(GetMyBase,&MemoryBasicInfo,sizeof(MemoryBasicInfo));

	return MemoryBasicInfo.AllocationBase;
}

VOID DbgPrint(PCHAR pcFormat,...)
{
	va_list vaList;
	CHAR chFormat[1024];
	CHAR chMsg[1024*4];
	CHAR chPath[MAX_PATH];

	GetModuleFileNameA(NULL,chPath,RTL_NUMBER_OF(chPath)-1);

	_snprintf(chFormat,sizeof(chFormat)-1,"[%s] %s",PathFindFileNameA(chPath),pcFormat);

	va_start(vaList,pcFormat);
	_vsnprintf(chMsg,sizeof(chMsg)-1,chFormat,vaList);
	va_end(vaList);

	OutputDebugString(chMsg);
}


char * __cdecl strdup(const char* c)
{
	size_t len = strlen(c);
	char* p = (char*)malloc(len+1);
	if (p)
	{
		strcpy(p,c);
		p[len] = 0;
	}
	return p;
}

void * __cdecl malloc(size_t sz)
{
	return HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,sz);
}

void __cdecl free(void * ptr)
{
	HeapFree(GetProcessHeap(),0,ptr);
}

void * __cdecl realloc(void * ptr,size_t new_size)
{
	return HeapReAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,ptr,new_size);
}

char *Wchar2Char(const WCHAR *str)
{
    char *buff;
    int ret;
    ret = WideCharToMultiByte(CP_ACP, 0, str, -1, NULL, 0,NULL,FALSE);
    if(ret > 0)
    {
        buff = (char *)malloc(ret);
        if(WideCharToMultiByte(CP_ACP, 0, str, -1, buff, ret,NULL,FALSE))
            return buff;
        else
            free(buff);
    }
    return NULL;
}

char *Wchar2UTF8(const WCHAR *str)
{
    char *buff;
    int ret;
    ret = WideCharToMultiByte(CP_UTF8, 0, str, -1, NULL, 0,NULL,FALSE);
    if(ret > 0)
    {
        buff = (char *)malloc(ret);
        if(WideCharToMultiByte(CP_UTF8, 0, str, -1, buff, ret,NULL,FALSE))
            return buff;
        else
            free(buff);
    }
    return NULL;
}

// ANSII --> UNICODE 注意返回的要以 av_Free 释放掉 
WCHAR *Char2Wchar(const char *str)
{
    WCHAR *buff;
    int ret;
    ret = MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, str, -1, NULL, 0);
    if(ret > 0)
    {
        buff = (WCHAR *)malloc(ret * sizeof(WCHAR));
        if(MultiByteToWideChar(CP_ACP, MB_ERR_INVALID_CHARS, str, -1, buff, ret))
            return buff;
        else
            free(buff);
    }
    return NULL;
}

ULONG  GetStringBytesW(const WCHAR *str)
{
    return (wcslen(str) + 1) * sizeof(WCHAR);
}


int  ReadRegA(HKEY MainKey,LPCSTR Subkey,LPCSTR Vname,void *szData, DWORD dwSize)
{
    HKEY   hKey;

    if(RegOpenKeyA(MainKey,Subkey,&hKey) == ERROR_SUCCESS)
    {
        if(RegQueryValueExA(hKey,Vname,NULL,NULL,(LPBYTE)szData,&dwSize) != ERROR_SUCCESS)
        {
            dwSize = 0;
        }
        RegCloseKey(hKey);  
    }
	else
    {
        dwSize = 0;
    }

    return dwSize;
}

int  ReadRegW(HKEY MainKey,LPCWSTR Subkey,LPCWSTR Vname,void *szData, DWORD dwSize)
{
    HKEY   hKey;

    if(RegOpenKeyW(MainKey,Subkey,&hKey) == ERROR_SUCCESS)
    {
        if(RegQueryValueExW(hKey,Vname,NULL,NULL,(LPBYTE)szData,&dwSize) != ERROR_SUCCESS)
        {
            dwSize = 0;
        }
        RegCloseKey(hKey);  
    }
	else
    {
        dwSize = 0;
    }

    return dwSize;
}

int WriteReg(HKEY MainKey,LPCTSTR Subkey,LPCTSTR Vname,DWORD Type, LPCTSTR  szBuf,DWORD dwData,int Mode)
{
    HKEY hKey;
    BOOL bError = FALSE;

    if (Mode == 0)
    {
        if ( RegCreateKey(MainKey,Subkey, &hKey) != ERROR_SUCCESS) 
            goto exit;
    }
    else
    {
        if (RegOpenKey(MainKey,Subkey, &hKey) != ERROR_SUCCESS) 
            goto exit;
        //设置一个值时如果该值不存在则返回false
        //如果不存在时要创建一个则调用时Mode=0，由RegCreateKey来获得句柄
        if (RegQueryValueEx(hKey, Vname, 0, &Type, NULL, NULL) != ERROR_SUCCESS)
            goto exit;
    }

    if (Mode == 2)
    {
        if (RegDeleteValue(hKey,Vname) != ERROR_SUCCESS)
        {
            goto exit;
        }
    }

    if (Type == REG_SZ || Type == REG_EXPAND_SZ)
    {
        if (RegSetValueEx(hKey,Vname,0,Type,(LPBYTE) szBuf, sizeof(TCHAR) * (_tcslen(szBuf) + 1)) != ERROR_SUCCESS)  
        {
            goto exit;
        }
    }

    if(Type == REG_DWORD)
    {
        if (RegSetValueEx(hKey,Vname,0,Type,(LPBYTE) &dwData,sizeof(DWORD)) != ERROR_SUCCESS)
        {
            goto exit;
        }
    }

    bError = TRUE;
exit:
    RegCloseKey(hKey);

    return bError;
}

BOOL IsAdmin(void)
{
	TCHAR buff[512];
	return 0 != ReadRegW(HKEY_USERS,L"S-1-5-19\\Environment",L"TEMP",buff,sizeof(buff));
}

WCHAR *GetFormatString(LPCWSTR formatstring, ...) 
{
    int nSize = 0;
    WCHAR *buff = NULL;
    int ret ;

    va_list args;
    va_start(args, formatstring);

    do 
    {
        nSize += 1;
        if(buff)
            free(buff);
        buff = (WCHAR *)malloc(nSize * sizeof(WCHAR));
        if(NULL == buff)
            return NULL;
        ret = _vsnwprintf(buff,nSize-1,formatstring,args);
    }while(0 > ret);
    buff[nSize-1] = 0; //vsnwprintf 不会为我们写入最后的 0 
    va_end(args);
    return buff;
}

/*
返回 wins 的版本信息字符串
*/
WCHAR* GetWindowsBuildString(void)
{
    OSVERSIONINFOEXW osvi;
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);
    //http://msdn.microsoft.com/en-us/library/windows/desktop/ms724833(v=vs.85).aspx
    if ( GetVersionExW ( ( OSVERSIONINFOW * ) &osvi) 
        != FALSE && osvi.dwPlatformId == VER_PLATFORM_WIN32_NT )
    {

        if ( osvi.wProductType == VER_NT_WORKSTATION )
        {
            //Windows 2000 - 5.0
            if(osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 0)
                return L"Win2000";
            //Windows XP -  5.1
            else if(osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 1)
                return L"WinXp 5.1";
            //Windows XP Professional x64 Edition - 5.2
            else if(osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2)
                return L"WinXp 5.2";
            //Windows Vista - 6.0
            else if(osvi.dwMajorVersion == 6  && osvi.dwMinorVersion == 0)
                return L"Vista";
            //Windows 7 - 6.1
            else if(osvi.dwMajorVersion == 6  && osvi.dwMinorVersion == 1)
                return L"Win7";
            //Windows 8 - 6.2
            else if(osvi.dwMajorVersion == 6  && osvi.dwMinorVersion == 2)
                return L"Win8";
            else
                return L"Win8+";
        }
        //Windows Server based
        else if ( osvi.wProductType == VER_NT_DOMAIN_CONTROLLER 
            || osvi.wProductType == VER_NT_SERVER)
        {

            //Windows Server 2003 - 5.2, Windows Server 2003 R2 - 5.2, Windows Home Server - 5.2
            if(osvi.dwMajorVersion == 5 && osvi.dwMinorVersion == 2)
                return L"Win2003";
            //Windows Server 2008 - 6.0
            else if(osvi.dwMajorVersion == 6  && osvi.dwMinorVersion == 0)
                return L"Win2008";
            //Windows Server 2008 R2 - 6.1
            else if(osvi.dwMajorVersion == 6  && osvi.dwMinorVersion == 1)
                return L"Win2008 R2";
            //Windows Server 2008 R2 - 6.1
            else 
                return L"Win2012?";
        }
        return L"00";
    }
    return L"00";
}

WCHAR* GetMachineID (_Inout_ WCHAR *retw)
{
    HW_PROFILE_INFOW   HwProfInfo;
    if (GetCurrentHwProfileW(&HwProfInfo)) 
    {
        //WCHAR retw[260];
        memset(retw, 0, sizeof(retw));
        lstrcpyW(retw, HwProfInfo.szHwProfileGuid);
        return retw;
    } 
    else
        return NULL;
}

__int64 GetSysTickCount64()
{
    static LARGE_INTEGER TicksPerSecond = {0};
    LARGE_INTEGER Tick;
    __int64 Ret = 0;

    if(QueryPerformanceFrequency(&TicksPerSecond))
    {
        if(QueryPerformanceCounter(&Tick))
        {
            __int64 Seconds = Tick.QuadPart / TicksPerSecond.QuadPart;
            __int64 LeftPart = Tick.QuadPart - (TicksPerSecond.QuadPart*Seconds);
            __int64 MillSeconds = LeftPart*1000/TicksPerSecond.QuadPart;
            Ret = Seconds*1000 + MillSeconds;
        }
    }
    return Ret;
};

int __cdecl Wtoi(_In_z_ const wchar_t *_Str)
{
    typedef int (__cdecl *pwtoi)(_In_z_ const wchar_t *_Str);
    pwtoi p = (pwtoi)GetProcAddress(GetModuleHandle("ntdll.dll"),"__wtoi");
    if(p)
    {
        return p(_Str);
    }
    else
    {
        dbg_msg("can not get wtoi address \n");
    }
    return 0;
}

LPBYTE ReadAllFile(LPCWSTR fileName,LPDWORD fileSize)
{
    LPBYTE ret = NULL;
    HANDLE hfile;
    //先成功打开这个文件再说
    hfile = CreateFileW(fileName,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
    if(hfile != INVALID_HANDLE_VALUE)
    {
        //看看这个文件的大小是不是 0 
        DWORD dwSize = GetFileSize(hfile,NULL);
        if(dwSize)
        {
            BYTE *buff = (BYTE *)malloc(dwSize);
            DWORD bytes = 0;
            DWORD bytesRead = 0;
            while(bytesRead < dwSize && (ReadFile(hfile,buff + bytesRead,dwSize - bytesRead,&bytes,NULL)))
            {
                bytesRead += bytes;
            }
            if(bytesRead >= dwSize)
            {
                *fileSize = dwSize;
                ret = buff;
            }
            if(!ret && buff)
            {
                free(buff);
            }
        }
        CloseHandle(hfile);
    }
    return ret;
}

char *UrlEncode(char *str)
{
    char *buf = (char *)malloc(strlen(str) * 3 + 1);
    if (buf != NULL)
    {
        char *pstr = str, *pbuf = buf;
        while (*pstr)
        {
            //if (isalnum(*pstr) || *pstr == '-' || *pstr == '_' || *pstr == '.' || *pstr == '~')
            //    *pbuf++ = *pstr;
            if (*pstr == ' ')
                *pbuf++ = '+';
            else
                *pbuf++ = '%', *pbuf++ = to_hex(*pstr >> 4), *pbuf++ = to_hex(*pstr & 15);
            pstr++;
        }
        *pbuf = '\0';
        return buf;
    }

    return NULL;
}

CHAR * UrlencodeW(const wchar_t* lpURL)
{
    CHAR *ret = NULL;
    TCHAR * strTemp;
    const int nBuffLen = (wcslen(lpURL) + 1) * 6; //guess_url_encode_length(lpURL) + 1;

    WORD c1;
    const wchar_t* lpFileOffset = wcsrchr(lpURL, _T('/'));
    const wchar_t* lpSrc = lpURL;
    strTemp = (TCHAR *)malloc(nBuffLen * sizeof(TCHAR));
    TCHAR* lpDst = strTemp;

    while ( (c1 = *lpSrc++) != _T('\0') )
    {
        if ( HIBYTE(c1) == 0 )
        {
            if ( (c1 <= '0') || (c1 >= 'z'))  //字符编码范围 
            {
                // hex encode
                *lpDst++ = _T('%');
                *lpDst++ = _T("0123456789ABCDEF")[c1 >> 4];
                *lpDst++ = _T("0123456789ABCDEF")[c1 & 0x0F];
            }
            else
            {
                *lpDst++ = (TCHAR)c1;
            }
        }
        else
        {
            const wchar_t* lpNextSrc = lpSrc;
            while ( (c1 = *lpNextSrc), HIBYTE(c1) != 0 )
            {
                lpNextSrc++;
            }

            --lpSrc; // 回溯一个字符

            const int nInputLen = (lpNextSrc - lpSrc);
            int nOutputLen = 0;
            char* lpOutputBuff = NULL;

            if ( (lpFileOffset != NULL) && (lpSrc > lpFileOffset) )
            {
                // hex encode
                nOutputLen = WideCharToMultiByte(CP_ACP, 0, lpSrc, nInputLen, NULL, 0, 0, NULL);

                lpOutputBuff = new char[nOutputLen + 1];
                WideCharToMultiByte(CP_ACP, 0, lpSrc, nInputLen, lpOutputBuff, nOutputLen, NULL, NULL);
            }
            else
            {
                nOutputLen = WideCharToMultiByte(CP_UTF8, 0, lpSrc, nInputLen, NULL, 0, 0, NULL);

                lpOutputBuff = new char[nOutputLen + 1];
                WideCharToMultiByte(CP_UTF8, 0, lpSrc, nInputLen, lpOutputBuff, nOutputLen, NULL, NULL);
            }

            for ( int i = 0; i < nOutputLen; i++ )
            {
                BYTE c1 = lpOutputBuff[i];

                *lpDst++ = _T('%');
                *lpDst++ = _T("0123456789ABCDEF")[c1 >> 4];
                *lpDst++ = _T("0123456789ABCDEF")[c1 & 0x0F];
            }

            delete[] lpOutputBuff;
            lpOutputBuff = NULL;

            lpSrc = lpNextSrc;
        }
    }

    if ( lpDst != NULL )
    {
        *lpDst = 0;
    }
    else
    {
        free(strTemp);
        strTemp = NULL;
    }

    if(strTemp && sizeof(TCHAR) == 2)
    {
        //转换成 CHAR 
        ret = Wchar2Char((WCHAR *)strTemp);
        free(strTemp);
    }
    return ret;
}


/*
void * __cdecl operator new(size_t sz)
{
	return malloc(sz);
}

void * __cdecl operator new(size_t sz,void * ptr)
{
	return (ptr);
}

void __cdecl operator delete(void * ptr)
{
	free(ptr);
}

int __cdecl _purecall(void)
{
	return 0;
}
*/

PVOID MapBinary(LPCSTR lpPath,DWORD dwFileAccess,DWORD dwFileFlags,DWORD dwPageAccess,DWORD dwMapAccess,PDWORD pdwSize)
{
	PVOID pMap = NULL;
	HANDLE hMapping;
	HANDLE hFile;

	hFile = CreateFile(lpPath,dwFileAccess,FILE_SHARE_READ,NULL,OPEN_EXISTING,dwFileFlags,0);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		hMapping = CreateFileMappingA(hFile,NULL,dwPageAccess,0,0,0);
		if (hMapping != INVALID_HANDLE_VALUE)
		{
			pMap = MapViewOfFile(hMapping,dwMapAccess,0,0,0);
			if (!pMap)
			{
				DbgPrint(__FUNCTION__"(): MapViewOfFile failed with error %x\n",GetLastError());
			}
			else if (pdwSize) 
                *pdwSize = GetFileSize(hFile,NULL);

			CloseHandle(hMapping);
		}
		else
		{
			DbgPrint(__FUNCTION__"(): CreateFileMapping failed with error %x\n",GetLastError());
		}

		CloseHandle(hFile);
	}
	else
	{
		DbgPrint(__FUNCTION__"(): CreateFile failed with error %x\n",GetLastError());
	}

	return pMap;
}

BOOL SetFileDllFlag(LPCSTR lpPath)
{
	BOOL bRet = FALSE;
	PIMAGE_NT_HEADERS pNtHdr;
	DWORD dwFileSize;
	PVOID pMap;

	if (pMap = MapBinary(lpPath,FILE_ALL_ACCESS,FILE_FLAG_WRITE_THROUGH,PAGE_READWRITE,FILE_MAP_ALL_ACCESS,&dwFileSize))
	{
		if (pNtHdr = RtlImageNtHeader(pMap))
		{
			DWORD HeaderSum, CheckSum;

			pNtHdr->FileHeader.Characteristics |= IMAGE_FILE_DLL;

			if (CheckSumMappedFile(pMap,dwFileSize,&HeaderSum,&CheckSum))
			{
				pNtHdr->OptionalHeader.CheckSum = CheckSum;

				bRet = TRUE;
			}
		}

		FlushViewOfFile(pMap,dwFileSize);
		UnmapViewOfFile(pMap);
	}

	return bRet;
}

DWORD RvaToOffset(PIMAGE_NT_HEADERS pPE,DWORD dwRva)
{
	PIMAGE_SECTION_HEADER pSEC = IMAGE_FIRST_SECTION(pPE);

	for (WORD i = 0; i < pPE->FileHeader.NumberOfSections; i++)
	{
		if (dwRva >= pSEC->VirtualAddress && dwRva < (pSEC->VirtualAddress + pSEC->Misc.VirtualSize))
		{
			return dwRva + ALIGN_DOWN(pSEC->PointerToRawData,pPE->OptionalHeader.FileAlignment) - pSEC->VirtualAddress;
		}

		pSEC++;
	}

	return 0;
}

PIMAGE_SECTION_HEADER SearchSection(PVOID pvPEBase,LPCSTR lpName)
{
	PIMAGE_NT_HEADERS pNtHeaders;

	pNtHeaders = RtlImageNtHeader(pvPEBase);
	if (pNtHeaders)
	{
		PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);

		for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
		{
			if (!strcmp(lpName,(PCHAR)&pSection->Name)) return pSection;

			pSection++;
		}
	}

	return 0;
}

BOOL FileWrite(LPCSTR lpName,DWORD dwFlags,LPCVOID pvBuffer,DWORD dwSize)
{
	BOOL bRet = FALSE;
	HANDLE hFile;
	DWORD t;

	hFile = CreateFileA(lpName,GENERIC_WRITE,FILE_SHARE_READ,NULL,dwFlags,0,0);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		SetFilePointer(hFile,0,0,FILE_BEGIN);

		bRet = WriteFile(hFile,pvBuffer,dwSize,&t,0);

		FlushFileBuffers(hFile);

		SetEndOfFile(hFile);

		CloseHandle(hFile);
	}

	return bRet;
}

BOOL FileRead(LPCSTR lpFileName, PVOID *ppBuffer, DWORD *pdwSize)
{
	BOOL bRet = FALSE;
	HANDLE hFile;
	DWORD dwSize;
	DWORD dwReaded;

	hFile = CreateFileA(lpFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, 0);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		dwSize = GetFileSize(hFile, NULL);
		if (dwSize)
		{
			*ppBuffer = malloc(dwSize + 1);
			if (*ppBuffer)
			{
				bRet = ReadFile(hFile, *ppBuffer, dwSize, &dwReaded, NULL);
				*RVA_TO_VA(*ppBuffer, dwSize) = '\0';

				if (pdwSize) *pdwSize = dwSize;
				if (!bRet) free(*ppBuffer);
			}
		}

		CloseHandle(hFile);
	}

	return bRet;
}

static int clean_char2W(WCHAR  *str,WCHAR ch)
{
    WCHAR *p;
    while(*str)
    {
        if(*str == ch && *(str+1) == ch)
        {
            p = ++str;
            while(*str)
            {
                *p++ = *(str+1);
                ++str;
            }
            return 1;
        }
        ++str;
    }
    return 0;
}

void clean_charW(WCHAR  *str,WCHAR ch)
{
    while(clean_char2W(str,ch));
}

int GetSysCpuString(WCHAR *RetBuf,int length)
{
    int idx = 0;
    DWORD Mhz = 0;
    WCHAR Temp[1024];
    int len = 0;

    if(ReadRegW(HKEY_LOCAL_MACHINE,L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",L"ProcessorNameString",Temp,1024))
    {
        clean_charW(Temp,L' ');
    }
    else
        return 0;

	len += _snwprintf(RetBuf+len,length, L"%s",Temp);

    idx = 0;
    while(1)
    {
        _snwprintf(Temp,1024,L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\%d", idx++);
        if(ReadRegW(HKEY_LOCAL_MACHINE,Temp,L"~MHz", (CHAR *)&Mhz, sizeof(Mhz)))
        {
           // len += swprintf_s(RetBuf+len,length-len, L"%d MHz,", Mhz);
            //++idx;
        }
        else 
            break;
    }
    --idx;

    _snwprintf(Temp,1024,L"%s",RetBuf);
    len = _snwprintf(RetBuf, length,L"%s X %d ",Temp, idx);

    return len;
}

int GetSysIpInfo(WCHAR *buff,int length)
{
    struct hostent * pHost;
    int i,j;
    char szHostName[128];
    WCHAR addr[32];
    int ret = 0 ;

    buff[0] = 0;
    if( gethostname(szHostName, 128) != 0 ) 
        return 0;

    pHost = gethostbyname(szHostName); 
    if(pHost == NULL)
        return 0;
    for( i = 0; pHost!= NULL && pHost->h_addr_list[i]!= NULL; i++ ) 
    {
        if(buff[0])
            wcsncat(buff,L",",length);
        for(j = 0; j < pHost->h_length; j++ ) 
        {
            if( j > 0 )
                wcscat(buff,L".");

            _snwprintf(addr,RTL_NUMBER_OF(addr),L"%u", (unsigned int)((unsigned char*)pHost->h_addr_list[i])[j]);
            wcsncat(buff,addr,length);
        }
    }
    return wcslen(buff);
}


//判断当前进程是不是具有管理员权限 （administrators 组）
BOOL CheckAdmin()
{
	BOOL Ret;
	SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
	PSID AdministratorsGroup; 

	if (Ret = AllocateAndInitializeSid(&NtAuthority,
		2,
		SECURITY_BUILTIN_DOMAIN_RID,
		DOMAIN_ALIAS_RID_ADMINS,
		0,0,0,0,0,0,&AdministratorsGroup))
	{
		if (!CheckTokenMembership(NULL,AdministratorsGroup,&Ret))
		{
			Ret = FALSE;
		}

		FreeSid(AdministratorsGroup);
	}

	return Ret;
}

//查看当前的 UAC 级别
BOOL CheckUAC()
{
	BOOL fIsElevated = FALSE;
	HANDLE hToken = NULL;

	if (OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&hToken))
	{
		TOKEN_ELEVATION elevation;
		DWORD dwSize;

		if (GetTokenInformation(hToken,TokenElevation,&elevation,sizeof(elevation),&dwSize))
		{
			fIsElevated = !elevation.TokenIsElevated;
		}

		CloseHandle(hToken);
	}

	return fIsElevated;
}

//当前进程是不是 WOW64 进程
BOOL CheckWow64()
{
	BOOL bIsWow64 = FALSE;
	typedef BOOL(WINAPI*LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
	LPFN_ISWOW64PROCESS fnIsWow64Process;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleA("kernel32.dll"),"IsWow64Process");
	if (NULL != fnIsWow64Process)
	{
		fnIsWow64Process(GetCurrentProcess(),&bIsWow64);
	}

	return bIsWow64;
}

VOID FixDWORD(BYTE *Data,DWORD Size,DWORD Old,DWORD New)
{
	DWORD p = 0;
	PDWORD pDD;

	while (p < Size)
	{
		pDD = (PDWORD)(Data + p);
		if (*pDD == Old) *(DWORD*)(Data + p) = New;

		p++;
	}
}

VOID HideDllPeb(LPCSTR lpDllName)
{
	PLDR_DATA_TABLE_ENTRY pldteDllEntry;
	PLIST_ENTRY pleCurrentDll;
	PLIST_ENTRY pleHeadDll;
	PPEB_LDR_DATA ppldLoaderData;
	PPEB ppPEB = (PPEB)__readfsdword(0x30);

	ppldLoaderData = ppPEB->Ldr;
	if (ppldLoaderData)
	{
		pleHeadDll = &ppldLoaderData->InLoadOrderModuleList;
		pleCurrentDll = pleHeadDll;
		while (pleCurrentDll && (pleHeadDll != (pleCurrentDll = pleCurrentDll->Flink)))
		{
			pldteDllEntry = CONTAINING_RECORD(pleCurrentDll,LDR_DATA_TABLE_ENTRY,InLoadOrderModuleList);			
			if (pldteDllEntry && pldteDllEntry->Flags & 0x00000004)
			{
				CHAR Buffer[MAX_PATH];
				ANSI_STRING as = RTL_CONSTANT_STRING(Buffer);

				RtlUnicodeStringToAnsiString(&as,&pldteDllEntry->BaseDllName,FALSE);
				if (StrStrIA(Buffer,lpDllName))
				{
					DbgPrint(__FUNCTION__"(): Dll '%s' removed from loader data\n",lpDllName);

					RemoveEntryList(&pldteDllEntry->InLoadOrderModuleList);
					RemoveEntryList(&pldteDllEntry->InInitializationOrderModuleList);
					RemoveEntryList(&pldteDllEntry->InMemoryOrderModuleList);
					RemoveEntryList(&pldteDllEntry->HashLinks);
				}
			}
		}
	}
}	

PVOID GetSystemInformation(SYSTEMINFOCLASS InfoClass)
{
	NTSTATUS St;
	PVOID Buffer;
	DWORD Size = 0x1000*4;
	DWORD t;

	do
	{
		Buffer = malloc(Size);
		if (!Buffer) return NULL;

		St = NtQuerySystemInformation(InfoClass,Buffer,Size,&t);
		if (!NT_SUCCESS(St)) 
		{
			free(Buffer);
			Buffer = NULL;
			Size += 0x1000*4;
		}
	}
	while (St == STATUS_INFO_LENGTH_MISMATCH);

	if (!NT_SUCCESS(St))
	{
		DbgPrint(__FUNCTION__"(): NtQuerySystemInformation failed with status %lx\n",St);
	}

	return Buffer;
}

DWORD CreateThreadAndWait(PVOID pvProc,PVOID pvContext,DWORD dwWait)
{
	DWORD dwExitCode = 0;

	HANDLE hThread = CreateThread(NULL,0,(LPTHREAD_START_ROUTINE)pvProc,pvContext,0,NULL);
	if (hThread)
	{
		if (WaitForSingleObject(hThread,dwWait) == WAIT_OBJECT_0)
		{
			GetExitCodeThread(hThread,&dwExitCode);
		}

		CloseHandle(hThread);
	}

	return dwExitCode;
}

PCHAR StrNCopy(PCHAR pcStr,DWORD dwLen)
{
	PCHAR pcResult = NULL;

	if (dwLen)
	{
		pcResult = (PCHAR)malloc(dwLen+1);
		if (pcResult)
		{
			RtlCopyMemory(pcResult,pcStr,dwLen);

			pcResult[dwLen] = 0;
		}
	}

	return pcResult;
}

PCHAR StrCopy(PCHAR pcStr)
{
	return StrNCopy(pcStr,strlen(pcStr));
}

DWORD FindStrInStr(PCHAR pcStr1,DWORD dwLen1,PCHAR pcStr2,DWORD dwLen2)
{
	if (dwLen1 >= dwLen2)
	{
		for (DWORD dwCnt = 0; dwCnt < dwLen1; dwCnt++)
		{
			for (DWORD dwPos1 = dwCnt,dwPos2 = 0; dwPos1 < dwLen1; dwPos1++)
			{
				if (tolower(pcStr1[dwPos1]) !=  tolower(pcStr2[dwPos2]))
				{
					break;
				}

				++dwPos2;
				if (dwPos2 == dwLen2) return dwPos1 - dwLen2 + 1;
			}
		}
	}

	return -1;
}

PCHAR GetStrValueStr(PCHAR pcBuffer,DWORD dwBufferLen,PCHAR pcStr,DWORD dwStrLen,PCHAR pcSep)
{
	DWORD dwLen;
	DWORD dwPos;

	dwPos = FindStrInStr(pcBuffer,dwBufferLen,pcStr,dwStrLen);
	if (dwPos != -1)
	{
		dwPos += dwStrLen;
		if (pcBuffer[dwPos] == ' ') ++dwPos;

		if (pcSep)
		{
			dwLen = FindStrInStr(pcBuffer+dwPos,dwBufferLen-dwPos,pcSep,strlen(pcSep));
			if (dwLen == -1) dwLen = 0;
		}
		else
		{
			dwLen = dwBufferLen - dwPos;
		}

		if (dwLen) return StrNCopy(pcBuffer + dwPos,dwLen);
	}

	return NULL;
}

unsigned long Crc32(const unsigned char * buf, unsigned long len)
{
	unsigned long crc_table[256];
	unsigned long crc;

	for (int i = 0; i < 256; i++)
	{
		crc = i;
		for (int j = 0; j < 8; j++)
			crc = crc & 1 ? (crc >> 1) ^ 0xEDB88320UL : crc >> 1;

		crc_table[i] = crc;
	};

	crc = 0xFFFFFFFFUL;

	while (len--) 
		crc = crc_table[(crc ^ *buf++) & 0xFF] ^ (crc >> 8);

	return crc ^ 0xFFFFFFFFUL;
}

static LONG DeleteRegKeyRecursive_q(HKEY RootKey,LPCSTR lpSubKey,LONG Level)
{
	HKEY hKey;

	if (ERROR_SUCCESS == RegOpenKeyExA(RootKey,lpSubKey,0,KEY_ALL_ACCESS,&hKey))
	{
		CHAR szSubKey[MAX_PATH];

		while (ERROR_SUCCESS == RegEnumKeyA(hKey,0,szSubKey,sizeof(szSubKey)))
		{
			if (ERROR_SUCCESS != DeleteRegKeyRecursive_q(hKey,szSubKey,Level+1)) break;
		}

		RegCloseKey(hKey);
	}

	return RegDeleteKeyA(RootKey,lpSubKey);
}

LONG DeleteRegKeyRecursive(HKEY RootKey,LPCSTR lpSubKey)
{
	return DeleteRegKeyRecursive_q(RootKey,lpSubKey,0);
}

BOOL ProcessRelocs(PVOID pvImageBase, DWORD dwDelta)
{
	DWORD dwRelocsSize;
	PIMAGE_BASE_RELOCATION pReloc;

	if (dwDelta)
	{
		pReloc = (PIMAGE_BASE_RELOCATION)RtlImageDirectoryEntryToData(pvImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &dwRelocsSize);
		if (pReloc && dwRelocsSize)
		{
			PIMAGE_BASE_RELOCATION pEndReloc = (PIMAGE_BASE_RELOCATION)(pReloc + dwRelocsSize);

			while (pReloc->SizeOfBlock && pReloc < pEndReloc)
			{
				pReloc = LdrProcessRelocationBlock(MAKE_PTR(pvImageBase, pReloc->VirtualAddress, ULONG_PTR), (pReloc->SizeOfBlock - sizeof(*pReloc))/sizeof(USHORT), (PUSHORT)(pReloc + 1), dwDelta);
				if (!pReloc) return FALSE;
			}
		}
	}

	return TRUE;
}

BOOLEAN ProcessImport(PVOID pvImageBase)
{
	DWORD dwImportSize;
	PIMAGE_IMPORT_DESCRIPTOR pImport;

	pImport = (PIMAGE_IMPORT_DESCRIPTOR)RtlImageDirectoryEntryToData(pvImageBase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &dwImportSize);
	if (pImport && dwImportSize)
	{
		for (; pImport->Name; pImport++)
		{
			PCHAR szDllName = RVA_TO_VA(pvImageBase, pImport->Name);
			HMODULE hDll = LoadLibraryA(szDllName);
			if (!hDll) return FALSE;

			PDWORD thunkRef, funcRef;

			if (pImport->OriginalFirstThunk)
			{
				thunkRef = MAKE_PTR(pvImageBase, pImport->OriginalFirstThunk, PDWORD); 
				funcRef = MAKE_PTR(pvImageBase, pImport->FirstThunk, PDWORD);
			}
			else
			{
				thunkRef = MAKE_PTR(pvImageBase, pImport->FirstThunk, PDWORD); 
				funcRef = MAKE_PTR(pvImageBase, pImport->FirstThunk , PDWORD);      
			}

			for (; *thunkRef; thunkRef++, funcRef++)
			{
				PVOID pvProcAddress;

				if (IMAGE_SNAP_BY_ORDINAL(*thunkRef))
				{
					pvProcAddress = GetProcAddress(hDll, (PCHAR)IMAGE_ORDINAL(*thunkRef));
				}
				else
				{
					pvProcAddress = GetProcAddress(hDll, (PCHAR)&((PIMAGE_IMPORT_BY_NAME)RVA_TO_VA(pvImageBase, *thunkRef))->Name);
				}
				if (!pvProcAddress) return FALSE;

				*(PVOID*)funcRef = pvProcAddress;
			}
		}
	}

	return TRUE;
}


const char *TakeOutStringByChar(const char *Source,char *Dest, int buflen, char ch)
{
    int i;

    if(Source == NULL)
        return NULL;

    const char *p = strchr(Source, ch);
    while(*Source == ' ')
        Source++;
    for(i=0; i<buflen && *(Source+i) && *(Source+i) != ch; i++)
    {
        Dest[i] = *(Source+i);
    }
    if(i == 0)
        return NULL;
    else
        Dest[i] = '\0';

    const char *lpret = p ? p+1 : Source+i;

    while(Dest[i-1] == ' ' && i>0)
        Dest[i---1] = '\0';

    return lpret;
}

char from_hex(char ch)
{
    return isdigit(ch) ? ch - '0' : tolower(ch) - 'a' + 10;
}

/* Converts an integer value to its hex character*/
char to_hex(char code) {
  static char hex[] = "0123456789abcdef";
  return hex[code & 15];
}

/* Returns a url-decoded version of str */
/* IMPORTANT: be sure to free() the returned string after use */
char *url_decode(char *str) {
  char *pstr = str, *buf = (char *)malloc(strlen(str) + 1), *pbuf = buf;
  while (*pstr) {
    if (*pstr == '%') {
      if (pstr[1] && pstr[2]) {
        *pbuf++ = from_hex(pstr[1]) << 4 | from_hex(pstr[2]);
        pstr += 2;
      }
    } else if (*pstr == '+') { 
      *pbuf++ = ' ';
    } else {
      *pbuf++ = *pstr;
    }
    pstr++;
  }
  *pbuf = '\0';
  return buf;
}



char* strtok_r(
    char *str, 
    const char *delim, 
    char **nextp)
{
    char *ret;

    if (str == NULL)
    {
        str = *nextp;
    }

    str += strspn(str, delim);

    if (*str == '\0')
    {
        return NULL;
    }

    ret = str;

    str += strcspn(str, delim);

    if (*str)
    {
        *str++ = '\0';
    }

    *nextp = str;

    return ret;
}

BOOL LoadImageFromMemory(PVOID pBuffer, PVOID *ppImage)
{
	BOOL Ret = FALSE;
	PIMAGE_NT_HEADERS pNtHeader;
	PVOID pImage;
	PIMAGE_SECTION_HEADER pSection;

	pNtHeader = RtlImageNtHeader(pBuffer);
	if (pNtHeader)
	{
		pImage = VirtualAlloc(NULL, pNtHeader->OptionalHeader.SizeOfImage, MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (pImage)
		{
			pSection = IMAGE_FIRST_SECTION(pNtHeader);
			RtlCopyMemory(pImage, pBuffer, pSection->PointerToRawData);

			for (WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; i++)
			{
				RtlCopyMemory(RVA_TO_VA(pImage,pSection[i].VirtualAddress), RVA_TO_VA(pBuffer,pSection[i].PointerToRawData), pSection[i].SizeOfRawData);
			}

			if (ProcessImport(pImage))
			{
				if (ProcessRelocs(pImage, VA_TO_RVA(pNtHeader->OptionalHeader.ImageBase, pImage)))
				{
					Ret = TRUE;
				}
			}

			if (Ret)
			{
				typedef BOOLEAN (WINAPI *PDLL_ENTRY_POINT)(PVOID, DWORD, DWORD);
				PDLL_ENTRY_POINT pDllEntryPoint = MAKE_PTR(pImage, pNtHeader->OptionalHeader.AddressOfEntryPoint, PDLL_ENTRY_POINT);

				if (!pDllEntryPoint(pImage, DLL_PROCESS_ATTACH, 0))
				{
					Ret = FALSE;
				}
				else
				{
					if (ppImage) *ppImage = pImage;
				}
			}

			if (!Ret) VirtualFree(pImage, 0, MEM_RELEASE);
		}
	}

	return Ret;
}

PVOID GetExportEntry(PVOID ModuleBase, LPCSTR lpProcName)
{
	PIMAGE_NT_HEADERS pNtHeaders;
	PIMAGE_EXPORT_DIRECTORY pImageExport;
	DWORD dwExportSize;

	pNtHeaders = (PIMAGE_NT_HEADERS)RtlImageNtHeader(ModuleBase);
	if (pNtHeaders)
	{
		pImageExport = (PIMAGE_EXPORT_DIRECTORY)RtlImageDirectoryEntryToData(ModuleBase,TRUE,IMAGE_DIRECTORY_ENTRY_EXPORT,&dwExportSize);
		if (pImageExport)
		{
			PDWORD pAddrOfNames = MAKE_PTR(ModuleBase, pImageExport->AddressOfNames, PDWORD);
			for (DWORD i = 0; i < pImageExport->NumberOfNames; i++)
			{
				if (!strcmp(RVA_TO_VA(ModuleBase, pAddrOfNames[i]), lpProcName))
				{
					PDWORD pAddrOfFunctions = MAKE_PTR(ModuleBase, pImageExport->AddressOfFunctions, PDWORD);
					PWORD pAddrOfOrdinals = MAKE_PTR(ModuleBase, pImageExport->AddressOfNameOrdinals, PWORD);

					return RVA_TO_VA(ModuleBase, pAddrOfFunctions[pAddrOfOrdinals[i]]);
				}
			}
		}
	}

	return NULL;
}