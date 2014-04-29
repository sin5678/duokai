//负责注入 DLL ，
#include <Windows.h>
#include <stdio.h>


/*
字符串连接函数 
@d 目标字符串
@s 源字符串
@n 目标最大可以保存的字符串数量 包括末尾的 \0
@return 返回连接后的字符串
*/
__forceinline WCHAR *av_wcsncat(WCHAR *d, const WCHAR *s,int n)
{
	int i = 0;
	for(i = wcslen(d);i < n - 1 && *s;i++,s++)
	{
		d[i] = *s;
	}
	d[i] = 0;
	return d;
}

/*
字符串复制函数
@d 目标内存
@s 源字符串
@n 目标内存中可以存放的最多字符数量 保护末尾的 \0
@return 返回 d
*/
__forceinline WCHAR *av_wcsncpy(WCHAR *d , const WCHAR *s , int n)
{
	int i = 0;
	for(i = 0;i < n - 1 && *s;i++,s++)
	{
		d[i] = *s;
	}
	d[i] = 0;
	return d;
}

/*
将字符串中的第一个 \\ 变成\
@str 输入的字符串
@return 成功返回 1  失败返回 0
*/
int clean_backslash2(WCHAR  *str)
{
	WCHAR *p;
	while(*str)
	{
		if(*str == '\\' && *(str+1) == '\\')
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

/*
将字符串中所有的 \\ 变成 \
@str 输入字符串
*/
void clean_backslash(WCHAR  *str)
{
	while(clean_backslash2(str));
}


int memfind(const char *mem, /*要查找内存块的起始地址*/
			const char *str, /*要在其中查找的字符串或者xxx*/
			int sizem, /*内存块的大小*/
			int sizes/*要查找的字符串的大小*/
			)   
{   
	int   da,i,j;   
	if (sizes == 0) 
		da = strlen(str);   /*如果sizes为0 则认为 str 表示的是字符串*/
	else 
		da = sizes;   
	for (i = 0; i <= sizem - da; i++)   
	{   
		for (j = 0; j < da; j ++)   
			if (mem[i+j] != str[j])	
				break;   
		if (j == da) 
			return i;   /*找到了 返回其在内存中的偏移*/
	}   
	return -1;   
}

BOOL WriteCfg2DllFile(WCHAR *dllName,WCHAR *cfg)
{
	BOOLEAN ret = FALSE;
	HANDLE hfile = CreateFileW(dllName,GENERIC_WRITE | GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);
	if(hfile == INVALID_HANDLE_VALUE)
	{
		printf("open dll file error %d \n",GetLastError());
		return FALSE;
	}

	DWORD fsize = GetFileSize(hfile,NULL);
	UCHAR *buff = (UCHAR *)malloc(fsize);
	DWORD bytes = 0;
	ReadFile(hfile,buff,fsize,&bytes,NULL);

	int offset ;
	WCHAR *flag = L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	if(( offset = memfind((CONST CHAR *)buff,(const char *)flag,fsize,wcslen(flag) * 2)))
	{
		av_wcsncpy((WCHAR *)(buff + offset),cfg,500);
		SetFilePointer(hfile,0,NULL,FILE_BEGIN);
		WriteFile(hfile,buff,fsize,&bytes,NULL);
		ret = TRUE;
	}
	CloseHandle(hfile);
	return ret;
}

int wmain(int argc, WCHAR **argv)
{
	if(argc < 3)
	{
		printf("Usage: %S  <miner path> <cfg dir> \n",argv[0]);
		return 0;
	}

	WCHAR *MinerPath = argv[1];
	WCHAR *CfgPath = argv[2];

	if(wcslen(CfgPath) > 500)
	{
		printf("cfg path too long \n");
		return -1;
	}

	if(!SetCurrentDirectoryW(CfgPath))
	{
		printf("切换目录失败 ，确定文件是否存在 \n");
		return -1;
	}

	//复制一份 DLL 

	SetFileAttributes(L"xx.dll",FILE_ATTRIBUTE_NORMAL);
	DeleteFile(L"xx.dll");
	CopyFileW(L"Hook.dll",L"xx.dll",FALSE);
	SetFileAttributes(L"xx.dll",FILE_ATTRIBUTE_NORMAL);
	STARTUPINFOW si;
	ZeroMemory(&si,sizeof(STARTUPINFOW));
	si.cb = sizeof(STARTUPINFOW);
	PROCESS_INFORMATION pi;
	if(CreateProcessW(NULL,MinerPath,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&si,&pi))
	{
		HANDLE hThread;
		DWORD bytes = 0;
		WCHAR dllPath[512];
		av_wcsncpy(dllPath,CfgPath,sizeof(dllPath));
		av_wcsncat(dllPath,L"\\xx.dll",sizeof(dllPath));
		clean_backslash(dllPath);
		printf("use dll file %S \n",dllPath);
		if(WriteCfg2DllFile(dllPath,CfgPath))
		{
			LPVOID addr = VirtualAllocEx(pi.hProcess,NULL,wcslen(dllPath) * 3,MEM_RESERVE | MEM_COMMIT ,PAGE_EXECUTE_READWRITE);
			WriteProcessMemory(pi.hProcess,addr,dllPath,(wcslen(dllPath) + 1) * sizeof(WCHAR),&bytes);
			hThread = CreateRemoteThread(pi.hProcess,NULL,0,(LPTHREAD_START_ROUTINE)LoadLibraryW,addr,0,NULL);
			if(hThread)
			{
				WaitForSingleObject(hThread,INFINITE);
				ResumeThread(pi.hThread);
			}
			else
			{
				printf("craete remote thread error \n");
				TerminateProcess(pi.hProcess,-1);
			}
		}
		else
		{
			printf("write dll file error \n");
			TerminateProcess(pi.hProcess,-1);
		}
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}
	else
	{
		printf("create process failed \n");
	}
	return 0;
}