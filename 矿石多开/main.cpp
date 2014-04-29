//����ע�� DLL ��
#include <Windows.h>
#include <stdio.h>


/*
�ַ������Ӻ��� 
@d Ŀ���ַ���
@s Դ�ַ���
@n Ŀ�������Ա�����ַ������� ����ĩβ�� \0
@return �������Ӻ���ַ���
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
�ַ������ƺ���
@d Ŀ���ڴ�
@s Դ�ַ���
@n Ŀ���ڴ��п��Դ�ŵ�����ַ����� ����ĩβ�� \0
@return ���� d
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
���ַ����еĵ�һ�� \\ ���\
@str ������ַ���
@return �ɹ����� 1  ʧ�ܷ��� 0
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
���ַ��������е� \\ ��� \
@str �����ַ���
*/
void clean_backslash(WCHAR  *str)
{
	while(clean_backslash2(str));
}


int memfind(const char *mem, /*Ҫ�����ڴ�����ʼ��ַ*/
			const char *str, /*Ҫ�����в��ҵ��ַ�������xxx*/
			int sizem, /*�ڴ��Ĵ�С*/
			int sizes/*Ҫ���ҵ��ַ����Ĵ�С*/
			)   
{   
	int   da,i,j;   
	if (sizes == 0) 
		da = strlen(str);   /*���sizesΪ0 ����Ϊ str ��ʾ�����ַ���*/
	else 
		da = sizes;   
	for (i = 0; i <= sizem - da; i++)   
	{   
		for (j = 0; j < da; j ++)   
			if (mem[i+j] != str[j])	
				break;   
		if (j == da) 
			return i;   /*�ҵ��� ���������ڴ��е�ƫ��*/
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
		printf("�л�Ŀ¼ʧ�� ��ȷ���ļ��Ƿ���� \n");
		return -1;
	}

	//����һ�� DLL 

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