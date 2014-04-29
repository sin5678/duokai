#include <Windows.h>
#include "ntdll.h"
#include "utils.h"
#include "splice.h"

/*
拦截创建 mutex 让程序创建随机名称的 mutex 
拦截注册表异常 重定向矿鸡配置文件目录
*/

WCHAR g_DllPath[512];
WCHAR cfg_dir[512] = L"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

NTSTATUS __stdcall ZwQueryKey(
  _In_       HANDLE KeyHandle,
  _In_       KEY_INFORMATION_CLASS KeyInformationClass,
  _Out_opt_  PVOID KeyInformation,
  _In_       ULONG Length,
  _Out_      PULONG ResultLength
);

NTSTATUS __stdcall ZwQueryValueKey(
  _In_       HANDLE KeyHandle,
  _In_       PUNICODE_STRING ValueName,
  _In_       KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
  _Out_opt_  PVOID KeyValueInformation,
  _In_       ULONG Length,
  _Out_      PULONG ResultLength
);

typedef NTSTATUS (* P_NtCreateMutant)(
    OUT PHANDLE MutantHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN BOOLEAN InitialOwner
    );

typedef NTSTATUS (* P_ZwQueryKey)(
  _In_       HANDLE KeyHandle,
  _In_       KEY_INFORMATION_CLASS KeyInformationClass,
  _Out_opt_  PVOID KeyInformation,
  _In_       ULONG Length,
  _Out_      PULONG ResultLength
);

typedef NTSTATUS (* P_ZwQueryValueKey)(
  _In_       HANDLE KeyHandle,
  _In_       PUNICODE_STRING ValueName,
  _In_       KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
  _Out_opt_  PVOID KeyValueInformation,
  _In_       ULONG Length,
  _Out_      PULONG ResultLength
);

typedef LSTATUS (* P_RegQueryValueExW) (
    __in HKEY hKey,
    __in_opt LPCWSTR lpValueName,
    __reserved LPDWORD lpReserved,
    __out_opt LPDWORD lpType,
    __out_bcount_part_opt(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    __inout_opt LPDWORD lpcbData
    );

typedef NTSTATUS (* P_NtReleaseMutant)(
  IN HANDLE               MutantHandle,
  OUT PLONG               PreviousCount OPTIONAL );

typedef NTSTATUS (* P_NtResumeThread)(
    IN HANDLE	ThreadHandle,
    OUT PULONG	PreviousSuspendCount OPTIONAL
);

typedef struct _KEY_NAME_INFORMATION {
    ULONG   NameLength;
    WCHAR   Name[1];            // Variable length string
} KEY_NAME_INFORMATION, *PKEY_NAME_INFORMATION;

P_ZwQueryKey  pfZwQueryKey = NULL;
UCHAR  g_RealZwQueryKey[OLD_BYTES_SIZE];
UCHAR g_RealZwQueryValueKey[OLD_BYTES_SIZE];
UCHAR g_RealRegQueryValueExW[OLD_BYTES_SIZE];
UCHAR g_RealNtResumeThread[OLD_BYTES_SIZE];
UCHAR g_RealNtCreateMutant[OLD_BYTES_SIZE];

NTSTATUS __stdcall HOOK_ZwQueryKey(
  _In_       HANDLE KeyHandle,
  _In_       KEY_INFORMATION_CLASS KeyInformationClass,
  _Out_opt_  PVOID KeyInformation,
  _In_       ULONG Length,
  _Out_      PULONG ResultLength
)
{
    NTSTATUS status = ((P_ZwQueryKey)&g_RealZwQueryKey[0])(KeyHandle,
        KeyInformationClass,
        KeyInformation,
        Length,
        ResultLength);
    if(0 == status)
    {

    }
    return status;
}

//返回的 WCHAR 要以 av_Free 释放掉 
WCHAR *av_UnicodeStringToWchar(PUNICODE_STRING string)
{
    WCHAR *str = (WCHAR *)malloc(string->Length + sizeof(WCHAR));
    wcsncpy(str, string->Buffer, string->Length / 2); 
    str[string->Length / 2] = 0; // wcsncpy 不会在后面补上  0
    return str;
}

LPWSTR GetObjectNameFromHandle(HANDLE hObject)
{
    WCHAR * fileName = NULL;
    ULONG returnedLength; 
    NTSTATUS status;
    OBJECT_NAME_INFORMATION *ni = NULL;  //<-- 以后用指针别忘了 初始化 

    status = NtQueryObject(hObject, 
        ObjectNameInformation,
        ni, 
        0, 
        &returnedLength);
    if(STATUS_INFO_LENGTH_MISMATCH == status)
    {
        int i;
        for (i = 0 ;i< 1;i++)//try 10 times
        {
            returnedLength += 1024;
            ni = (OBJECT_NAME_INFORMATION *)malloc(returnedLength);
            status = NtQueryObject(hObject,ObjectNameInformation,ni,returnedLength,&returnedLength);
            if(STATUS_SUCCESS == status)
            {
                fileName = av_UnicodeStringToWchar(&ni->Name);
                if(fileName)
                {
                    dbg_msg("Get Object : %S ",fileName);
                }
                free(ni);
                ni = NULL;
                break;
            }
            if(STATUS_INFO_LENGTH_MISMATCH == status)
            {
                free(ni);
                ni = NULL;
            }
            else
                break;
        }
        if(ni)
        {
            //10 次都不行。、。。。
            free(ni);
            ni = NULL;
            return NULL; //直接返回了。。 
        }
    }
    else
    {
        dbg_msg("failed !! return status 0x%08X ",status);
    }
    return fileName;
}

/*
通过注册表项的 句柄 得到其名称 
*/
WCHAR *GetKeyNameByHandle(HKEY hKey)
{
    WCHAR *Name = NULL;
    NTSTATUS status;
    ULONG len = 0x1000;
    KEY_NAME_INFORMATION *ki = (KEY_NAME_INFORMATION *)malloc(len);
    if(!ki)
        return NULL;
    if(STATUS_SUCCESS != (status = pfZwQueryKey(hKey,KeyNameInformation,ki,len,&len)))
    {
        if(status == STATUS_BUFFER_OVERFLOW || status == STATUS_BUFFER_TOO_SMALL)
        {
            free(ki);
            len += 1024;
            ki = (KEY_NAME_INFORMATION *)malloc(len);
            if(ki)
            { 
                if(STATUS_SUCCESS != (status = pfZwQueryKey(hKey,KeyNameInformation,ki,len,&len)))
                {

                }
            }
        }
    }

    if(status == STATUS_SUCCESS)
    {
        Name = (WCHAR *)malloc(ki->NameLength + sizeof(WCHAR));
        if(Name)
        {
            wcsncpy(Name,ki->Name,ki->NameLength / 2);
            Name[ki->NameLength / sizeof(WCHAR)] =  0;
        }
    }
    free(ki);
    return Name;
}

NTSTATUS HOOK_NtCreateMutant(
    OUT PHANDLE MutantHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    IN BOOLEAN InitialOwner
    )
{
    dbg_msg("call HOOK_NtCreateMutant \n");
    if(ObjectAttributes && ObjectAttributes->pObjectName)
    {
        dbg_msg("create mutant : %wZ \n",ObjectAttributes->pObjectName);

        UNICODE_STRING str;
        RtlInitUnicodeString(&str,L"\\BaseNamedObjects\\QVOD_MINER");
        if(RtlEqualUnicodeString(&str,ObjectAttributes->pObjectName,TRUE))
        {
            RtlInitUnicodeString(ObjectAttributes->pObjectName,L"\\BaseNamedObjects\\sincoder");
        }
    }
    return ((P_NtCreateMutant)&g_RealNtCreateMutant[0])(MutantHandle,DesiredAccess,ObjectAttributes,InitialOwner);
}

LSTATUS HOOK_RegQueryValueExW (
    __in HKEY hKey,
    __in_opt LPCWSTR lpValueName,
    __reserved LPDWORD lpReserved,
    __out_opt LPDWORD lpType,
    __out_bcount_part_opt(*lpcbData, *lpcbData) __out_data_source(REGISTRY) LPBYTE lpData,
    __inout_opt LPDWORD lpcbData
    )
{
    LSTATUS status = ((P_RegQueryValueExW)&g_RealRegQueryValueExW[0])(hKey,lpValueName,lpReserved,lpType,lpData,lpcbData);
    if(ERROR_SUCCESS == status)
    {
        if(lpData && lpcbData)
        {
            DWORD len = *lpcbData + 2;
            WCHAR *str = (WCHAR *)malloc(len);
            if(str)
            {
                ZeroMemory(str,len + 2);
                memcpy(str,lpData,len);
                OutputDebugStringW(str);
                free(str);
            }
        }
    }
    return status;
}

//HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\ProgramData

NTSTATUS HOOK_ZwQueryValueKey(
  _In_       HANDLE KeyHandle,
  _In_       PUNICODE_STRING ValueName,
  _In_       KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
  _Out_opt_  PVOID KeyValueInformation,
  _In_       ULONG Length,
  _Out_      PULONG ResultLength
)
{
    NTSTATUS status = ((P_ZwQueryValueKey)&g_RealZwQueryValueKey[0])(
        KeyHandle,
        ValueName,
        KeyValueInformationClass,
        KeyValueInformation,
        Length,
        ResultLength);

    if(NT_SUCCESS(status) && (KeyValueInformationClass == KeyValuePartialInformation) )
    {
        KEY_VALUE_PARTIAL_INFORMATION  *ki = (KEY_VALUE_PARTIAL_INFORMATION  *)KeyValueInformation;
        WCHAR *KeyName = GetKeyNameByHandle((HKEY)KeyHandle);
        if(KeyName)
        {
			if(_wcsicmp(KeyName,
				L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders") == 0 
			)
			{
				UNICODE_STRING str;
				RtlInitUnicodeString(&str,L"Common AppData");
				if(RtlEqualUnicodeString(&str,ValueName,TRUE))
				{
                    dbg_msg("Hit key Common AppData \n");
					DWORD len = 2 * (wcslen(cfg_dir) + 1) + sizeof(KEY_VALUE_PARTIAL_INFORMATION);
					if(len <= Length)
					{
						KEY_VALUE_PARTIAL_INFORMATION *p = (KEY_VALUE_PARTIAL_INFORMATION *)KeyValueInformation;
						//p->TitleIndex = ki->TitleIndex;
						//p->Type = ki->Type;
						p->DataLength = 2 * (wcslen(cfg_dir) + 1);
						memcpy(p->Data,cfg_dir,p->DataLength);
					}
					else
					{
						status = STATUS_BUFFER_TOO_SMALL;
					}
					if(ResultLength)
					{
						*ResultLength = len;
					}
				}
			}
            else if(0 == _wcsicmp(KeyName,L"\\REGISTRY\\MACHINE\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList"))
            {
                //  windows 7 上面看的是这个注册表键
                UNICODE_STRING str;
				RtlInitUnicodeString(&str,L"ProgramData");
				if(RtlEqualUnicodeString(&str,ValueName,TRUE))
				{
                    dbg_msg("Hit key ProgramData \n");
					DWORD len = 2 * (wcslen(cfg_dir) + 1) + sizeof(KEY_VALUE_PARTIAL_INFORMATION);
					if(len <= Length)
					{
						KEY_VALUE_PARTIAL_INFORMATION *p = (KEY_VALUE_PARTIAL_INFORMATION *)KeyValueInformation;
						//p->TitleIndex = ki->TitleIndex;
						//p->Type = ki->Type;
						p->DataLength = 2 * (wcslen(cfg_dir) + 1);
						memcpy(p->Data,cfg_dir,p->DataLength);
					}
					else
					{
						status = STATUS_BUFFER_TOO_SMALL;
					}
					if(ResultLength)
					{
						*ResultLength = len;
					}
                }
            }
            free(KeyName);
        }
    }
    return status;
}

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
    PVOID Reserved2[3];
    HANDLE UniqueProcessId;
    PVOID Reserved3;
    ULONG HandleCount;
    BYTE Reserved4[4];
    PVOID Reserved5[11];
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION;

INT GetProcessThreadCount(HANDLE hProcessId)
{
    INT Ret = -1;
    PVOID SysInfo;
    ULONG Size = 0x1000;
    NTSTATUS St;
    SYSTEM_PROCESS_INFORMATION* pProcess;
    do
    {
        SysInfo = malloc(Size);
        if (!SysInfo) 
            return Ret;
        St = NtQuerySystemInformation(SystemProcessInformation, SysInfo, Size, NULL);
        if (St == STATUS_INFO_LENGTH_MISMATCH)
        {
            free(SysInfo);
            Size *= 2;
        }
        else if (!NT_SUCCESS(St))
        {
            free(SysInfo);
            return Ret;
        }
    }while (St == STATUS_INFO_LENGTH_MISMATCH);

    pProcess = (SYSTEM_PROCESS_INFORMATION *)SysInfo;
    for (;;) 
    {
        if (pProcess->UniqueProcessId == hProcessId)
        {
            Ret = pProcess->NumberOfThreads;
            break;
        }
        if (!pProcess->NextEntryOffset) 
            break;
        pProcess = (SYSTEM_PROCESS_INFORMATION *)((PUCHAR)pProcess + pProcess->NextEntryOffset);
    }
    free(SysInfo);
    return Ret;
}

typedef struct _THREAD_TIMES_INFORMATION {
    LARGE_INTEGER           CreationTime;
    LARGE_INTEGER           ExitTime;
    LARGE_INTEGER           KernelTime;
    LARGE_INTEGER           UserTime;
} THREAD_TIMES_INFORMATION, *PTHREAD_TIMES_INFORMATION;

//HOOK 子进程。。
NTSTATUS  HOOK_NtResumeThread(
    IN HANDLE	ThreadHandle,
    OUT PULONG	PreviousSuspendCount OPTIONAL
)
{
	//判断下这个线程是不是在新启动的进程当中。。。
	THREAD_BASIC_INFORMATION  ti;
    if(STATUS_SUCCESS == NtQueryInformationThread(ThreadHandle,
        ThreadBasicInformation,
        &ti,
        sizeof(THREAD_BASIC_INFORMATION),
        NULL))
    {
		DWORD pid = (DWORD)ti.ClientId.UniqueProcess;
        if(pid > 0 && pid != (DWORD)-1)
        {
            //在看看远程进程是不是正在启动
            HANDLE process_handle;
            NTSTATUS status;
            CLIENT_ID client;
            OBJECT_ATTRIBUTES objectAttributes;
            client.UniqueProcess = (HANDLE)pid;
            client.UniqueThread = NULL;
            InitializeObjectAttributes(&objectAttributes, NULL, 0, NULL, NULL);
            status = NtOpenProcess(&process_handle,
				PROCESS_ALL_ACCESS,
                &objectAttributes,
				&client);
			if(NT_SUCCESS(status))
            {
				DWORD pid = GetProcessId(process_handle);
				if(pid)
				{
					if(1 == GetProcessThreadCount((HANDLE)pid))
					{
						//看看这个一个线程的 usertime 是不是 0 
						THREAD_TIMES_INFORMATION  ti;
						if(STATUS_SUCCESS == NtQueryInformationThread(ThreadHandle,
							ThreadTimes,
							&ti,
							sizeof(THREAD_TIMES_INFORMATION),
							NULL))
						{
							if(ti.UserTime.QuadPart == 0)
							{
								OutputDebugStringA("start inject ...");
								//好的 这个应该是个新启动的进程了。。。
								//注入 DLL 到这个进程中 
								DWORD bytes;
								LPVOID addr = VirtualAllocEx(process_handle,
									NULL,
									wcslen(g_DllPath) * 3,
									MEM_RESERVE | MEM_COMMIT ,
									PAGE_EXECUTE_READWRITE);
								WriteProcessMemory(process_handle,
									addr,
									g_DllPath,(wcslen(g_DllPath) + 1) * sizeof(WCHAR),&bytes);
								HANDLE hThread = CreateRemoteThread(process_handle,
									NULL,
									0,
									(LPTHREAD_START_ROUTINE)LoadLibraryW,addr,0,NULL);
								if(hThread)
								{
									WaitForSingleObject(hThread,INFINITE);
								}
								else
								{
									OutputDebugStringA("craete remote thread error");
									//TerminateProcess(process_handle,-1);
								}
							}
						}
					}
				}
				NtClose(process_handle);
			}
		}
	}
	return ((P_NtResumeThread)&g_RealNtResumeThread[0])(ThreadHandle,PreviousSuspendCount);
}

//
DWORD CloseQvodMutantThread(LPVOID p)
{
    //关闭 互斥体 
    dbg_msg("thread start ...");
    while(1)
    {
        ULONG h = 0x0;
        for (h = 0; h < 0xFFFF; h++)
        {
            WCHAR *name = GetObjectNameFromHandle((HANDLE)h);
            if(name)
            {
                dbg_msg("get handle %S ",name);
                if(wcsstr(name,L"QVOD_MINER"))
                {
                    NtClose((HANDLE)h);
                }
                free(name);
                Sleep(1);
             }
        }
        /*
        HANDLE hMutant = NULL;
        OBJECT_ATTRIBUTES ob;
        UNICODE_STRING us;
        RtlInitUnicodeString(&us,L"\\BaseNamedObjects\\QVOD_MINER");
        InitializeObjectAttributes(&ob,&us,0,NULL,NULL);

        if(NT_SUCCESS(NtOpenMutant(&hMutant,MUTANT_ALL_ACCESS,&ob)))
        {
            dbg_msg("success open qvod  mutant \n");

            P_NtReleaseMutant pNtReleaseMutant = 
                (P_NtReleaseMutant)GetProcAddress(LoadLibraryA("ntdll.dll"),"NtReleaseMutant");
            if(pNtReleaseMutant)
            {
                LONG c;
                do
                {
                    pNtReleaseMutant(hMutant,&c);
                }while(c > 1);
            }
            else
            {
                dbg_msg("do not get NtReleaseMutant addr \n");
            }

            NtClose(hMutant);
        }
        else
        {
            dbg_msg("open mutant failed \n");
        }
        */
        Sleep(10000);
    }
    return 0;
}

BOOL WINAPI DllMain(
  _In_  HINSTANCE hinstDLL,
  _In_  DWORD fdwReason,
  _In_  LPVOID lpvReserved
)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        {
			OutputDebugStringA("get config ");
			OutputDebugStringW(cfg_dir);
			GetModuleFileNameW(hinstDLL,g_DllPath,sizeof(g_DllPath)/2);
            pfZwQueryKey = (P_ZwQueryKey)GetProcAddress(LoadLibraryA("ntdll.dll"),"NtQueryKey");
            DisableThreadLibraryCalls(hinstDLL);
            Splice(GetProcAddress(LoadLibraryA("ntdll.dll"),"NtQueryValueKey"),HOOK_ZwQueryValueKey,g_RealZwQueryValueKey);
			Splice(GetProcAddress(LoadLibraryA("ntdll.dll"),"NtResumeThread"),HOOK_NtResumeThread,g_RealNtResumeThread);
            Splice(GetProcAddress(LoadLibraryA("ntdll.dll"),"NtCreateMutant"),HOOK_NtCreateMutant,g_RealNtCreateMutant);

            CreateThread(NULL,0,CloseQvodMutantThread,NULL,0,NULL);
		   //	Splice(GetProcAddress(LoadLibraryA("advapi32.dll"),"RegQueryValueExW"),HOOK_RegQueryValueExW,g_RealRegQueryValueExW);
        }
        break;
    default:
        break;
    }
    dbg_msg("exit dllmain \n");
    return TRUE;
}