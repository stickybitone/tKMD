#include <Windows.h>
#include <string>
#include <vector>
#include <fileapi.h>

#define SystemHandleInformation 16
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004
#define STATUS_INVALID_HANDLE 0xc0000008
#define NTSTATUS LONG

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectBasicInformation = 0,
    ObjectTypeInformation = 2
} OBJECT_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct __PUBLIC_OBJECT_TYPE_INFORMATION {
    UNICODE_STRING TypeName;
    ULONG Reserved[22];    
} PUBLIC_OBJECT_TYPE_INFORMATION, * PPUBLIC_OBJECT_TYPE_INFORMATION;

typedef struct _PUBLIC_OBJECT_BASIC_INFORMATION {
    ULONG Attributes;
    ACCESS_MASK GrantedAccess;
    ULONG HandleCount;
    ULONG PointerCount;
    ULONG Reserved[10];    // reserved for internal use
} PUBLIC_OBJECT_BASIC_INFORMATION, * PPUBLIC_OBJECT_BASIC_INFORMATION;

typedef NTSTATUS(NTAPI* fNtQueryObject)
(
    HANDLE handle,
    OBJECT_INFORMATION_CLASS objectInformationClass,
    PVOID objectInformation,
    ULONG objectInformationLength,
    PULONG returnLength
);

typedef NTSTATUS(NTAPI* fNtDuplicateObject)
(
        HANDLE SourceProcessHandle,
        HANDLE SourceHandle,
        HANDLE TargetProcessHandle,
        PHANDLE TargetHandle,
        ACCESS_MASK DesiredAccess,
        ULONG HandleAttributes,
        ULONG Options
);

typedef NTSTATUS (NTAPI *fNtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT UniqueProcessId;
    USHORT CreatorBackTraceIndex;
    UCHAR ObjectTypeIndex;
    UCHAR HandleAttributes;
    USHORT HandleValue;
    PVOID Object;
    ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

BOOL listAllKernelObjectsViaHandles(DWORD pid)
{
    NTSTATUS status;
    ULONG handleInfoSize = 0x10000;

    PSYSTEM_HANDLE_INFORMATION handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
    fNtQuerySystemInformation NtQuerySystemInformation = (fNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQuerySystemInformation");
    while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
    {
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);
    }
    fNtQueryObject NtQueryObject = (fNtQueryObject)GetProcAddress(GetModuleHandle(L"ntdll"), "NtQueryObject");
    fNtDuplicateObject NtDuplicateObject = (fNtDuplicateObject)GetProcAddress(GetModuleHandle(L"ntdll"), "NtDuplicateObject");

    OBJECT_INFORMATION_CLASS objectInformationClass = ObjectTypeInformation;
    PPUBLIC_OBJECT_TYPE_INFORMATION objectTypeInformation;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO hi;
    HANDLE pHandle;
    HANDLE dupHandle;
    std::vector<std::wstring> accessRights; 
    std::wstring accessRightsAll;
    TCHAR path[MAX_PATH+1];
    path[MAX_PATH] = L'0';

    for (int i = 0; i < handleInfo->NumberOfHandles; i++)
    {
        hi = (SYSTEM_HANDLE_TABLE_ENTRY_INFO)handleInfo->Handles[i];
        if (hi.UniqueProcessId == pid)
        {
            pHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, hi.UniqueProcessId);
            NtDuplicateObject(pHandle, (HANDLE)hi.HandleValue, GetCurrentProcess(), &dupHandle, GENERIC_READ, 0, 0);
            objectTypeInformation = (PPUBLIC_OBJECT_TYPE_INFORMATION)malloc(0x1000);
            status = NtQueryObject((HANDLE)dupHandle, objectInformationClass, objectTypeInformation, 0x1000, NULL);
            if (status != STATUS_INVALID_HANDLE)
            {
                if (hi.GrantedAccess & READ_CONTROL)
                {
                    accessRights.push_back(L"READ_CONTROL");
                }
                if (hi.GrantedAccess & DELETE)
                {
                    accessRights.push_back(L"DELETE");
                }
                if (hi.GrantedAccess & WRITE_DAC)
                {
                    accessRights.push_back(L"WRITE_DAC");
                }
                if (hi.GrantedAccess & WRITE_OWNER)
                {
                    accessRights.push_back(L"WRITE_OWNER");
                }
                if (hi.GrantedAccess & SYNCHRONIZE)
                {
                    accessRights.push_back(L"SYNC");
                }
                if (hi.GrantedAccess & GENERIC_READ)
                {
                    accessRights.push_back(L"GENERIC_READ");
                }
                if (hi.GrantedAccess & GENERIC_WRITE)
                {
                    accessRights.push_back(L"GENERIC_WRITE");
                }
                if (hi.GrantedAccess & GENERIC_EXECUTE)
                {
                    accessRights.push_back(L"GENERIC_EXECUTE");
                }
                if (hi.GrantedAccess & GENERIC_ALL)
                {
                    accessRights.push_back(L"GENERIC_ALL");
                }
                if (hi.GrantedAccess & STANDARD_RIGHTS_REQUIRED)
                {
                    accessRights.push_back(L"STANDARD_RIGHTS_REQUIRED");
                }
                if (hi.GrantedAccess & STANDARD_RIGHTS_ALL)
                {
                    accessRights.push_back(L"STANDARD_RIGHTS_ALL");
                }
                if (hi.GrantedAccess & SPECIFIC_RIGHTS_ALL)
                {
                    accessRights.push_back(L"SPECIFIC_RIGHTS_ALL");
                }
                if (hi.GrantedAccess & ACCESS_SYSTEM_SECURITY)
                {
                    accessRights.push_back(L"ACCESS_SYSTEM_SECURITY");
                }
                if (hi.GrantedAccess & MAXIMUM_ALLOWED)
                {
                    accessRights.push_back(L"MAXIMUM_ALLOWED");
                }
            
                int len = accessRights.size();

                for (const std::wstring& s : accessRights)
                {
                    len--;
                    accessRightsAll += s;
                    if (len != 0)
                    {
                        accessRightsAll += L",";
                    }
                }
                
                GetFinalPathNameByHandleW(dupHandle, path, MAX_PATH, VOLUME_NAME_NT);
                std::wstring ws(path);
                wprintf(L"[+][%d] handle of type [%s] with access [%s]: 0x%x at 0x%p\n", hi.UniqueProcessId, objectTypeInformation->TypeName.Buffer, accessRightsAll.c_str(), hi.HandleValue, hi.Object);
                if (!std::wcscmp(objectTypeInformation->TypeName.Buffer, L"File"))
                {
                    wprintf(L"\t\tFILE:%s\n", ws.c_str()); 
                }
                accessRightsAll = L"";
                accessRights = {};
                memset(path, 0, MAX_PATH);
            }
            free(objectTypeInformation);
        }
    }
    free(handleInfo);
    
    return status;
}
