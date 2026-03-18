#pragma once
#define METHOD_NEITHER                  3
#define FILE_ANY_ACCESS                 0
#define CTL_CODE( DeviceType, Function, Method, Access ) (                 \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) \
)

#define tKMD_DEVICE 0x8000

#define IOCTL_CALLBACK_PROCESS CTL_CODE(tKMD_DEVICE, 0x800, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_CALLBACK_THREAD CTL_CODE(tKMD_DEVICE, 0x801, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_CALLBACK_IMAGE CTL_CODE(tKMD_DEVICE, 0x802, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_LIST_MODULES CTL_CODE(tKMD_DEVICE, 0x803, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_CALLBACK_REMOVE CTL_CODE(tKMD_DEVICE, 0x804, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_WINDOWS_VERSION CTL_CODE(tKMD_DEVICE, 0x805, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_REMOVE_PS_PROTECTION CTL_CODE(tKMD_DEVICE, 0x806, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_SUPPORTED_VERSION CTL_CODE(tKMD_DEVICE, 0x807, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_SET_FULL_PRIVS_ON_KERNEL_OBJECT CTL_CODE(tKMD_DEVICE, 0x808, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_BORROW_TOKEN CTL_CODE(tKMD_DEVICE, 0x80a, METHOD_NEITHER, FILE_ANY_ACCESS)
#define IOCTL_LIST_ETW CTL_CODE(tKMD_DEVICE, 0x80b, METHOD_NEITHER, FILE_ANY_ACCESS)

typedef struct _MODULE_NAMES
{
    CHAR Name[256];
} MODULE_NAMES, * PMODULE_NAMES;

typedef struct _CALLBACK_INFO
{
    ULONG64 Address;
    CHAR Module[256];
} CALLBACK_INFO, *PCALLBACK_INFO;

typedef struct _TARGET_CALLBACK
{
    unsigned long long Address;
} TARGET_CALLBACK, * PTARGET_CALLBACK;

typedef struct _WINDOWS_VERSION
{
    ULONG MajorVersion;
    ULONG MinorVersion;
    ULONG BuildNumber;
} WINDOWS_VERSION, * PWINDOWS_VERSION;

typedef struct _PS_PROTECTION 
{
    UCHAR Level;
    UCHAR Type : 3;
    UCHAR Audit : 1;
    UCHAR Signer : 4;
} PS_PROTECTION, * PPS_PROTECTION;

typedef struct _TARGET_PROCESS
{
    int ProcessId;
} TARGET_PROCESS, * PTARGET_PROCESS;

typedef struct _TARGET_HANDLE
{
    int ProcessId;
    int handle;
} TARGET_HANDLE, * PTARGET_HANDLE;

typedef struct _TOKENX
{
    int borrowerPID;
    int lenderPID;
} TOKENX, * PTOKENX;

typedef struct _OFFSET
{
    ULONG PROCESS_NOTIFY_OFFSET;
    ULONG THREAD_NOTIFY_OFFSET;
    ULONG IMAGE_NOTIFY_OFFSET;
    ULONG PS_PROTECTION_OFFSET;
} OFFSET, * POFFSET;

//START ETW 

typedef struct _ETW
{
    DWORD64 EtwpDebuggerDataAddr;
    DWORD64 * SiloDriverState;
    ULONG numberOfEnabledETWs;
} ETW, * PETW;

typedef struct _ETW_GUID
{
    _GUID guid;
} ETW_GUID, * PETW_GUID;

struct _EX_PUSH_LOCK
{
    union
    {
        struct
        {
            ULONGLONG Locked : 1;                                             //0x0
            ULONGLONG Waiting : 1;                                            //0x0
            ULONGLONG Waking : 1;                                             //0x0
            ULONGLONG MultipleShared : 1;                                     //0x0
            ULONGLONG Shared : 60;                                            //0x0
        } explstruct;
        ULONGLONG Value;                                                    //0x0
        VOID* Ptr;                                                          //0x0
    };
};

struct _ETW_HASH_BUCKET
{
    struct _LIST_ENTRY ListHead[3];                                         //0x0
    struct _EX_PUSH_LOCK BucketLock;                                        //0x30
};

struct _ETW_LAST_ENABLE_INFO
{
    union _LARGE_INTEGER EnableFlags;                                       //0x0
    USHORT LoggerId;                                                        //0x8
    UCHAR Level;                                                            //0xa
    UCHAR Enabled : 1;                                                        //0xb
    UCHAR InternalFlag : 7;                                                   //0xb
};

struct _TRACE_ENABLE_INFO
{
    ULONG IsEnabled;                                                        //0x0
    UCHAR Level;                                                            //0x4
    UCHAR Reserved1;                                                        //0x5
    USHORT LoggerId;                                                        //0x6
    ULONG EnableProperty;                                                   //0x8
    ULONG Reserved2;                                                        //0xc
    ULONGLONG MatchAnyKeyword;                                              //0x10
    ULONGLONG MatchAllKeyword;                                              //0x18
};

struct _ETW_GUID_ENTRY
{
    struct _LIST_ENTRY GuidList;                                            //0x0
    struct _LIST_ENTRY SiloGuidList;                                        //0x10
    volatile LONGLONG RefCount;                                             //0x20
    struct _GUID Guid;                                                      //0x28
    struct _LIST_ENTRY RegListHead;                                         //0x38
    VOID* SecurityDescriptor;                                               //0x48
    union
    {
        struct _ETW_LAST_ENABLE_INFO LastEnable;                            //0x50
        ULONGLONG MatchId;                                                  //0x50
    };
    struct _TRACE_ENABLE_INFO ProviderEnableInfo;                           //0x60
    struct _TRACE_ENABLE_INFO EnableInfo[8];                                //0x80
    struct _ETW_FILTER_HEADER* FilterData;                                  //0x180
    struct _ETW_SILODRIVERSTATE* SiloState;                                 //0x188
    struct _ETW_GUID_ENTRY* HostEntry;                                      //0x190
    struct _EX_PUSH_LOCK Lock;                                              //0x198
    struct _ETHREAD* LockOwner;                                             //0x1a0
};

//END ETW