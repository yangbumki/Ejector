#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

#define BUFSIZE		1024

typedef class EJECTOR{
private:
	TCHAR processName[BUFSIZE] = { 0, };
	TCHAR exeName[BUFSIZE] = { 0, };
	HANDLE snapShot = NULL;
	PROCESSENTRY32 pe32;

	MODULEENTRY32 me32;
	
	HANDLE tokenHandle = NULL;
	LUID luid;
	TOKEN_PRIVILEGES tokenPriv;

	HANDLE processHandle = NULL, remoteThreadHandle = NULL;
	LPTHREAD_START_ROUTINE remoteEjectFunc = NULL;


	void SetProcessTitle(const TCHAR* title) {
		memset(processName, 0, BUFSIZE);
		wcscpy_s(processName, title);
	};

	void SetExeName(const TCHAR* name) {
		memset(this->exeName, 0, BUFSIZE);
		wcscpy_s(this->exeName, name);
	};

	void WarningMessage(const char* msg) {
		printf_s("%s", msg);
	};

	void ErrorMessage(const char* msg) {
		MessageBoxA(NULL, msg, "ERROR", NULL);
		exit(-1);
	};

public:
	EJECTOR() {
		
	};
	~EJECTOR() {
		CloseHandle(snapShot);
		CloseHandle(tokenHandle);
		CloseHandle(processHandle);
		CloseHandle(remoteThreadHandle);
	};

	void SetProcessName(const TCHAR* name) {
		memset(this->exeName, 0, BUFSIZE);
		wcscpy_s(this->exeName, name);
	};

	BOOL FindPID(const TCHAR* name) {
		SetProcessName(name);

		if (snapShot != NULL) WarningMessage("SnapShot is not invalid\n");

		snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPALL,NULL);
		if (snapShot == NULL) ErrorMessage("CreateToolhelp32Snapshot()");

		memset(&pe32, 0, sizeof(PROCESSENTRY32));
		pe32.dwSize = sizeof(PROCESSENTRY32);

		Process32First(snapShot, &pe32);
		TCHAR* temp = NULL;
		int result = 0;
		do {
			if (snapShot == NULL) {
				WarningMessage("Process is not found\n");
				return false;
			};

			temp = pe32.szExeFile;
			//wprintf_s(L"%s\n", pe32.szExeFile);
			result = wcscmp(pe32.szExeFile, this->exeName);
			//printf("%d \n", result);
			if (result == 0) break;
		} while (Process32Next(snapShot, &pe32));

		return TRUE;
	};

	BOOL SetDebugPrivileges() {
		if (tokenHandle != NULL) WarningMessage("Token is not invalid\n");
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &tokenHandle)) ErrorMessage("OpenprocessToken()");
		if(!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) ErrorMessage("LookupPrivilegeValue()");

		tokenPriv.PrivilegeCount = 1;
		tokenPriv.Privileges[0].Luid = luid;
		tokenPriv.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (!AdjustTokenPrivileges(tokenHandle, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) ErrorMessage("AdjustTokenPrivileges()");
		if (!GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
			WarningMessage("The toke doest not have the specified privilege. \n"); return false;
		};

		return true;
	};

	BOOL FindDLL(const TCHAR* dllName) {
		if (snapShot == NULL) {
			WarningMessage("snapshot is availed\n");
			return false;
		};

		snapShot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, this->pe32.th32ProcessID);
		memset(&me32, 0, sizeof(MODULEENTRY32));
		me32.dwSize = sizeof(MODULEENTRY32);

		if (!Module32First(this->snapShot, &this->me32)) ErrorMessage("Module32First");

		int result = 0;
		do {
			if (snapShot == NULL) {
				WarningMessage("Module is avalid\n");
				return false;
			};
			//wprintf_s(L"%s\n", me32.szModule);
			result = wcscmp(dllName, me32.szModule);
			if (result == 0) break;
		} while (Module32Next(snapShot, &me32));

		return true;
	};

	BOOL SetEjectDLL(const TCHAR* exeName,const TCHAR* DLLname) {
		if (!FindPID(exeName)) WarningMessage("FindPID()");
		if(!SetDebugPrivileges()) WarningMessage("SetDebugPrivileges()");
		if (!FindDLL(DLLname)) WarningMessage("FindDLL()");

		processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
		if (processHandle == NULL) ErrorMessage("OpenProcess()");

		auto kernel32 = GetModuleHandle(L"kernel32.dll");
		remoteEjectFunc = (LPTHREAD_START_ROUTINE)GetProcAddress(kernel32, "FreeLibrary");
		if (remoteEjectFunc == NULL) ErrorMessage("FreeLibrary not found");

		if (remoteThreadHandle != NULL) WarningMessage("RemoteThread is not avalid\n");
		remoteThreadHandle = CreateRemoteThread(this->processHandle, NULL, 0, remoteEjectFunc, me32.modBaseAddr, 0, NULL);
		if (remoteThreadHandle == NULL) ErrorMessage("CreaterRemoteThread()");

		WaitForSingleObject(remoteThreadHandle, INFINITY);

		//TerminateProcess(processHandle, 0);
		return TRUE;
		
	};

}ejector;