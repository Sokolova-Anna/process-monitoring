#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>
#include <comdef.h>
#include <tchar.h>
#include <strsafe.h>
#include <string>
#include <tchar.h>
#include <strsafe.h>

#define DLL_NAME "\\hook.dll"
#define BUFSIZE 512

int parseСommand(int argc, char* argv[], std::string* pid, std::string* process_name, std::string* func, std::string* filename);
DWORD getPidByName(std::string name);
HANDLE createPipe();
int injectLib(DWORD pid);
int messaging(HANDLE pipeHandle, std::string message);


int parseСommand(int argc, char* argv[], std::string* pid, std::string* process_name, std::string* func, std::string* filename)
{
	*pid = "";
	*process_name = "";
	*func = "";
	*filename = "";

	if (argc != 5)
	{
		std::cout << "Wrong args number" << std::endl;
		return 1;
	}

	std::string arg_1(argv[1]), arg_2(argv[2]), arg_3(argv[3]), arg_4(argv[4]);

	if (arg_1 == "-pid")
		*pid = arg_2;
	else if (arg_3 == "-pid")
		*pid = arg_4;
	else if (arg_1 == "-name")
		*process_name = arg_2;
	else if (arg_3 == "-name")
		*process_name = arg_4;
	else
	{
		std::cout << "Process id/name ?" << std::endl;
		return 1;
	}

	if (arg_1 == "-func")
		*func = arg_2;
	else if (arg_3 == "-func")
		*func = arg_4;
	else if (arg_1 == "-hide")
		*filename = arg_2;
	else if (arg_3 == "-hide")
		*filename = arg_4;
	else
	{
		std::cout << "Func / filename to hide ?" << std::endl;
		return 1;
	}

	return 0;
}

DWORD getPidByName(std::string name)
{
	DWORD pid = 0;

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);

	if (Process32First(snapshot, &process))
	{
		do
		{
			_bstr_t b(process.szExeFile);
			const char* c = b;
			if (strcmp(c, name.c_str()) == 0)
			{
				pid = process.th32ProcessID;
				break;
			}
		} while (Process32Next(snapshot, &process));
	}

	CloseHandle(snapshot);

	return pid;

}

HANDLE createPipe()
{
	BOOL   ConnectFlag = FALSE;
	DWORD  ThreadID = 0;
	HANDLE PipeHandle = INVALID_HANDLE_VALUE;
	HANDLE ThreadHandle = NULL;
	LPCTSTR PipeName = TEXT("\\\\.\\pipe\\newpipe");

	PipeHandle = CreateNamedPipe(
		PipeName,
		PIPE_ACCESS_DUPLEX,
		PIPE_TYPE_MESSAGE |
		PIPE_READMODE_MESSAGE |
		PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES,
		BUFSIZE,
		BUFSIZE,
		0,
		NULL);

	if (PipeHandle == INVALID_HANDLE_VALUE)
	{
		printf("CreateNamedPipe failed with %d.\n", GetLastError());
		return 0;
	}

	return PipeHandle;

}

int injectLib(DWORD pid)
{
	HANDLE hProcess;
	HANDLE hRemoteThread;
	LPVOID hRemoteBuf;
	int len = sizeof(DLL_NAME) + 1;

	HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
	if (hKernel32 == NULL)
	{
		std::cout << "GetModuleHandleW error\n";
		return 1;
	}

	LPVOID pLoadLibrary = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryA");
	if (pLoadLibrary == NULL)
	{
		std::cout << "GetProcAddress error\n";
		return 1;
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL)
	{
		std::cout << "OpenProcess error\n";
		return 1;
	}

	char cur_dir[1000] = { 0 };
	GetCurrentDirectoryA(sizeof(cur_dir), cur_dir);
	strcat(cur_dir, DLL_NAME);
	const char* dllPath = cur_dir;

	hRemoteBuf = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (hRemoteBuf == NULL)
	{
		std::cout << "VirtualAllocEx error\n";
		return 1;
	}

	int res = WriteProcessMemory(hProcess, hRemoteBuf, dllPath, strlen(dllPath), NULL);
	if (res == NULL)
	{
		std::cout << "WriteProcessMemory error\n";
		return 1;
	}

	hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, hRemoteBuf, 0, NULL);
	if (hRemoteThread == NULL)
	{
		std::cout << "CreateRemoteThread error: " << GetLastError() << std::endl;
		return 1;
	}

	CloseHandle(hProcess);
	return 0;

}

int messaging(HANDLE pipeHandle, std::string message)
{
	HANDLE hHeap = GetProcessHeap();
	char* pchRequest = new char[BUFSIZE * sizeof(char)];
	char* pchReply = new char[BUFSIZE * sizeof(char)];

	DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;
	BOOL fSuccess = FALSE;

	if (pipeHandle == NULL)
	{
		std::cout << "Pipe handle error" << std::endl;
		return 1;
	}

	fSuccess = ReadFile(pipeHandle, pchRequest, BUFSIZE * sizeof(CHAR), &cbBytesRead, NULL);

	if (!fSuccess || cbBytesRead == 0)
	{
		if (GetLastError() == ERROR_BROKEN_PIPE)
			std::cout << "Client disconnected" << std::endl;
		else
			std::cout << "ReadFile error" << std::endl;
		return 0;
	}

	std::cout << "FROM CLIENT: " << pchRequest << std::endl;

	strcpy(pchReply, message.c_str());
	cbReplyBytes = (lstrlenA(pchReply) + 1) * sizeof(char);

	std::cout << "Sending: " << pchReply << std::endl;
	fSuccess = WriteFile(pipeHandle, pchReply, cbReplyBytes, &cbWritten, NULL);

	while (1)
	{
		fSuccess = ReadFile(pipeHandle, pchRequest, BUFSIZE * sizeof(CHAR), &cbBytesRead, NULL);

		if (!fSuccess || cbBytesRead == 0)
		{
			if (GetLastError() == ERROR_BROKEN_PIPE)
				std::cout << "Client disconnected" << std::endl;
			else
				std::cout << "ReadFile error" << std::endl;
			break;
		}

		std::cout << "FROM CLIENT: " << pchRequest << std::endl;

		if (!fSuccess || cbReplyBytes != cbWritten)
		{
			std::cout << "WriteFile error" << std::endl;
			break;
		}
	}

	FlushFileBuffers(pipeHandle);
	DisconnectNamedPipe(pipeHandle);
	CloseHandle(pipeHandle);

	return 0;
}

int main(int argc, char* argv[])
{
	DWORD pid;
	std::string s_pid, proccess_name, func, filename;

	int res = parseСommand(argc, argv, &s_pid, &proccess_name, &func, &filename);
	if (res)
		return 1;

	if (s_pid != "")
		pid = atoi(s_pid.c_str());
	else
		pid = getPidByName(proccess_name);
	if (pid == 0)
	{
		std::cout << "pid not found" << std::endl;
		return 1;
	}

	std::string message;
	if (func != "")
		message = "m" + func;
	else if (filename != "")
		message = "h" + filename;
	else
	{
		std::cout << "no func, no filename" << std::endl;
		return 1;
	}

	HANDLE pipe_handle = createPipe();
	std::cout << "pipe created" << std::endl;

	res = injectLib(pid);
	if (res)
		return 1;
	std::cout << "lib injected" << std::endl;

	BOOL result = ConnectNamedPipe(pipe_handle, NULL);
	if (!result) {
		std::cout << "Failed to make connection on named pipe." << std::endl;
		CloseHandle(pipe_handle);
		return 1;
	}
	std::cout << "connected to pipe" << std::endl;

	res = messaging(pipe_handle, message);

	CloseHandle(pipe_handle);

	return 0;
}
