#pragma once
#include <stdlib.h>
#include <iostream>
#include <windows.h>
//#include <detours.h>
#include <fstream>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <fileapi.h>

#pragma comment(lib, "Dbghelp.lib")

#define BUFSIZE 512

HANDLE pipe_handle;
std::ofstream logfile;
std::wofstream w_logfile;
char* funcName;
std::string filename;
std::string filename_nopath;
std::wstring w_filename;
std::wstring w_filename_nopath;

typedef NTSTATUS(*fNtOpenFile)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, ULONG, ULONG);
bool isPathToHiddenFile = false;
fNtOpenFile g_newNtOpenFile = nullptr;

#pragma pack(push, 1)
struct jmp_far_bytes {
    unsigned short _movabs_rax = 47176; // movabs rax, imm
    __int64 jmp_addr = 0; // 8byte imm value
    unsigned short _jmp_rax = 57599; // jmp rax
};
#pragma pack(pop)

extern "C" LPVOID hookFunc();
extern "C" FARPROC pHookedFunc = NULL;

std::string getPathFromFullPath(std::string fullpath);
std::wstring wgetPathFromFullPath(std::wstring wfullpath);

HANDLE WINAPI hook_FindFirstFileExA(LPCSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags);
HANDLE WINAPI hook_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
HANDLE WINAPI hook_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
HANDLE WINAPI hook_FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
HANDLE WINAPI hook_FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATA lpFindFileData);
HANDLE WINAPI hook_FindFirstFileExW(LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS  fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags);
BOOL WINAPI hook_FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA  lpFindFileData);
BOOL WINAPI hook_FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATA lpFindFileData);
NTSTATUS hook_NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions);

void hookNtOpenFile();
void hideFile();
HANDLE connectToServer();
int sendMessage(HANDLE pipeHandle, std::string message);
int sendMessage(HANDLE pipeHandle, char* message);
int recvMessage(HANDLE pipeHandle, LPVOID chBuf);
extern "C" VOID printTime();
const HMODULE getCurrentModule();
int ReplaceIATEntryInOneModule(PCSTR pszCalleeModName, PROC pfnCurrent, PROC pfnNew, HMODULE hmodCaller);
void ReplaceIATEntryInAllModules(PCSTR pszExportMod, PROC pfnCurrent, PROC pfnNew);
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved);

