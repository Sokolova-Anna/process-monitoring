#define _CRT_SECURE_NO_WARNINGS
#include "hook.h"


std::string getPathFromFullPath(std::string fullpath)
{
    size_t backslashPosition = fullpath.rfind('\\');
    std::string path = fullpath.substr(0, backslashPosition + 1);
    return path;
}

std::wstring wgetPathFromFullPath(std::wstring wfullpath)
{
    size_t backslashPosition = wfullpath.rfind('\\');
    std::wstring wpath = wfullpath.substr(0, backslashPosition + 1);

    return wpath;
}

HANDLE WINAPI hook_FindFirstFileExA(LPCSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags)
{
    logfile << "in hook_FindFirstFileExA()" << std::endl;
    std::string currentDirectoryPath = getPathFromFullPath(std::string(lpFileName));
    std::string path = getPathFromFullPath(filename);

    isPathToHiddenFile = (path == currentDirectoryPath);

    HANDLE hResult = FindFirstFileExA(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);
    std::string foundFilename = (char*)((WIN32_FIND_DATAW*)lpFindFileData)->cFileName;

    if (isPathToHiddenFile && filename == foundFilename)
    {
        hResult = INVALID_HANDLE_VALUE;
    }
    return hResult;
}

HANDLE WINAPI hook_CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    logfile << "in hook_CreateFileA()" << std::endl;

    if (filename == lpFileName) 
    {
        return INVALID_HANDLE_VALUE;
    }
    HANDLE hResult = CreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    return hResult;
}

HANDLE WINAPI hook_CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
    logfile << "in hook_CreateFileW()" << std::endl;

    if (w_filename == lpFileName) 
    {
        return INVALID_HANDLE_VALUE;
    }
    HANDLE hResult = CreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    return hResult;
}

HANDLE WINAPI hook_FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
{
    logfile << "in hook_FindFirstFileA()" << std::endl;

    HANDLE hResult = FindFirstFileA(lpFileName, lpFindFileData);
    isPathToHiddenFile = (filename == lpFileName);
    if (isPathToHiddenFile && filename_nopath == lpFindFileData->cFileName)
    {
        hResult = INVALID_HANDLE_VALUE;
    }
    return hResult;
}

HANDLE WINAPI hook_FindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATA lpFindFileData)
{
    logfile << "in hook_FindFirstFileW()" << std::endl;

    HANDLE hResult = FindFirstFileW(lpFileName, lpFindFileData);
    isPathToHiddenFile = (w_filename == lpFileName);
    if (isPathToHiddenFile && w_filename_nopath == lpFindFileData->cFileName)
    {
        hResult = INVALID_HANDLE_VALUE;
    }
    return hResult;
}

HANDLE WINAPI hook_FindFirstFileExW(LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS  fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags)
{
    logfile << "in hook_FindFirstFileExW()" << std::endl;

    std::wstring currentDirectoryPath = wgetPathFromFullPath(std::wstring(lpFileName));
    isPathToHiddenFile = (w_filename == currentDirectoryPath);

    HANDLE hResult = FindFirstFileExW(lpFileName, fInfoLevelId, lpFindFileData, fSearchOp, lpSearchFilter, dwAdditionalFlags);

    std::wstring foundFilename = ((WIN32_FIND_DATAW*)lpFindFileData)->cFileName;

    if (isPathToHiddenFile && w_filename_nopath == foundFilename) {
        hResult = INVALID_HANDLE_VALUE;
    }
    return hResult;
}

BOOL WINAPI hook_FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA  lpFindFileData)
{
    logfile << "in hook_FindNextFileA()" << std::endl;

    BOOL bResult = FindNextFileA(hFindFile, lpFindFileData);

    if (isPathToHiddenFile && filename_nopath == lpFindFileData->cFileName) {
        bResult = FindNextFileA(hFindFile, lpFindFileData);
    }

    return bResult;
}

BOOL WINAPI hook_FindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATA lpFindFileData)
{
    logfile << "in hook_FindNextFileW()" << std::endl;

    BOOL bResult = FindNextFileW(hFindFile, lpFindFileData);

    if (isPathToHiddenFile && w_filename_nopath == lpFindFileData->cFileName) {
        bResult = FindNextFileW(hFindFile, lpFindFileData);
    }

    return bResult;
}

NTSTATUS hook_NtOpenFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, ULONG ShareAccess, ULONG OpenOptions)
{
    auto res = g_newNtOpenFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, ShareAccess, OpenOptions);
    logfile << "in hkNtOpenFile" << std::endl;

    HANDLE fileHandle = &FileHandle;
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        logfile << "INVALID_HANDLE_VALUE" << std::endl;
    }
    
    std::wstring curFilePath(ObjectAttributes->ObjectName->Buffer);
    curFilePath.erase(0, 4);

    w_logfile << curFilePath << std::endl;
    
    if (curFilePath == w_filename)
    {
        return 0xC000000F;
    }

    return res;
}

void hookNtOpenFile()
{
    HMODULE library_handle = LoadLibrary(L"NTDLL.DLL");
    if (!library_handle)
        logfile << "LoadLibrary failed" << std::endl;
    fNtOpenFile proc_addr = (fNtOpenFile)GetProcAddress(library_handle, "NtOpenFile");

    // rm page write protection so we can add jmp to real NtOpenFile
    // and get read permissions
    DWORD old_protect = 0;
    VirtualProtect(proc_addr, 128, PAGE_EXECUTE_READWRITE, &old_protect);

    // make a copy of real ntopenfile somewhere, 128 bytes should be enough
    fNtOpenFile newNtOpenFile = (fNtOpenFile)VirtualAlloc(nullptr, 128, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!newNtOpenFile)
        logfile << "VirtualAlloc failed" << std::endl;
    memcpy(newNtOpenFile, proc_addr, 128);
    // save ptr to copy of ntopenfile
    g_newNtOpenFile = newNtOpenFile;

    // prepare shellcode
    auto jmp_struct = new jmp_far_bytes;
    jmp_struct->jmp_addr = (__int64)hook_NtOpenFile;

    // fill old instruction with nops
    memset(proc_addr, 0x90, 16);
    // then put shellcode at the start of old ntopenfile
    memcpy(proc_addr, jmp_struct, sizeof jmp_far_bytes);

    delete jmp_struct;
}


void hideFile()
{
    hookNtOpenFile();

    HMODULE hKernel32 = GetModuleHandleA((LPCSTR)"Kernel32.dll");

    FARPROC pfnOriginal = (FARPROC)GetProcAddress(hKernel32, "CreateFileA");
    ReplaceIATEntryInAllModules("KERNEL32.dll", pfnOriginal, (PROC)hook_CreateFileA);

    pfnOriginal = (FARPROC)GetProcAddress(hKernel32, "CreateFileW");
    ReplaceIATEntryInAllModules("KERNEL32.dll", pfnOriginal, (PROC)hook_CreateFileW);

    pfnOriginal = (FARPROC)GetProcAddress(hKernel32, "FindFirstFileA");
    ReplaceIATEntryInAllModules("KERNEL32.dll", pfnOriginal, (PROC)hook_FindFirstFileA);

    pfnOriginal = (FARPROC)GetProcAddress(hKernel32, "FindFirstFileW");
    ReplaceIATEntryInAllModules("KERNEL32.dll", pfnOriginal, (PROC)hook_FindFirstFileW);

    pfnOriginal = (FARPROC)GetProcAddress(hKernel32, "FindFirstFileExA");
    ReplaceIATEntryInAllModules("KERNEL32.dll", pfnOriginal, (PROC)hook_FindFirstFileExA);

    pfnOriginal = (FARPROC)GetProcAddress(hKernel32, "FindFirstFileExW");
    ReplaceIATEntryInAllModules("KERNEL32.dll", pfnOriginal, (PROC)hook_FindFirstFileExW);

    pfnOriginal = (FARPROC)GetProcAddress(hKernel32, "FindNextFileA");
    ReplaceIATEntryInAllModules("KERNEL32.dll", pfnOriginal, (PROC)hook_FindNextFileA);

    pfnOriginal = (FARPROC)GetProcAddress(hKernel32, "FindNextFileW");
    ReplaceIATEntryInAllModules("KERNEL32.dll", pfnOriginal, (PROC)hook_FindNextFileW);

}

HANDLE connectToServer()
{
    LPCSTR pipeName = "\\\\.\\pipe\\newpipe";
    HANDLE pipeHandle;

    while (1)
    {
        pipeHandle = CreateFileA(
            pipeName,
            GENERIC_READ |
            GENERIC_WRITE,
            0,
            NULL,
            OPEN_EXISTING,
            0,
            NULL);

        if (pipeHandle != INVALID_HANDLE_VALUE)
            break;

        if (pipeHandle == INVALID_HANDLE_VALUE)
        {
            logfile << "INVALID HANDLE VALUE" << std::endl;
            logfile.close();
            return 0;
        }

        if (GetLastError() != ERROR_PIPE_BUSY)
        {
            logfile << GetLastError() << std::endl;
            logfile.close();
            return 0;
        }

        if (!WaitNamedPipeA((LPCSTR)pipeName, 20000))
        {
            return 0;
        }
    }

    DWORD dwMode = PIPE_READMODE_MESSAGE;
    BOOL fSuccess = SetNamedPipeHandleState(pipeHandle, &dwMode, NULL, NULL);

    if (!fSuccess)
        return 0;

    return pipeHandle;
}

int sendMessage(HANDLE pipeHandle, std::string message)
{
    char* lpvMessage = new char[message.size() + 1];
    strcpy(lpvMessage, message.c_str());

    sendMessage(pipeHandle, lpvMessage);

    return 0;
}

int sendMessage(HANDLE pipeHandle, char* message)
{
    DWORD cbToWrite, cbWritten;
    cbToWrite = (lstrlenA(message) + 1) * sizeof(char);

    logfile << "Sending: " << message << std::endl;

    BOOL fSuccess = WriteFile(pipeHandle, message, cbToWrite, &cbWritten, NULL);
    if (!fSuccess)
    {
        logfile << "WriteFile error" << std::endl;
        return 1;
    }

    return 0;
}

int recvMessage(HANDLE pipeHandle, LPVOID chBuf)
{
    DWORD cbRead;
    BOOL fSuccess;

    do
    {
        fSuccess = ReadFile(pipeHandle, chBuf, BUFSIZE * sizeof(TCHAR), &cbRead, NULL);

        if (!fSuccess && GetLastError() != ERROR_MORE_DATA)
            break;

    } while (!fSuccess);

    if (!fSuccess)
        return 1;

    return 0;
}

extern "C" VOID printTime()
{
    char buffer[80];
    std::string message = funcName;
    time_t seconds = time(nullptr);
    tm* timeinfo = localtime(&seconds);
    strftime(buffer, sizeof(buffer), "%d-%m-%Y %H:%M:%S", timeinfo);
    std::string strtime(buffer);
    message += ": ";
    message += strtime;
    sendMessage(pipe_handle, message);
}

const HMODULE getCurrentModule()
{
    HMODULE hModule = NULL;
    GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)getCurrentModule, &hModule);
    return hModule;
}

int ReplaceIATEntryInOneModule(PCSTR pszCalleeModName, PROC pfnCurrent, PROC pfnNew, HMODULE hmodCaller)
{
    ULONG ulSize;
    PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)ImageDirectoryEntryToData(hmodCaller, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &ulSize);

    if (pImportDesc == nullptr) {
        logfile << "ImageDirectoryEntryToData failed" << GetLastError() << std::endl;
        return 1;
    }

    for (; pImportDesc->Name; pImportDesc++) {
        PSTR pszModName = (PSTR)((PBYTE)hmodCaller + pImportDesc->Name);

        if (lstrcmpiA(pszModName, pszCalleeModName) == 0) {
            break;
        }
    }
    if (pImportDesc->Name == 0) {
        return 0;
    }

    PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)((PBYTE)hmodCaller + pImportDesc->FirstThunk);

    for (; pThunk->u1.Function; pThunk++) {

        if ((PROC)pThunk->u1.Function == pfnCurrent) {
            DWORD dwOldProtect;

            if (!VirtualProtect(&pThunk->u1.Function, sizeof(pThunk->u1.Function), PAGE_READWRITE, &dwOldProtect)) {
                logfile << "VirtualProtect error" << std::endl;
                return 1;
            }

            if (!WriteProcessMemory(GetCurrentProcess(), &pThunk->u1.Function, &pfnNew, sizeof(pfnNew), nullptr)) {
                logfile << "WriteProcessMemory error" << std::endl;
                return 1;
            }

            VirtualProtect(&pThunk->u1.Function, sizeof(pThunk->u1.Function), dwOldProtect, &dwOldProtect);
            break;
        }
    }

    return 0;
}

void ReplaceIATEntryInAllModules(PCSTR pszExportMod, PROC pfnCurrent, PROC pfnNew)
{
    HMODULE hThisMod = getCurrentModule();
    HANDLE hModuleSnap = nullptr;
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);

    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    if (Module32First(hModuleSnap, &me32))
    {
        do
        {
            if (hThisMod != me32.hModule)
            {
                int result = ReplaceIATEntryInOneModule(pszExportMod, pfnCurrent, pfnNew, me32.hModule);
                if (result) {
                    logfile << "ReplaceIATEntryInOneModule failed" << std::endl;
                }
                //else
                    //logfile << "ReplaceIATEntryInOneModule success" << std::endl;
            }
        } while (Module32Next(hModuleSnap, &me32));
    }

    CloseHandle(hModuleSnap);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    std::string message, buffer, func;
    CHAR chBuf[BUFSIZE];
    LONG res;

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        logfile.open("D:\\injector\\x64\\Debug\\logfile.txt");
        w_logfile.open("D:\\injector\\x64\\Debug\\w_logfile.txt");

        pipe_handle = connectToServer();
        if (pipe_handle == 0)
            return 1;

        logfile << "connected to server" << std::endl;

        message = "connected";
        if (sendMessage(pipe_handle, message))
            return 1;

        if (recvMessage(pipe_handle, chBuf))
            return 1;

        logfile << "FROM SERVER: " << chBuf << std::endl;

        buffer = chBuf;
        if (buffer[0] == 'm')
        {
            func = buffer;
            func.erase(0, 1);
            funcName = new char[func.length() + 1];
            strcpy(funcName, func.c_str());

            pHookedFunc = GetProcAddress(GetModuleHandle(L"KERNEL32.dll"), funcName);
            if (pHookedFunc == NULL) {
                logfile << "GetProcAddress error" << std::endl;
                return 1;
            }
            ReplaceIATEntryInAllModules("kernel32.dll", pHookedFunc, (PROC)hookFunc);


        }
        else if (buffer[0] == 'h')
        {
            filename = buffer;
            filename.erase(0, 1);
            filename_nopath = filename.substr(filename.find_last_of("\\") + 1);

            w_filename = std::wstring(filename.begin(), filename.end());
            w_filename_nopath = std::wstring(filename_nopath.begin(), filename_nopath.end());

            hideFile();
        }
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

