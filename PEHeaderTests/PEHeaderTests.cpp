// PEHeaderTests.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <fstream>
#include "../PETools/PETools.h"
#include <winnt.h>
#include <winternl.h>


int __stdcall NtTestAlert()
{
    return 0;
}

#include <filesystem>
#include <set>
bool IsDllOrExe(const std::filesystem::directory_entry& entry, bool bIncludeExes = false)
{

    if (!entry.path().extension().compare(".cpl") || !entry.path().extension().compare(".drv") || !entry.path().extension().compare(".dll") ||
        (!entry.path().extension().compare(".exe") && bIncludeExes))
        return true;
    return false;
}


std::vector<std::string> GetEverySingleFuckingDLLWithFolder(const char* szDir)
{
    std::vector<std::string> dlls;
    

    if (!std::filesystem::exists(szDir)) return {};

    try {
        for (const std::filesystem::directory_entry& dir_entry :
            std::filesystem::recursive_directory_iterator(szDir, std::filesystem::directory_options::skip_permission_denied))
        {
            if (IsDllOrExe(dir_entry, true))
            {
                std::string file_name = dir_entry.path().filename().string();

                if (std::find(dlls.begin(), dlls.end(), file_name) == dlls.end())
                {
                    //printf("%s\n", file_name.c_str());
                    dlls.push_back(file_name);
                }
            }
        }
    }
    catch (std::exception& e)
    {
        printf("Caught Exception : %s\n", e.what());

        if (IsDebuggerPresent())
            DebugBreak();

        //int c = getchar();
    }

    return dlls;
}

std::vector<std::string> GetImports(const char* szPath)
{
    std::fstream dll2(szPath, std::ios::in | std::ios::binary);
    // DudeBroDll.dll

    if (!dll2.is_open())
        return {};

    dll2.seekg(0, std::ios::end);
    size_t nDllSize = dll2.tellg();
    char* pBuffer = (char*)malloc(nDllSize);
    dll2.seekg(0, std::ios::beg);
    dll2.read(pBuffer, nDllSize);

    std::vector<std::string> ret = PETools::FetchAllImportedModules(pBuffer, nDllSize, false);

    free(pBuffer);

    return ret;
}

/*
 * Case Insensitive String Comparision
 */
bool compareChar(const char& c1, const char& c2)
{
    if (c1 == c2)
        return true;
    else if (std::toupper(c1) == std::toupper(c2))
        return true;
    return false;
}

bool caseInSensStringCompare(const std::string& str1, const std::string& str2)
{
    return ((str1.size() == str2.size()) &&
        std::equal(str1.begin(), str1.end(), str2.begin(), &compareChar));
}

bool MatchFilesToMissingIncludes(std::vector<std::string> dlls, const char* szDir, std::string& out_str, std::ofstream* out)
{
    
    if (!std::filesystem::exists(szDir)) return {};



    bool bIssue = false;
    for (const std::filesystem::directory_entry& dir_entry :
        std::filesystem::recursive_directory_iterator(szDir, std::filesystem::directory_options::skip_permission_denied))
    {
        if (IsDllOrExe(dir_entry, true))
        {
            auto imports = GetImports(dir_entry.path().string().c_str());
            for (const auto& _import : imports)
            {
                // ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? ? 
                if (strstr(_import.c_str(), "api-") || strstr(_import.c_str(), "ext-"))
                    continue;


                if (std::find_if(
                    dlls.begin(), dlls.end(),
                    [&dlls, &_import](const std::string& x) { return caseInSensStringCompare(x, _import); }) == dlls.end())
                {
                    auto str = std::string("Windows Import Discrepancy! " + dir_entry.path().filename().string() + " imports " + _import + "\n");
                    
                    if (out)
                        out->write(str.c_str(), str.size());

                    printf("%s\n", str.c_str());
                    bIssue = true;
                }
            }
        }
    }

    return bIssue;
}

#include <Psapi.h>
#include <TlHelp32.h>
int mapp_lol(const char* szProc, void* pBuffer, size_t nBuffersize)
{
    PROCESSENTRY32 PE32{ 0 };
    PE32.dwSize = sizeof(PE32);

    HANDLE hSnap = CreateToolhelp32Snapshot(0x02, 0);
    if (hSnap == INVALID_HANDLE_VALUE)
    {
        DWORD Err = GetLastError();
        printf("FAILED CreateToolhelp32Snapshot(): 0x%X\n", Err);
        getchar();
        return 0;
    }

    DWORD PID = 0;
    BOOL bRet = Process32First(hSnap, &PE32);
    while (bRet)
    {
        if (!strcmp(szProc, PE32.szExeFile))
        {
            PID = PE32.th32ProcessID;
            break;
        }
        bRet = Process32Next(hSnap, &PE32);
    }

    CloseHandle(hSnap);

    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (!hProc)
    {
        DWORD Err = GetLastError();
        printf("FAILED OpenProcess(): 0x%X\n", Err);
        getchar();
        return 0;
    }



    if (!PETools::MapDLLToProcess(hProc, pBuffer, nBuffersize))
    {
        CloseHandle(hProc);
        printf("Failed to map :[\n");
        getchar();
        return 0;
    }

    CloseHandle(hProc);
    printf("Mapping Done\n");
    getchar();
    return 0;
}

int main()
{
#if 0
    printf("getting every dll...\n");



    std::vector<std::string> dlls_on_disk = GetEverySingleFuckingDLLWithFolder("C:\\Windows\\");
    auto program_files = GetEverySingleFuckingDLLWithFolder("C:\\Program Files (x86)\\");
    auto all_c = GetEverySingleFuckingDLLWithFolder("C:\\");
    auto all_c2 = GetEverySingleFuckingDLLWithFolder("C:\\Windows\\WinSxS\\");


    dlls_on_disk.insert(dlls_on_disk.end(), program_files.begin(), program_files.end());
    dlls_on_disk.insert(dlls_on_disk.end(), all_c.begin(), all_c.end());
    dlls_on_disk.insert(dlls_on_disk.end(), all_c2.begin(), all_c2.end());
  

    sort(dlls_on_disk.begin(), dlls_on_disk.end());
    dlls_on_disk.erase(unique(dlls_on_disk.begin(), dlls_on_disk.end()), dlls_on_disk.end());

    printf("completed dll scan, %d dlls found....\n", dlls_on_disk.size());

    if (IsDebuggerPresent())
        DebugBreak();

    // int c = getchar();

    std::ofstream dll_dump("dumped_dlls.txt", std::ios::out);

    for (const auto& dll : dlls_on_disk)
    {
        dll_dump.write(dll.c_str(), dll.length());
        dll_dump.write("\n", 1);
    }
    std::ofstream vulns("vulns.txt", std::ios::out);

    printf("Comparing Sys Exes And DLLs!\n");
    std::string out_string;
    MatchFilesToMissingIncludes(dlls_on_disk, "C:\\Windows\\SysWOW64\\", out_string, &vulns);
    MatchFilesToMissingIncludes(dlls_on_disk, "C:\\Windows\\WinSxS\\", out_string, &vulns);

 

    //vulns.write(out_string.c_str(), out_string.size());

    Beep(0x1000, 10);
    printf("Completed!\n");
    int l = getchar();


    return 0;
#endif
#if 0
    std::fstream dll("TeachingLily.exe", std::ios::in | std::ios::binary);

    dll.seekg(0, std::ios::end);
    size_t nDllSize = dll.tellg();
    char* pBuffer = (char*)malloc(nDllSize);
    dll.seekg(0, std::ios::beg);

    dll.read(pBuffer, nDllSize);



    static auto DumpPEInfo = [](void* pBuffer)
    {
        int iNumSections = PETools::GetNumberOfSections(pBuffer);
        for (int i = 0; i < iNumSections; i++)
        {
            char buffer[9]{ 0 };
            memset(buffer, 0x00, sizeof(buffer));
            auto sec = PETools::GetSectionHeaderByIndex(pBuffer, i);
            memcpy(buffer, sec->Name, 8);
            printf("%s (%x -> %x) @ (%x -> @%x)\n", buffer, sec->VirtualAddress, sec->VirtualAddress + sec->Misc.VirtualSize,
                sec->PointerToRawData, sec->PointerToRawData + sec->SizeOfRawData);
        }

        int nDataDir = PETools::GetNumberOfRvaAndSizes(pBuffer);
        for (int i = 0; i < nDataDir; i++)
        {
            auto dir = PETools::GetDataDirectory(pBuffer, i);
            if(dir->VirtualAddress)
                printf("    Data Dir %d : %x -> %x\n",i, dir->VirtualAddress, dir->VirtualAddress + dir->Size);
        }

    };

    static auto compare_sections_of_two_dlls = [](void* pOld, void* pNew)
    {
        int nSecs = PETools::GetNumberOfSections(pOld);

        for (int i = 0; i < nSecs; i++)
        {
            auto oSec = PETools::GetSectionHeaderByIndex(pOld, i);

            auto nSec = PETools::GetSectionHeaderByIndex(pNew, i);

            char buffer[9]{ 0 };
            memset(buffer, 0x00, sizeof(buffer));
            memcpy(buffer, oSec->Name, 8);

            char buffer2[9]{ 0 };
            memset(buffer2, 0x00, sizeof(buffer));
            memcpy(buffer2, nSec->Name, 8);

            if (memcmp((char*)pOld + oSec->PointerToRawData, (char*)pNew + nSec->PointerToRawData, min(oSec->SizeOfRawData, nSec->SizeOfRawData)))
            {
                printf("Section (%d) %s - %s Doesnt Match\n", i, buffer, buffer2);
                for (int j = 0; j < 20; j++)
                    printf("%1x ", *((unsigned char*)pOld + oSec->PointerToRawData + j));

                printf("\n");
                for (int j = 0; j < 20; j++)
                    printf("%1x ", *((unsigned char*)pNew + nSec->PointerToRawData + j));
                printf("\n");
            }
        }
    };

    PIMAGE_SECTION_HEADER pSection = PETools::GetSectionHeaderByName(pBuffer, ".text");
    DumpPEInfo(pBuffer);
    printf("Resizing from (%x)...", nDllSize);
    char* pNewPEFile = (char*)PETools::ResizeSection(".text", pBuffer, nDllSize, pSection->SizeOfRawData * 2, nullptr, false);
    printf("Done (%x)\n", nDllSize);
    DumpPEInfo(pNewPEFile);

    compare_sections_of_two_dlls(pBuffer, pNewPEFile);
    std::ofstream out("out_test.exe", std::ios::out | std::ios::binary);
    out.write((const char*)pNewPEFile, nDllSize);
    out.close();


    free(pBuffer);
    free(pNewPEFile);
#endif

#if 0
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    char* Wow64 = (char*)GetProcAddress(ntdll, "NtTestAlert");
    Wow64 += 5;
    _asm {
        mov eax, 479
        call Wow64
    }





    SysCall::_windows_syscall_t<decltype(&NtTestAlert)> test_alert(131520);
    //test_alert();


    SysCall::_windows_syscall_t<decltype(&NtAllocateVirtualMemory)> _NtAllocateVirtualMemory(24);
    SIZE_T rSize;
    NTSTATUS Status;
    SIZE_T Size = 4096;
    PVOID VirtualMemory = NULL;
    PCHAR StartOfBuffer;

    Status = _NtAllocateVirtualMemory(GetCurrentProcess(), &VirtualMemory, 0, &Size, MEM_RESERVE, PAGE_NOACCESS);

    return 0;
    _CrtSetDbgFlag(_CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF | _CRTDBG_CHECK_ALWAYS_DF | _CRTDBG_CHECK_CRT_DF| _CRTDBG_LEAK_CHECK_DF);
#endif

    PETools::INIT_PETools_NoPass();
        


    //
    {
        std::fstream dll2("DudeWtf.exe", std::ios::in | std::ios::binary);
        // DudeBroDll.dll
        // "C:\\Windows\\twain_32.dll"
        dll2.seekg(0, std::ios::end);
        size_t nDllSize = dll2.tellg();
        char* pBuffer = (char*)malloc(nDllSize);
        dll2.seekg(0, std::ios::beg);
        dll2.read(pBuffer, nDllSize);
        wchar_t* pwszPath = (wchar_t*)L"C:\\Program Files (x86)\\Internet Explorer\\iexplore.exe";

        HANDLE hHand;
        HANDLE hThread;
        PETools::CreateSuspendedProcessx86(pwszPath, &hHand, &hThread);

        PETools::ProcessHallowExecSuspendedProcessx86(hHand, hThread, pBuffer, nDllSize);

        //PETools::StartProcessThread(hHand);

        wchar_t wszOutBuffer[MAX_PATH];

        ULONG BufferSize = sizeof(wszOutBuffer);
        PETools::PtConvertDosPathNameToNT((PWSTR)pwszPath, wszOutBuffer, &BufferSize);

        SIZE_T nSize = 0;
        LPVOID pFileMem = NULL;

        PETools::ReadFileToBuffer(pwszPath, TRUE, &pFileMem, &nSize);
    }

    std::fstream dll2("Osiris.dll", std::ios::in | std::ios::binary);
    // DudeBroDll.dll
    // "C:\\Windows\\twain_32.dll"
    dll2.seekg(0, std::ios::end);
    size_t nDllSize = dll2.tellg();
    char* pBuffer = (char*)malloc(nDllSize);
    dll2.seekg(0, std::ios::beg);

    //PETools::INIT_PETools_NoPass(nullptr);

    dll2.read(pBuffer, nDllSize);
    dll2.close();

    mapp_lol("csgo.exe", pBuffer, nDllSize);

    //PETools::ldrLoadFromDisk("CSGO_Fixup.dll");


    //void* pMappedDLL = PETools::ldrLoadFromDisk("VCRUNTIME140.dll");//
    void* pMappedDLL = PETools::MapToMemory(pBuffer, nDllSize, "DudeBroDll.dll");
    //const WCHAR* _module = (WCHAR*)((TEB2*)NtCurrentTeb())->ProcessEnvironmentBlock->ProcessParameters->ImagePathName.Buffer;//->ProcessParameters->ImagePathName.Buffer;
    //auto PEB = ((TEB2*)NtCurrentTeb())->ProcessEnvironmentBlock;
    
    char* pVar = getenv("WINDIR");




    HMODULE test = GetModuleHandleA("DudeBroDll.dll");



    if (pMappedDLL)
    {
        BOOL(WINAPI * _DllMain)(
            HINSTANCE hinstDLL,
            DWORD fdwReason,
            LPVOID lpReserved) = (decltype(_DllMain))PETools::GetFileEntryPoint(pMappedDLL);
#if 0
        _asm {
            mov eax, pMappedDLL
            call _DllMain
        }
#endif


        _DllMain((HINSTANCE)pMappedDLL, DLL_PROCESS_ATTACH, nullptr);
    }







    while (true)
    {
        Sleep(9999);
    }





}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
