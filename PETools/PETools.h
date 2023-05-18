/*

Copyright (C) 2022 by Zachary Washburn

Permission is hereby granted, free of charge, to any person obtaining a copy of this
software and associated documentation files (the "Software"), to deal in the Software without restriction,
including without l> imitation the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial
portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

// end license 

========================================================================================================
											   PE TOOLS
========================================================================================================

										      OVERVIEW:

	A simple collection of various helper functions, and tools releated to Microsoft's Portable
Executable file format. Allows for modification of PE files within a buffer and for loading and working
with mapped (loaded) dlls. Most functions are unoptimized and don't include sanity checks, this project
is merely to provide the bare tools needed. Used properly, this should be used as reference for more 
robust libraries/codebases working with such files. Preliminary CLR file (.NET File Format) support
is included. Compiled using c++ lastest as of 6/26/2022.


								      ADDITIONAL CONSIDERATIONS:

Calling Convention :

	All Functions are declared as __stdcall. This is to aid in use from inline assembly (don't have to
increment esp after the function call. To change this simply change the PETOOLSCALL define)



Hashing :

	Functions with "ByHash" hide the string arguements passed into them by accepting a hashed value. 
Pass a function of type fnPEToolsHaser_t ( type unsigned long(PETOOLSCALL*)(char*) ) to INIT_PETools
on startup to init functionality. This is useful for dettering static reverse engineering of your
binaries. Keep in consideration, dynamic debugging (i.e. stepping through each operand) allows 
individuals to see values either kept on the stack or in memory (IAT/EAT tables).



XML / SAL / C++ Attributes Documentation : 

	Functions are defined with both XML and SAL code commenting. For Portablity to other operating systems,
dummy files for sal.h may need to be created. This allows for more intelligent intellisense parsing.

	Attributes are used for similar purposes (initiate compiler warnings). Any MSVC specific attributes 
are wrapped by #define's. 



Windows Header Declaration :
	As this library is very windows specific, the including of the Window header is required. Otherwise 
types would have to be defined. Any windows function calls are done through pointers passed within
INIT_PETools. This is done in case IAT imports should be hidden. TO simply initialize without manually
passing in Windows API function pointers, call INIT_PETools_NoPass instead.

		---- ZJW
========================================================================================================
											PE TOOLS
========================================================================================================
*/

#ifndef _H_PETOOLS
#define _H_PETOOLS
#ifdef _MSC_VER
#pragma once
#endif
#include <winternl.h>
#include <Windows.h>
#include <vector>
#include <string>
//#include <SubAuth.h>
//#include "PEBStructs.h"
// for doing things like reflective mapping
#define PETOOLS_NO_LOADER_INCLUDES
#define PETOOLS_USE_SYSCALLS

#ifdef PETOOLS_USE_SYSCALLS
#define NTSYSALERTHASH
#endif

namespace PETools {

#define PETOOLSCALL __stdcall
	// wrapper class for all the functions
	class PEFile
	{
	public:
		



	private:
		unsigned char* m_pFileBuffer;
		unsigned char* m_pMappedFile;
		size_t		   m_nFileSize;
	};


	typedef unsigned long(PETOOLSCALL* fnPEToolsHasher_t)(char*);

#define PT_STACK_CHARACTER(c, character, xor) constexpr decltype(character) c##_xor = character ^ xor; 
#define PT_STACK_CHARACTERW(c, character, xor) constexpr decltype(L##character) w_##c##_xor = L##character ^ xor; 
#define PT_GET_STACK_CHARACTER(c, xor) c##_xor ^ xor
#define PT_GET_STACK_CHARACTERW(c, xor) w_##c##_xor ^ xor
	PT_STACK_CHARACTER(n, 'n', 0x43);
	PT_STACK_CHARACTER(t, 't', 0x43);
	PT_STACK_CHARACTER(d, 'd', 0x43);
	PT_STACK_CHARACTER(l, 'l', 0x43);
	PT_STACK_CHARACTER(dot, '.', 0x43);
	PT_STACK_CHARACTER(W, 'W', 0x43);
	PT_STACK_CHARACTER(I, 'I', 0x43);
	PT_STACK_CHARACTER(N, 'N', 0x43);
	PT_STACK_CHARACTER(D, 'D', 0x43);
	PT_STACK_CHARACTER(S, 'S', 0x43);
	PT_STACK_CHARACTER(Y, 'Y', 0x43);
	PT_STACK_CHARACTER(T, 'T', 0x43);
	PT_STACK_CHARACTER(E, 'E', 0x43);
	PT_STACK_CHARACTER(M, 'M', 0x43);
	PT_STACK_CHARACTER(O, 'O', 0x43);
	PT_STACK_CHARACTER(R, 'R', 0x43);
	PT_STACK_CHARACTER(s, 's', 0x43);
	PT_STACK_CHARACTER(y, 'y', 0x43);
	PT_STACK_CHARACTER(e, 'e', 0x43);
	PT_STACK_CHARACTER(m, 'm', 0x43);
	PT_STACK_CHARACTER(o, 'o', 0x43);
	PT_STACK_CHARACTER(r, 'r', 0x43);
	PT_STACK_CHARACTER(percent, '%', 0x43);

	PT_STACK_CHARACTERW(W, 'W', 0x4332);
	PT_STACK_CHARACTERW(I, 'I', 0x4332);
	PT_STACK_CHARACTERW(N, 'N', 0x4332);
	PT_STACK_CHARACTERW(D, 'D', 0x4332);
	PT_STACK_CHARACTERW(O, 'O', 0x4332);
	PT_STACK_CHARACTERW(C, 'C', 0x4332);
	PT_STACK_CHARACTERW(backslash, '\\', 0x4332);
	PT_STACK_CHARACTERW(colon, ':', 0x4332);
	PT_STACK_CHARACTERW(S, 'S', 0x4332);
	PT_STACK_CHARACTERW(Y, 'Y', 0x4332);
	PT_STACK_CHARACTERW(T, 'T', 0x4332);
	PT_STACK_CHARACTERW(E, 'E', 0x4332);
	PT_STACK_CHARACTERW(M, 'M', 0x4332);
	PT_STACK_CHARACTERW(R, 'R', 0x4332);
	PT_STACK_CHARACTERW(s, 's', 0x4332);
	PT_STACK_CHARACTERW(y, 'y', 0x4332);
	PT_STACK_CHARACTERW(t, 't', 0x4332);
	PT_STACK_CHARACTERW(e, 'e', 0x4332);
	PT_STACK_CHARACTERW(m, 'm', 0x4332);
	PT_STACK_CHARACTERW(o, 'o', 0x4332);
	PT_STACK_CHARACTERW(r, 'r', 0x4332);
	PT_STACK_CHARACTERW(d, 'd', 0x4332);
	PT_STACK_CHARACTERW(i, 'i', 0x4332);
	PT_STACK_CHARACTERW(w, 'w', 0x4332);
	PT_STACK_CHARACTERW(n, 'n', 0x4332);
	PT_STACK_CHARACTERW(3, '3', 0x4332);
	PT_STACK_CHARACTERW(2, '2', 0x4332);
	PT_STACK_CHARACTERW(6, '6', 0x4332);
	PT_STACK_CHARACTERW(4, '4', 0x4332);
	PT_STACK_CHARACTERW(x, 'x', 0x4332);
	PT_STACK_CHARACTERW(null, '\0', 0x4332);
	PT_STACK_CHARACTERW(percent, '%', 0x4332);



#define WINDOW_PETOOLS_IMPORT(func) decltype(&func) pfn##func
	//PETOOLS_WINDOWS_FUNC(GetProcessHeap);
	//PETOOLS_WINDOWS_FUNC(HeapAlloc);
	/// <c>INIT_PETools</c> 
	/// <summary> Initializes The Base Library </summary>
	/// <param name="pfnVirtualProtect"> VirtualProtect (kernel32.dll) </param>
	/// <param name="pfnVirtualAlloc"> VirtualAlloc (kernel32.dll) </param>
	/// <param name="pfnGetProcAddress"> GetProcAddress (kernel32.dll) </param>
	/// <param name="pfnLoadLibraryA"> LoadLibraryA (kernel32.dll) </param>
	/// <param name="pfnGetProcessHeap"> GetProcessHeap (kernel32.dll) </param>
	/// <param name="pfnHeapAlloc"> HeapAlloc (kernel32.dll) </param>
	/// <param name="pfnRtlInitUnicodeString"> RtlInitUnicodeString (ntdll.dll) </param>
	/// <param name="pfnNtQuerySystemTime"> NtQuerySystemTime (ntdll.dll) </param>
	/// <param name="pfnRtlHashUnicodeString"> NtQuerySystemTime (ntdll.dll) </param>
	/// <param name="pfnRtlRbInsertNodeEx"> RtlRbInsertNodeEx (ntdll.dll) </param>
	/// <param name="pfnHasher"> A Hasher Function of (fnPEToolsHaser_t) type unsigned long(PETOOLSCALL*)(char*) for hashing string
	/// in "ByHash" functions </param>
	/// <returns> void (no return) </returns>
	void PETOOLSCALL INIT_PETools(
		_In_ WINDOW_PETOOLS_IMPORT(VirtualProtect),
		_In_ WINDOW_PETOOLS_IMPORT(VirtualAlloc),
		_In_ WINDOW_PETOOLS_IMPORT(GetProcAddress),
		_In_ WINDOW_PETOOLS_IMPORT(LoadLibraryA),
		_In_ WINDOW_PETOOLS_IMPORT(GetProcessHeap),
		_In_ WINDOW_PETOOLS_IMPORT(HeapAlloc),
		_In_ FARPROC pfnNtQuerySystemTime,
		_In_ FARPROC pfnRtlHashUnicodeString,
		_In_ FARPROC pfnRtlRbInsertNodeEx,
		_In_ FARPROC pfnLdrLoadDLL,
		_In_opt_ fnPEToolsHasher_t pfnHasher = nullptr
	);

	/// <c>INIT_PETools_NoPass</c> 
	/// <summary> Initializes The Base Library, Does Not Require Windows API Function Pointers To Be Passed </summary>
	/// <param name="pfnHasher"> A Hasher Function of (fnPEToolsHaser_t) type unsigned long(PETOOLSCALL*)(char*) for hashing string
	/// in "ByHash" functions </param>
	/// <returns> void (no return) </returns>
	void PETOOLSCALL INIT_PETools_NoPass(
		_In_opt_ fnPEToolsHasher_t pfnHasher = nullptr
	);

	/// <c>MapToMemory</c> 
	/// <summary> Loads An Image To Memory From Disk, Not using windows ldr api </summary>
	/// <param name="pPEFileData"> A Pointer to The Raw PE File Data (loaded buffer) </param>
	/// <param name="nFileSize"> The Size Of The Data Buffer </param>
	/// <param name="szAccessName"> Name To Access DLL Through GetProcAddress, NULL if linking to PEB not desired </param>
	/// <returns> A Pointer to the newly mapped memory, will return nullptr upon failure </returns>
	_Check_return_  _Ret_maybenull_ [[nodiscard]] void* PETOOLSCALL MapToMemory(
		_In_reads_(nFileSize) void* pPEFileData,
		_In_ size_t nFileSize,
		_In_opt_z_ const char* szAccessName = nullptr,
		_In_opt_   bool bCallEntry = false
	);

	_Check_return_  _Ret_maybenull_ [[nodiscard]] void* PETOOLSCALL MapFromDisk(
		_In_z_ const char* szPath
	);

	/// <c> ldrLoadFromDisk </c> 
	/// <summary> Loads An Image To Memory From Disk, Using ntdll windows ldr Api </summary>
	/// <param name="szPath"> The Path To The Image To Load </param>
	/// <returns> A Pointer to the newly mapped memory, will return nullptr upon failure </returns>
	_Check_return_  _Ret_maybenull_ [[nodiscard]] void* PETOOLSCALL ldrLoadFromDisk(
		_In_z_ const char* szPath
	);

	/// <c> ldrLoadFromDisk </c> 
	/// <summary> Loads An Image To Memory From Memory, Using ntdll windows ldr Api </summary>
	/// <param name="pPEFileData"> A Pointer to The Raw PE File Data (loaded buffer) </param>
	/// <param name="nFileSize"> The Size Of The Data Buffer </param>
	/// <returns> A Pointer to the newly mapped memory, will return nullptr upon failure </returns>
	_Check_return_  _Ret_maybenull_ [[nodiscard]] void* PETOOLSCALL ldrLoadFromMemory(
		_In_reads_(nFileSize) void* pPEFileData,
		_In_ size_t nFileSize
	);

	/// <c> AddSection </c> 
	/// <summary> Adds A Section To A PE File </summary>
	/// <param name="szSectionName"> The Name Of The New Section </param>
	/// <param name="pPEFileData"> A Pointer to the raw PE file data (loaded buffer) </param>
	/// <param name="nFileSize"> The Size Of The Data Buffer, By Reference Returns New PE FileSize </param>
	/// <param name="pSectionData"> Pointer to data to place at the start of the section, pass NULL for no data </param>
	/// <param name="nSectionDataSizeSize"> Size of the data pointed to by pSectionData </param>
	/// <param name="nSectionSize"> Size of the new section to add </param>
	/// <param name="nSectionCharacteristics"> Characteristic flags to initialize the new section with </param>
	/// <param name="bRealloc"> Should realloc be called on the provided buffer at pPEFile (true) 
	/// or should a new buffer be allocated (false) </param>
	/// <returns> A Pointer to the PE File with added section, will return nullptr upon failure </returns>
	_Check_return_ _Ret_maybenull_ void* PETOOLSCALL AddSection(
		_In_z_ const char* szSectionName,
		_In_reads_(nFileSize) void* pPEFile,
		_In_ size_t& nFileSize,
		_In_reads_opt_(nSectionDataSizeSize) void* pSectionData,
		_In_ size_t nSectionDataSizeSize,
		_In_ size_t nSectionSize,
		_In_ int nSectionCharacteristics = 0,
		_In_ bool bRealloc = false
	);

	_Check_return_ _Ret_maybenull_ void* PETOOLSCALL ResizeSection(
		_In_z_ const char* szSectionName,
		_In_reads_(nFileSize) void* pPEFile,
		_In_ size_t& nFileSize,
		_In_ size_t nNewSectionSize,
		_Outptr_opt_ void** pNewMemoryStartAddress = nullptr, 
		_In_ bool bRealloc = false
	);


	// If *pnFileSize == 0, it will read the entire file out, otherwise it will read *pnFileSize
	NTSTATUS ReadFileToBuffer(PWSTR wszPath, BOOLEAN bDosPathName, LPVOID* plpBuffer, SIZE_T* pnFileSize);

	NTSTATUS StartProcessThread(HANDLE hProcess);
	
	bool MapDLLToProcess(HANDLE hHandle, void* pPEFileData, size_t nPESize, BOOLEAN bCallDLLMain = true, PVOID* pModuleBaseAddress = nullptr, BOOLEAN bIsEXE = false );


	bool __declspec(safebuffers) ResolveRelocs(void* pImageBase, bool bSetImageBase = true );
	bool __declspec(safebuffers) ResolveImports(void* pImageBase, HMODULE( __stdcall* pfnlibLdr)(const char*), FARPROC(__stdcall* pfnGetFunc)(HMODULE, const char*));
	bool __declspec(safebuffers) RunTLSCallBacks(void* pImageBase);
	bool ResolveMemoryPermissions(void* pMappedModuleMem);
	bool ResolveMemoryPermissionsEx(HANDLE hHandle, void* pMappedModuleMem);
	bool MapPESectionsToMemory(
		void* pPEFileData,
		size_t nImageSize,
		void* pMemory,
		size_t nMemorySize
	);
	bool MapPESectionsToMemoryEx(
		HANDLE hHandle,
		void* pPEFileData,
		size_t nImageSize,
		void* pMemory,
		size_t nMemorySize
	);
	LPVOID __stdcall PtVirtualAlloc(
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD  flAllocationType,
		DWORD  flProtect
	);

	LPVOID __stdcall PtVirtualAlloc(
		HANDLE hHandle,
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD  flAllocationType,
		DWORD  flProtect
	);

	BOOL __stdcall PtVirtualProtect(
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD  flNewProtect,
		PDWORD lpflOldProtect);

	NTSTATUS NTAPI PtGetContextThread
	(
		IN HANDLE               ThreadHandle,
		OUT PCONTEXT            pContext
	);
	NTSTATUS NTAPI PtSetContextThread(
		IN HANDLE               ThreadHandle,
		IN PCONTEXT             Context
	);

	void __stdcall ptFreeMemory(LPVOID pAddress);

	inline void __stdcall PtFreeMemory(LPVOID pAddress)
	{
		return ptFreeMemory(pAddress);
	}

	bool ResolveImportsEx(void* pImageBase);
	constexpr unsigned long PETOOLSCALL PeToolsDefaultHasher(char* s);

	inline constexpr int _pet_tolower(char c)
	{
		return c | 32;
	}

#define _A 54059 /* a prime */
#define _B 76963 /* another prime */
#define FIRSTH 37 /* also prime */
	template<class T>
	constexpr unsigned long PETOOLSCALL PeToolsDefaultHasherConstExpr(T s)
	{
		unsigned long h = FIRSTH;
		//const int len = strlen(s);
		//int i = 0;
		while (*s) {
			h = (h * _A) ^ (_pet_tolower(s[0]) * _B);
			s++;
		}
		return h; // or return h % C;
	}

	BOOLEAN PtConvertDosPathNameToNT(PWSTR wszPath, PWSTR wszBuffer, PULONG BufferSize);

	NTSTATUS __stdcall PtNtAllocateVirtualMemory(
		HANDLE    ProcessHandle,
		PVOID* BaseAddress,
		ULONG_PTR ZeroBits,
		PSIZE_T   RegionSize,
		ULONG     AllocationType,
		ULONG     Protect
	);

	BOOL WINAPI PtGetExitCodeThread(IN HANDLE hThread,
		OUT LPDWORD lpExitCode);

	NTSTATUS PtCreateRemoteThread(HANDLE hHandle, PHANDLE phThread, LPTHREAD_START_ROUTINE pFunc, LPVOID pRemoteParam);

	FARPROC WINAPI _GetExportAddress(_In_ HMODULE hModule, _In_opt_ LPCSTR lpProcName, _In_ unsigned long ulHash = 0, fnPEToolsHasher_t pfnHasher = nullptr);
	inline FARPROC WINAPI GetExportAddress(_In_ HMODULE hModule, _In_ LPCSTR lpProcName) [[msvc::forceinline]]
	{
		return _GetExportAddress(hModule, lpProcName, 0, nullptr);
	}

	NTSTATUS ResumeSuspendedProcess(HANDLE hProcess);

	NTSTATUS NTAPI PtCreateTransaction
	(
		PHANDLE            TransactionHandle,
		ACCESS_MASK        DesiredAccess,
		PVOID ObjectAttributes,
		LPGUID             Uow,
		HANDLE             TmHandle,
		ULONG              CreateOptions,
		ULONG              IsolationLevel,
		ULONG              IsolationFlags,
		PVOID			    pLargeIntTimeout,
		PVOID				puniDescription
	);

	NTSTATUS NTAPI  PtQueryInformationProcess(
		_In_      HANDLE           ProcessHandle,
		_In_      DWORD			   ProcessInformationClass,
		_Out_     PVOID            ProcessInformation,
		_In_      ULONG            ProcessInformationLength,
		_Out_opt_ PULONG           ReturnLength
	);

	NTSTATUS NTAPI PtCreateSection
	(
		PHANDLE SectionHandle,
		ACCESS_MASK DesiredAccess,
		PVOID ObjectAttributes,
		PVOID pLargIntMaximumSize,
		ULONG SectionPageProtection,
		ULONG AllocationAttributes,
		HANDLE FileHandle
	);

	NTSTATUS NTAPI PtCreateProcessEx 
	(
		PHANDLE     ProcessHandle,
		ACCESS_MASK  DesiredAccess,
		PVOID ObjectAttributes  OPTIONAL,
		HANDLE   ParentProcess,
		ULONG    Flags,
		HANDLE SectionHandle     OPTIONAL,
		HANDLE DebugPort     OPTIONAL,
		HANDLE ExceptionPort     OPTIONAL,
		BOOLEAN  InJob
	);

	NTSTATUS NTAPI PtCreateUserProcess(
		_Out_ PHANDLE ProcessHandle,
		_Out_ PHANDLE ThreadHandle,
		_In_ ACCESS_MASK ProcessDesiredAccess,
		_In_ ACCESS_MASK ThreadDesiredAccess,
		_In_opt_ PVOID /*_OBJECT_ATTRIBUTES2* */ ProcessObjectAttributes,
		_In_opt_ PVOID /*_OBJECT_ATTRIBUTES2* */ ThreadObjectAttributes,
		_In_ ULONG ProcessFlags,
		_In_ ULONG ThreadFlags,
		_In_ PVOID /*PRTL_USER_PROCESS_PARAMETERS*/ ProcessParameters,
		_Inout_ PVOID /*PPS_CREATE_INFO2 */ CreateInfo,
		_In_ PVOID /*PPS_ATTRIBUTE_LIST2*/ AttributeList
	);


	NTSTATUS NTAPI PtCreateProcessParametersEx(
		_Out_ PVOID /*PRTL_USER_PROCESS_PARAMETERS**/ pProcessParameters,
		_In_ PVOID /*PUNICODE_STRING*/ ImagePathName,
		_In_opt_ PVOID /*PUNICODE_STRING*/  DllPath,
		_In_opt_ PVOID /*PUNICODE_STRING*/  CurrentDirectory,
		_In_opt_ PVOID /*PUNICODE_STRING*/  CommandLine,
		_In_opt_ PVOID Environment,
		_In_opt_ PVOID /*PUNICODE_STRING*/  WindowTitle,
		_In_opt_ PVOID /*PUNICODE_STRING*/  DesktopInfo,
		_In_opt_ PVOID /*PUNICODE_STRING*/  ShellInfo,
		_In_opt_ PVOID /*PUNICODE_STRING*/  RuntimeData,
		_In_ ULONG Flags
	);

	PVOID NTAPI PtAllocateHeap(
		PVOID  HeapHandle,
		ULONG  Flags,
		SIZE_T Size
	);

	NTSTATUS PtDestroyProcessParameters(
		IN /*PRTL_USER_PROCESS_PARAMETERS*/ PVOID ProcessParameters
	);

	DWORD NTAPI PtFreeHeap(
		PVOID                 HeapHandle,
		ULONG                 Flags,
		_Frees_ptr_opt_ PVOID BaseAddress
	);

	NTSTATUS PtUnmapViewOfSection(
		HANDLE ProcessHandle,
		PVOID  BaseAddress
	);

	NTSTATUS PtResumeThread(
		HANDLE ThreadHandle,
		PULONG PreviousSuspendCount
	);

	NTSTATUS ProcessHallowExecSuspendedProcessx86(HANDLE hProcess, HANDLE hThread, void* pPEData, size_t nFileSize);

	NTSTATUS WINAPI PtClose(HANDLE Handle);

	NTSTATUS CreateSuspendedProcessx64(WCHAR* szPath, PHANDLE phHandle);
	NTSTATUS CreateSuspendedProcessx86(WCHAR* szPath, PHANDLE phProcessHandle, PHANDLE phThreadHandle);

	HMODULE GetModuleA(const char* szModule);
	HMODULE GetModuleW(const wchar_t* szModule);
	HMODULE GetModuleHash(unsigned long ulHash, fnPEToolsHasher_t pfnHasher);

	bool PETOOLSCALL EraseHeader(void* pMemory);

	// inline Fetching arguements. Not particularly optimized


	NTSTATUS NTAPI PtTerminateThread(
		HANDLE ThreadHandle,
		NTSTATUS ExitStatus
	);

	inline PIMAGE_DOS_HEADER PETOOLSCALL GetDosHeader(
		_In_ void* pPEStart
	){
		return reinterpret_cast<PIMAGE_DOS_HEADER>(pPEStart);
	}

	inline PIMAGE_NT_HEADERS PETOOLSCALL GetNTHeader(
		_In_ void* pPEStart
	){
		return reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PIMAGE_DOS_HEADER>(pPEStart)->e_lfanew + (char*)pPEStart);
	}

	inline PIMAGE_FILE_HEADER PETOOLSCALL GetFileHeader(void* pPEStart)
	{
		return &(reinterpret_cast<PIMAGE_NT_HEADERS>(
			reinterpret_cast<PIMAGE_DOS_HEADER>(pPEStart)->e_lfanew + (char*)pPEStart))->FileHeader;
	}

	inline PIMAGE_FILE_HEADER PETOOLSCALL GetCOFFHeader(void* pPEStart)
	{
		return GetFileHeader(pPEStart);
	}

	inline PIMAGE_OPTIONAL_HEADER PETOOLSCALL GetOptionalHeader(void* pPEStart)
	{
		return &(reinterpret_cast<PIMAGE_NT_HEADERS>(
			reinterpret_cast<PIMAGE_DOS_HEADER>(pPEStart)->e_lfanew + (char*)pPEStart))->OptionalHeader;
	}

	inline void* PETOOLSCALL GetFileEntryPoint(void* pPEStart)
	{
		PIMAGE_OPTIONAL_HEADER pHeader = GetOptionalHeader(pPEStart);
		return (char*)pHeader->ImageBase + pHeader->AddressOfEntryPoint;
	}

	inline void* PETOOLSCALL GetFileEntryPoint(void* pPEStart, void* pBaseAddress)
	{
		PIMAGE_OPTIONAL_HEADER pHeader = GetOptionalHeader(pPEStart);
		return (char*)pBaseAddress + pHeader->AddressOfEntryPoint;
	}

	inline void* PETOOLSCALL GetCodeRegionStartAddress(void* pPEStart)
	{
		return (char*)pPEStart + GetOptionalHeader(pPEStart)->BaseOfCode;
	}

	inline size_t PETOOLSCALL GetSizeOfHeaders(void* pPEStart)
	{
		return GetOptionalHeader(pPEStart)->SizeOfHeaders;
	}

	inline size_t PETOOLSCALL GetImageSize(void* pPEStart)
	{
		return GetOptionalHeader(pPEStart)->SizeOfImage;
	}

	inline size_t PETOOLSCALL GetSizeOfOptionalHeader(void* pPEStart)
	{
		return GetFileHeader(pPEStart)->SizeOfOptionalHeader;
	}

	inline int PETOOLSCALL GetDLLCharacteristics(void* pPEStart)
	{
		return GetOptionalHeader(pPEStart)->DllCharacteristics;
	}

	inline size_t PETOOLSCALL GetCodeSizeSize(void* pPEStart)
	{
		return GetOptionalHeader(pPEStart)->SizeOfCode;
	}

	inline int PETOOLSCALL GetNumberOfSections(void* pPEStart)
	{
		return GetFileHeader(pPEStart)->NumberOfSections;
	}

	inline int PETOOLSCALL GetNumberOfRvaAndSizes(void* pPEStart)
	{
		return GetOptionalHeader(pPEStart)->NumberOfRvaAndSizes;
	}

	inline int PETOOLSCALL GetImageCharacteristics(void* pPEStart)
	{
		return GetFileHeader(pPEStart)->Characteristics;
	}

	// setters, not particularly optimized

	inline void PETOOLSCALL SetNumberOfSections(void* pPEStart, int nSections)
	{
		GetFileHeader(pPEStart)->NumberOfSections = nSections;
	}

	/// <c>GetSectionHeaderByOffset</c> 
	/// <summary> Fetches The Section Header At Offset Provided </summary>
	/// <param name="pPEStart"> Start Address of a PE File </param>
	/// <param name="nSection"> Index Of Section Header </param>
	/// <returns> Address of section header, nullptr If index out of range </returns>
	inline _Ret_maybenull_ PIMAGE_SECTION_HEADER PETOOLSCALL GetSectionHeaderByIndex(
		_In_ void* pPEStart,
		_In_ unsigned int nSection
	){
		PIMAGE_NT_HEADERS pNTHeaders = GetNTHeader(pPEStart);

		if (nSection >= pNTHeaders->FileHeader.NumberOfSections)
			return nullptr;

		return  &(reinterpret_cast<PIMAGE_SECTION_HEADER>(
			(DWORD)pNTHeaders + sizeof(DWORD) +
			(DWORD)(sizeof(IMAGE_FILE_HEADER)) + 
			(DWORD)pNTHeaders->FileHeader.SizeOfOptionalHeader)
		[nSection]);
	}

	/// <c>GetSectionHeaderByName</c> 
	/// <summary> Fetches A Section Header By Name </summary>
	/// <param name="pPEStart"> Start Address of a PE File </param>
	/// <param name="szName"> Name Of The Section To Fetch </param>
	/// <returns> Address of section header, nullptr If Not Found </returns>
	inline _Ret_maybenull_ PIMAGE_SECTION_HEADER PETOOLSCALL GetSectionHeaderByName(
		_In_ void* pPEStart,
		_In_z_ const char* szName
	){
		PIMAGE_SECTION_HEADER pSection = GetSectionHeaderByIndex(pPEStart, 0);

		if (!pSection)
			return nullptr;

		int nNumSections = PETools::GetNumberOfSections(pPEStart);
		for (int i = 0; i < nNumSections; i++, pSection++)
		{
			char name[sizeof(pSection->Name) + 1]{ 0 };
			memcpy_s(name, sizeof(name), pSection->Name, sizeof(pSection->Name));
			if (!_strcmpi(szName, name))
				return pSection;
		}

		return nullptr;
	}

	/// <c>GetSectionIndexByName</c> 
	/// <summary> Fetches A Section Header By Name </summary>
	/// <param name="pPEStart"> Start Address of a PE File </param>
	/// <param name="szName"> Name Of The Section To Fetch </param>
	/// <returns> Index of section header, -1 If Not Found </returns>
	inline _Ret_maybenull_ int PETOOLSCALL GetSectionIndexByName(
		_In_ void* pPEStart,
		_In_z_ const char* szName
	) {
		PIMAGE_SECTION_HEADER pSection = GetSectionHeaderByIndex(pPEStart, 0);

		if (!pSection)
			return -1;

		int nNumSections = PETools::GetNumberOfSections(pPEStart);
		for (int i = 0; i < nNumSections; i++, pSection++)
		{
			char name[sizeof(pSection->Name) + 1]{ 0 };
			memcpy_s(name, sizeof(name), pSection->Name, sizeof(pSection->Name));
			if (!_strcmpi(szName, name))
				return i;
		}

		return -1;
	}

	/// <c>GetSectionIndexForVirtualAddress</c> 
	/// <summary> Fetches A Section Index By Virtual Address </summary>
	/// <param name="pPEStart"> Start Address of a PE File </param>
	/// <param name="ulVirtualAddress"> Virtual Address </param>
	/// <returns> Index of section header, -1 If Not Found </returns>
	inline _Ret_maybenull_ int PETOOLSCALL GetSectionIndexForVirtualAddress(
		_In_ void* pPEStart,
		_In_ unsigned long ulVirtualAddress
	) {
		PIMAGE_SECTION_HEADER pSection = GetSectionHeaderByIndex(pPEStart, 0);

		if (!pSection)
			return -1;

		int nNumSections = PETools::GetNumberOfSections(pPEStart);
		for (int i = 0; i < nNumSections; i++, pSection++)
		{
			if(pSection->VirtualAddress <= ulVirtualAddress && ((pSection->VirtualAddress + pSection->Misc.VirtualSize) >= ulVirtualAddress))
				return i;
		}

		return -1;
	}

	/// <c>GetSectionHeaderForVirtualAddress</c> 
	/// <summary> Fetches A Section Header By Virtual Address </summary>
	/// <param name="pPEStart"> Start Address of a PE File </param>
	/// <param name="ulVirtualAddress"> Virtual Address </param>
	/// <returns> Index of section header, nullptr If Not Found </returns>
	inline _Ret_maybenull_ PIMAGE_SECTION_HEADER PETOOLSCALL GetSectionHeaderForVirtualAddress(
		_In_ void* pPEStart,
		_In_ unsigned long ulVirtualAddress
	) {
		PIMAGE_SECTION_HEADER pSection = GetSectionHeaderByIndex(pPEStart, 0);

		if (!pSection)
			return nullptr;

		int nNumSections = PETools::GetNumberOfSections(pPEStart);
		for (int i = 0; i < nNumSections; i++, pSection++)
		{
			if (pSection->VirtualAddress <= ulVirtualAddress && ((pSection->VirtualAddress + pSection->Misc.VirtualSize) > ulVirtualAddress))
				return pSection;
		}

		return nullptr;
	}

	/// <c>GetDataDirectory</c> 
	/// <summary> Fetches A Data Directory </summary>
	/// <param name="pPEStart"> Start Address of a PE File </param>
	/// <param name="usDirectoryIndex"> Directory Index, check Directory Entries in winnit.h </param>
	/// <returns> Address of IMAGE_DATA_DIRECTORY, nullptr if invalid Directory Index (no fnPEToolsHasher_t) </returns>
	inline _Ret_maybenull_ PIMAGE_DATA_DIRECTORY PETOOLSCALL GetDataDirectory(
		_In_ void* pPEStart,
		_In_ unsigned short usDirectoryIndex
	){

		PIMAGE_OPTIONAL_HEADER pOptionalHeader = GetOptionalHeader(pPEStart);
		if (usDirectoryIndex >= pOptionalHeader->NumberOfRvaAndSizes)
			return nullptr;
		return &pOptionalHeader->DataDirectory[usDirectoryIndex];
	}

	// Hash Specific Functions (In-case you want to hide what's going on to a degree)

	/// <c>GetSectionHeaderByHash</c> 
	/// <summary> Fetches A Section Header By Hash, Hash Calculated by the fnPEToolsHasher_t Passed In To INIT_PeTools </summary>
	/// <param name="pPEStart"> Start Address of a PE File </param>
	/// <param name="ulHash"> Hash Of The Section Name To Fetch </param>
	/// <returns> Address of section header, nullptr If Not Found or hashing not avaliable (no fnPEToolsHasher_t) </returns>
	_Ret_maybenull_ PIMAGE_SECTION_HEADER PETOOLSCALL GetSectionHeaderByHash(
		_In_ void* pPEStart,
		_In_ unsigned long ulHash
	);

	/// <c>GetSectionIndexByName</c> 
	/// <summary> Fetches A Section Header By Hash, Hash Calculated by the fnPEToolsHasher_t Passed In To INIT_PeTools  </summary>
	/// <param name="pPEStart"> Start Address of a PE File </param>
	/// <param name="ulHash"> Hash Of The Section Name To Fetch </param>
	/// <returns> Index of section header, -1 If Not Found </returns>
	_Ret_maybenull_ int PETOOLSCALL GetSectionIndexByHash(
		_In_ void* pPEStart,
		_In_ unsigned long ulHash
	);


	NTSTATUS PETOOLSCALL PtWriteVirtualMemory(HANDLE hHand, LPVOID plBaseAddr, LPVOID lpBuffer, ULONG ulNumBytesToWrite, PULONG ulBytesWritten);
	NTSTATUS PETOOLSCALL PtWriteVirtualMemoryInsure(HANDLE hHand, LPVOID plBaseAddr, LPVOID lpBuffer, ULONG ulNumBytesToWrite);
	NTSTATUS PETOOLSCALL PtReadVirtualMemory(
		HANDLE               ProcessHandle,
		PVOID                BaseAddress,
		PVOID               Buffer,
		ULONG                NumberOfBytesToRead,
		PULONG              NumberOfBytesReaded
	);

	NTSTATUS PETOOLSCALL PtReadVirtualMemoryInsure(
		HANDLE               ProcessHandle,
		PVOID                BaseAddress,
		PVOID               Buffer,
		ULONG                NumberOfBytesToRead
	);

	BOOL __stdcall PtVirtualProtect(
		HANDLE hHandle,
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD  flNewProtect,
		PDWORD lpflOldProtect
	);

	// PUNICODE_STRING
	void WINAPI ptRtlInitUnicodeString(void* DestinationString, PCWSTR SourceString);

	// PUNICODE_STRING
	bool WINAPI ptCreateUnicodeStringFromCString(char* szStr, void* str);

	HMODULE ptGetNtDll() [[msvc::forceinline]];


	inline wchar_t* GetFileNameFromPath(wchar_t* Path, bool bStartBeg = false)
	{
		wchar_t* LastSlash = bStartBeg ? Path : NULL;
		for (DWORD i = 0; Path[i] != NULL; i++)
		{
			if (Path[i] == '\\')
				LastSlash = &Path[i + 1];
		}
		return LastSlash;
	}

	LPVOID __stdcall ptAllocateMemory(SIZE_T Size, DWORD dwProtection);
	BOOLEAN PETOOLSCALL AddModuleToPEB(LPVOID pBaseAddress, LPVOID pOriginalMapBase, CHAR* szAccessName);

	inline wchar_t* RemoveFileExtension(wchar_t* FullFileName, wchar_t* OutputBuffer, DWORD OutputBufferSize)
	{
		wchar_t* LastDot = NULL;
		for (DWORD i = 0; FullFileName[i] != NULL; i++)
			if (FullFileName[i] == '.')
				LastDot = &FullFileName[i];

		for (DWORD j = 0; j < OutputBufferSize; j++)
		{
			OutputBuffer[j] = FullFileName[j];
			if (&FullFileName[j] == LastDot)
			{
				OutputBuffer[j] = NULL;
				break;
			}
		}
		OutputBuffer[OutputBufferSize - 1] = NULL;
		return OutputBuffer;
	}


	// Misc

	std::vector<std::string> FetchAllImportedModules(void* pPEFile, size_t nFileSize, bool bIsMapped);


}


namespace CLRPeTools
{

}
#endif