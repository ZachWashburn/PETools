// PETools.cpp : Defines the functions for the static library.
//

#include <PETools.h>
#include <winternl.h>
#include <Windows.h>
#include <SubAuth.h>
#include <PEBStructs.h>
#include <string>
#include <fstream>
#ifdef PETOOLS_USE_SYSCALLS
#include <WindowsSysCalls.h>

int SysCall::GetSysCodeForHash(unsigned long ulHash)
{
	unsigned char* pFunc = (unsigned char*)PETools::_GetExportAddress(PETools::ptGetNtDll(), 0, ulHash, &SysCallDefaultHasher);
	return GetSysCodeFromFuncx86(pFunc);
}

#endif // PETOOLS_USE_SYSCALLS
namespace PETools
{

	typedef NTSTATUS(WINAPI fnLdrGetDllPath_t)
		(PCWSTR _module,
			ULONG flags,
			PWSTR* path,
			PWSTR* unknown
	);

	typedef NTSTATUS(WINAPI* fnLdrLoadDll_t) //LdrLoadDll function prototype 
		(
			IN PWCHAR PathToFile OPTIONAL,
			IN ULONG Flags OPTIONAL,
			IN PUNICODE_STRING ModuleFileName,
			OUT PHANDLE ModuleHandle
			);

	typedef VOID(__stdcall* fnRtlRbInsertNodeEx_t)(
		RTL_RB_TREE* Tree,
		RTL_BALANCED_NODE* Parent,
		BOOLEAN Right,
		RTL_BALANCED_NODE* Node);
	typedef VOID(__stdcall* fnRtlInitUnicodeString_t)(
		void* DestinationString,
		__drv_aliasesMem PCWSTR SourceString
		);

	typedef NTSTATUS(__stdcall* fnNtQuerySystemTime_t)(
		PLARGE_INTEGER SystemTime
		);
	typedef NTSTATUS(__stdcall* fnRtlHashUnicodeString_t)(
		PUNICODE_STRING String,
		BOOLEAN          CaseInSensitive,
		ULONG            HashAlgorithm,
		PULONG           HashValue
		);

	typedef int (WINAPI* fnRtlNtPathNameToDosPathName)(
		int Flags, RTL_UNICODE_STRING_BUFFER2* RTLPATH, DWORD* Disposition, PWSTR* FilePart
	);


	typedef _Check_return_ NTSTATUS(NTAPI* fnNtProtectVirtualMemory_t)(
			_In_ HANDLE               ProcessHandle,
			_Outptr_ PVOID*			BaseAddress,
			_Outptr_ PULONG           NumberOfBytesToProtect,
			_In_ ULONG                NewAccessProtection,
			_In_ PULONG              OldAccessProtection
	);

#ifdef PETOOLS_NO_LOADER_INCLUDES

	// Not Entirely Correct, TODO : Finish!
	errno_t _pet_memcpy_s(void* pDataOut, unsigned int usDataOutSize, void* pDataIn, unsigned int usDataInSize)
	{
		if (usDataInSize > usDataOutSize)
			return EINVAL;
#ifdef _WIN64

		for (int i = 0; i < usDataInSize; i++)
			pDataOut[i] = pDataIn[i];

#else
		_asm {
			mov ecx, usDataInSize
			mov edi, pDataOut
			mov esi, pDataIn
			cld // set df flag so movsb increments pointers (DF = 0)
			rep movsb // copy data 
		}
#endif
		return 0;
	}

	constexpr size_t _pet_strlen(const char* str)
	{
		const char* s;
		for (s = str; *s; ++s)
		{}
		return (s - str);
	}

	constexpr size_t _pet_strlen(const wchar_t* str)
	{
		const wchar_t* s;
		for (s = str; *s; ++s)
		{
		}
		return (s - str);
	}

	int _pet_strcmp(const char* s1, const char* s2)
	{
		while (*s1 == *s2++)
			if (*s1++ == 0)
				return (0);
		return (*(unsigned char*)s1 - *(unsigned char*)--s2);
	}


	int _pet_atoi(const char* str)
	{
		int res = 0;
		for (int i = 0; str[i] != '\0'; ++i)
			res = res * 10 + str[i] - '0';
		return res;
	}

	const char* _pet_strchr(register const char* s, int c)
	{
		do {
			if (*s == c)
				return (char*)s;
			} while (*s++);
		return (0);
	}

	char* _pet_strcpy(char* dest, const char* src)
	{
		size_t stLen = strlen(src) + 1;
		_pet_memcpy_s(dest, stLen, (void*)src, stLen);
		return dest;
	}

	wchar_t* _pet_strcpy(wchar_t* dest, const wchar_t* src)
	{
		wchar_t* p;

		if ((dest == 0) || (src == 0))
			return dest;

		if (dest == src)
			return dest;

		p = dest;
		while (*src != 0) {
			*p = *src;
			p++;
			src++;
		}

		*p = 0;
		return dest;
	}

	void* _pet_memset(void* dest, int val, size_t len)
	{
		unsigned char* ptr = (unsigned char*)dest;
		while (len-- > 0)
			*ptr++ = val;
		return dest;
	}

	size_t _pet_strnlen(const char* s, size_t maxlen)
	{
		size_t i;
		for (i = 0; i < maxlen; ++i)
			if (s[i] == '\0')
				break;
		return i;
	}

	char* _pet_strncpy(char* s1, const char* s2, size_t n)
	{
		size_t size = _pet_strnlen(s2, n);
		if (size != n)
			_pet_memset(s1 + size, '\0', n - size);
		_pet_memcpy_s(s1, size, (void*)s2, size);
		return s1;
	}


#define UC(c)	((unsigned char)c)


	char _pet_isupper(unsigned char c)
	{
	    if (c >= UC('A') && c <= UC('Z'))
	        return 1;
	    return 0;
	}
	int _pet_tolower(wchar_t c)
	{
		if ((unsigned char)c <= 0x7f)
			return _pet_isupper(c) ? c - 'A' + 'a' : c;
#if 0
		else if (c != EOF && MB_CUR_MAX == 1 && _pet_isupper(c))
		{
			char s[MB_LEN_MAX] = { c, '\0' };



			wchar_t wc;
			wc = *s
			*s = (char)_pet_tolower(wc);
			c = (unsigned char)s[0];
							
		}
#endif
		return c;
	}



	int _pet__wcsicmp_s1(const wchar_t* cs,
		const wchar_t* ct
	)
	{
		while (_pet_tolower(*cs) == _pet_tolower(*ct))
		{
			if (*cs == 0)
				return 0;
			cs++;
			ct++;
		}
		return _pet_tolower(*cs) - _pet_tolower(*ct);
	}	

	int _pet__wcsicmp(const wchar_t* cs,
		const wchar_t* ct
	)
	{
		while (_pet_tolower(*cs) == _pet_tolower(*ct))
		{
			if (*cs == 0)
				return 0;
			cs++;
			ct++;
			if (*cs == 0)
				return 0;
		}
		return _pet_tolower(*cs) - _pet_tolower(*ct);
	}
// Starting To Feel Like Valve Doing This...
#define memcpy_s(a,b,c,d) _pet_memcpy_s(a,b,c,d)
#define strlen(a) _pet_strlen(a)
#define strcmp(a,b) _pet_strcmp(a,b)
#define atoi(a) _pet_atoi(a)
#define strchr(a, b) _pet_strchr(a, b)
#define strcpy(a, b) _pet_strcpy(a, b)
#define memset(a, b, c) _pet_memset(a, b, c)
#define strnlen(a, b) _pet_strnlen(a, b)
#define strncpy(a, b, c) _pet_strncpy(a, b, c)
#define tolower(a) _pet_tolower(a)
#define _wcsicmp(a, b) _pet__wcsicmp(a,b)

#endif
	struct pe_tools_mapped_module_t
	{
		LPVOID m_pBaseAddress;
		LPVOID m_pEndAddress;
		pe_tools_mapped_module_t* m_pPrevious;
		pe_tools_mapped_module_t* m_pNext;
	};

	class __declspec(novtable) MappedModuleList
	{
	public:
		inline pe_tools_mapped_module_t* AddModule(LPVOID pBase, LPVOID pEnd)
		{
			pe_tools_mapped_module_t* pMod = (pe_tools_mapped_module_t*)ptAllocateMemory(sizeof(pe_tools_mapped_module_t), PAGE_READWRITE);
			memset(pMod, 0, sizeof(pMod));

			pMod->m_pPrevious = FindLastItem();
			pMod->m_pBaseAddress = pBase;
			pMod->m_pEndAddress = pEnd;
			if (pMod->m_pPrevious)
				pMod->m_pPrevious->m_pNext = pMod;
			else
				m_pModuleList = pMod;
			return pMod;
		}

		inline pe_tools_mapped_module_t* FindLastItem()
		{
			if (!m_pModuleList)
				return nullptr;

			pe_tools_mapped_module_t* pLastEntry = m_pModuleList;

			while (pLastEntry->m_pNext)
			{
				pLastEntry = (pe_tools_mapped_module_t*)pLastEntry->m_pNext;
			}

			return pLastEntry;
		}


		bool IsAddressWithinOurModules(LPVOID pAddr)
		{
			if (!m_pModuleList)
				return false;

			pe_tools_mapped_module_t* pLastEntry = m_pModuleList;

			while (pLastEntry->m_pNext)
			{
				if (pLastEntry->m_pBaseAddress <= pAddr && pLastEntry->m_pEndAddress > pAddr)
					return true;

				pLastEntry = (pe_tools_mapped_module_t*)pLastEntry->m_pNext;
			}

			return false;
		}

		pe_tools_mapped_module_t* m_pModuleList;
	};
	MappedModuleList* g_pModList = nullptr;

#define PETOOLS_WINDOWS_FUNC(func) decltype(&func) m_pfn##func;
	struct pe_tools_globals_t
	{
		PETOOLS_WINDOWS_FUNC(VirtualProtect)
		PETOOLS_WINDOWS_FUNC(VirtualAlloc)
		PETOOLS_WINDOWS_FUNC(GetProcAddress)
		PETOOLS_WINDOWS_FUNC(LoadLibraryA)
		PETOOLS_WINDOWS_FUNC(GetProcessHeap)
		PETOOLS_WINDOWS_FUNC(HeapAlloc)
		PETOOLS_WINDOWS_FUNC(VirtualFree)
		fnRtlInitUnicodeString_t m_pfnRtlInitUnicodeString;
		fnNtQuerySystemTime_t m_pfnNtQuerySystemTime;
		fnRtlHashUnicodeString_t m_pfnRtlHashUnicodeString;
		fnRtlRbInsertNodeEx_t m_pfnRtlRbInsertNodeEx;
		fnPEToolsHasher_t m_pfnHasher;
		fnLdrLoadDll_t m_pfnLdrLoadDll;
	} *g_Globals; // i like hungarian but this is repetitive!
#undef PETOOLS_WINDOWS_FUNC

	DWORD align(DWORD size, DWORD align, DWORD addr) {
		if (!(size % align))
			return addr + size;
		return addr + (size / align + 1) * align;
	}


	LONG NTAPI ExceptionHandler(_EXCEPTION_POINTERS* ExceptionInfo);

#define _A 54059 /* a prime */
#define _B 76963 /* another prime */
//#define C 86969 /* yet another prime */
#define FIRSTH 37 /* also prime */
	constexpr unsigned long PETOOLSCALL PeToolsDefaultHasher(char* s)
	{
		unsigned long h = FIRSTH;
		while (*s) {
			h = (h * _A) ^ (_pet_tolower(s[0]) * _B);
			s++;
		}
		return h; // or return h % C;
	}

	PIMAGE_BASE_RELOCATION NTAPI LdrProcessRelocationBlockLongLong(IN ULONG_PTR  	Address,
		IN ULONG  	Count,
		IN PUSHORT  	TypeOffset,
		IN LONGLONG  	Delta
	);






	void blah()
	{

	}

	/*
	 Introduction

	This Proof-Of-Concept (POC) code demonstrates the dynamic loading of a Win32 EXE into the memory space of a process that was created using the CreateProcess API with the CREATE_SUSPENDED parameter. This code also shows how to perform manual relocation of a Win32 EXE and how to unmap the original image of an EXE from its process space.

	Description of Technique

	Under Windows, a process can be created in suspend mode using the CreateProcess API with the CREATE_SUSPENDED parameter. The EXE image will be loaded into memory by Windows but execution will not begin until the ResumeThread API is used. Before calling ResumeThread, it is possible to read and write this process's memory space using APIs like ReadProcessMemory and WriteProcessMemory. This makes it possible to overwrite the image of the original EXE with the image of another EXE, thus enabling the execution of the second EXE within the memory space of the first EXE. This can be achieved with the following sequence of steps.

    Use the CreateProcess API with the CREATE_SUSPENDED parameter to create a suspended process from any EXE file. (Call this the first EXE).

    Call GetThreadContext API to obtain the register values (thread context) of the suspended process. The EBX register of the suspended process points to the process's PEB. The EAX register contains the entry point of the process (first EXE).

    Obtain the base-address of the suspended process from its PEB, i.e. at [EBX+8]

    Load the second EXE into memory (using ReadFile) and perform the neccessary alignment manually. This is required if the file alignment is different from the memory alignment

    If the second EXE has the same base-address as the suspended process and its image-size is <= to the image-size of the suspended process, simply use the WriteProcessMemory function to write the image of the second EXE into the memory space of the suspended process, starting at the base-address.

    Otherwise, unmap the image of the first EXE using ZwUnmapViewOfSection (exported by ntdll.dll) and use VirtualAllocEx to allocate enough memory for the second EXE within the memory space of the suspended process. The VirtualAllocEx API must be supplied with the base-address of the second EXE to ensure that Windows will give us memory in the required region. Next, copy the image of the second EXE into the memory space of the suspended process starting at the allocated address (using WriteProcessMemory).

    If the unmap operation failed but the second EXE is relocatable (i.e. has a relocation table), then allocate enough memory for the second EXE within the suspended process at any location. Perform manual relocation of the second EXE based on the allocated memory address. Next, copy the relocated EXE into the memory space of the suspended process starting at the allocated address (using WriteProcessMemory).

    Patch the base-address of the second EXE into the suspended process's PEB at [EBX+8].

    Set EAX of the thread context to the entry point of the second EXE.

    Use the SetThreadContext API to modify the thread context of the suspended process.

    Use the ResumeThread API to resume execute of the suspended process.	
	*/

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
		_In_opt_ fnPEToolsHasher_t pfnHasher /* = nullptr */
	)
	{
#ifdef PETOOLS_USE_SYSCALLS

		HMODULE hNtdll = ptGetNtDll();
		SysCall::g_pNTTestAlertPtr = _GetExportAddress(hNtdll, NULL, 0x51eb21ff, PETools::PeToolsDefaultHasher);
#endif

		g_Globals = (pe_tools_globals_t*)malloc(sizeof(pe_tools_globals_t));
		memset(g_Globals, 0, sizeof(pe_tools_globals_t));

		g_Globals->m_pfnHasher = pfnHasher;
		g_Globals->m_pfnVirtualAlloc = pfnVirtualAlloc;
		g_Globals->m_pfnVirtualProtect = pfnVirtualProtect;
		g_Globals->m_pfnLoadLibraryA = pfnLoadLibraryA;
		g_Globals->m_pfnVirtualAlloc = pfnVirtualAlloc;
		g_Globals->m_pfnGetProcAddress = pfnGetProcAddress;
		g_Globals->m_pfnGetProcessHeap = pfnGetProcessHeap;
		g_Globals->m_pfnHeapAlloc = pfnHeapAlloc;
		g_Globals->m_pfnRtlInitUnicodeString = (fnRtlInitUnicodeString_t)ptRtlInitUnicodeString;
		g_Globals->m_pfnNtQuerySystemTime = (fnNtQuerySystemTime_t)pfnNtQuerySystemTime;
		g_Globals->m_pfnRtlRbInsertNodeEx = (fnRtlRbInsertNodeEx_t)pfnRtlRbInsertNodeEx;
		g_Globals->m_pfnRtlHashUnicodeString = (fnRtlHashUnicodeString_t)pfnRtlHashUnicodeString;
		g_Globals->m_pfnLdrLoadDll = (fnLdrLoadDll_t)pfnLdrLoadDLL;

	}

	void PETOOLSCALL INIT_PETools_NoPass(
		_In_opt_ fnPEToolsHasher_t pfnHasher /*= nullptr*/
	)
	{
#ifdef PETOOLS_USE_SYSCALLS

		HMODULE hNtdll = ptGetNtDll();
		constexpr unsigned long test_alert_hash = PeToolsDefaultHasherConstExpr<const char*>("NtTestAlert");
		SysCall::g_pNTTestAlertPtr = _GetExportAddress(hNtdll, NULL, test_alert_hash, PETools::PeToolsDefaultHasher);
#endif

		//HMODULE ntdll = GetModuleHandleA("ntdll.dll");
#if 0	// GAH WINDOWS LINKING IMPORTS!
		INIT_PETools(&VirtualProtect,
			&VirtualAlloc,
			&GetProcAddress,
			&LoadLibraryA,
			&GetProcessHeap,
			&HeapAlloc,
			GetProcAddress(ntdll, "RtlInitUnicodeString"),
			GetProcAddress(ntdll, "NtQuerySystemTime"),
			GetProcAddress(ntdll, "RtlHashUnicodeString"),
			GetProcAddress(ntdll, "LdrLoadDll"),
			pfnHasher
		);
#endif
	}

	typedef struct
	{
		WORD	offset : 12;
		WORD	type : 4;
	} IMAGE_RELOC, * PIMAGE_RELOC;

	_Check_return_  _Ret_maybenull_ [[nodiscard]] void* PETOOLSCALL MapToMemory(
		_In_reads_(nFileSize) void* pPEFileData,
		_In_ size_t nFileSize,
		_In_opt_z_ const char* szAccessName /* = nullptr */,
		_In_opt_   bool bCallEntry /*= false*/
	)
	{
		if (!pPEFileData)
			return nullptr;

		if (!SysCall::g_pNTTestAlertPtr)
		{
			HMODULE hNtdll = ptGetNtDll();
			SysCall::g_pNTTestAlertPtr = _GetExportAddress(hNtdll, NULL, 0x51eb21ff, PETools::PeToolsDefaultHasher);
		}

		if (!g_pModList)
		{
			g_pModList = (MappedModuleList*)ptAllocateMemory(sizeof(MappedModuleList), PAGE_READWRITE);
			*g_pModList = MappedModuleList();
		}


		PIMAGE_DOS_HEADER pDos = GetDosHeader(pPEFileData);

		if (pDos->e_magic != 0x5A4D)
			return nullptr;

		PIMAGE_NT_HEADERS pNT = reinterpret_cast<PIMAGE_NT_HEADERS>((char*)pPEFileData + pDos->e_lfanew);
		PIMAGE_OPTIONAL_HEADER pOpt = &pNT->OptionalHeader;
		PIMAGE_FILE_HEADER pFile = &pNT->FileHeader;

		DWORD pOriginalBase = pOpt->ImageBase;

		// everyone allocates everything as PAGE_READWRITE_EXECUTE... that's not correct 
		LPVOID pMappedModuleMem = PtVirtualAlloc((LPVOID)pOpt->ImageBase, pOpt->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		


		if (!pMappedModuleMem)
		{
			// This doesn't support dynamic base. crud!
			if ((pOpt->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0)
				return nullptr;

			pMappedModuleMem = PtVirtualAlloc(nullptr, pOpt->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		}

		if (!pMappedModuleMem)
		{
#ifdef _DEBUG
			printf("Unable To Allocate PE File Memory!\n");
#endif
			return nullptr;
		}

#ifdef PE_TOOLS_ALLOW_INLINE_LAMBDAS
		static FreeBuffer = [&]() [[msvc::forceinline]]
		{
			ptFreeMemory(pMappedModuleMem);
		};
#define FREE_AND_EXIT() FreeBuffer(); return nullptr;
#else
#define FREE_AND_EXIT() ptFreeMemory(pMappedModuleMem); return nullptr;
#endif

		
		if (!MapPESectionsToMemory(pPEFileData, nFileSize, pMappedModuleMem, pOpt->SizeOfImage))
		{
#ifdef _DEBUG
			printf("Unable To Map PE Sections To Memory!\n");
#endif
			FREE_AND_EXIT();
		}


		if (!ResolveImports(pMappedModuleMem, (decltype(&LoadLibraryA))&MapFromDisk, (decltype(&GetProcAddress))&GetExportAddress))
		{
#ifdef _DEBUG
			printf("Unable To Resolve IAT!\n");
#endif
			FREE_AND_EXIT();
		}


		if (!ResolveRelocs(pMappedModuleMem, true))
		{
#ifdef _DEBUG
			printf("Unable To Run Relocs !\n");
#endif
			FREE_AND_EXIT();
		}

		if (!ResolveMemoryPermissions(pMappedModuleMem))
		{
#ifdef _DEBUG
			printf("Unable To Resolve Memory Permissions!\n");
#endif
			FREE_AND_EXIT();
		}

		if (!RunTLSCallBacks(pMappedModuleMem))
		{
#ifdef _DEBUG
			printf("Unable To Run TLS Callbacks!\n");
#endif
			FREE_AND_EXIT();
		}


		// BOOLEAN PETOOLSCALL AddModuleToPEB(LPVOID pBaseAddress, LPVOID pOriginalMapBase, CHAR * szAccessName)

		if (szAccessName)
		{
			if (!AddModuleToPEB(pMappedModuleMem, (LPVOID)pOriginalBase, (CHAR*)szAccessName))
			{
#ifdef _DEBUG
				printf("Unable To Link To PEB!\n");
#endif
				FREE_AND_EXIT();

			}
		}


		if (g_pModList)
			g_pModList->AddModule(pMappedModuleMem, (char*)pMappedModuleMem + pOpt->SizeOfImage);

		// todo REBUILD DONT GET ! 0xcfa460bd

		// set up exception handling 
		// oid ***__stdcall RtlAddVectoredExceptionHandler(int a1, int a2)
		decltype(&AddVectoredExceptionHandler) RtlAddVectoredExceptionHandler
			= (decltype(&AddVectoredExceptionHandler))_GetExportAddress(ptGetNtDll(), 0, 0xcfa460bd, &PeToolsDefaultHasher);
		
		if(RtlAddVectoredExceptionHandler)
			RtlAddVectoredExceptionHandler(1, &ExceptionHandler);


		if (bCallEntry && pOpt->AddressOfEntryPoint)
		{
			PLDR_INIT_ROUTINE pEntry = (PLDR_INIT_ROUTINE)GetFileEntryPoint(pMappedModuleMem);
			__try
			{
				pEntry(pMappedModuleMem, DLL_PROCESS_ATTACH, NULL);
			}
			__except (EXCEPTION_EXECUTE_HANDLER)
			{
				// well crap-o-roni
				// VCRUNTIME140.dll why do you do this!?
				return pMappedModuleMem;
			}
		}

		return pMappedModuleMem;
	}

	bool _ResolveMemoryPermissionsShellCode(void* pMappedModuleMem, decltype(&VirtualProtect) virtprotect);
	bool __declspec(safebuffers)ResolveRelocsShellCode(void* pMappedModuleMem, bool bSetImageBase /* = true */, decltype(&LdrProcessRelocationBlockLongLong) ldrProcessReloc);

	struct mapper_data_t
	{
		void* m_pBaseAddress;
		decltype(&RunTLSCallBacks) m_pfnTlsCallBack;
		decltype(&ResolveImports) m_pfnResolveImports;
		decltype(&ResolveRelocsShellCode) m_pfnResolveRelocs;
		decltype(&LoadLibraryA) m_pfnLoadLibraryA;
		decltype(&GetProcAddress) m_pfnGetProcAddress;
		decltype(&VirtualProtect) m_pfnVirtualProtect;
		decltype(&_ResolveMemoryPermissionsShellCode) m_pfnResolveMemProtections;
		decltype(&LdrProcessRelocationBlockLongLong) m_pfnLdrprocessrelocblocklong;
		bool m_bCallDllMain = true;
		bool m_bIsEXE = false;
	};

	__declspec(safebuffers) DWORD __stdcall ShellCode(
		LPVOID lpThreadParameter
	);


	bool MapDLLToProcess(HANDLE hHandle, void* pPEFileData, size_t nPESize, BOOLEAN bCallDLLMain/* = true*/, PVOID* pModuleBaseAddress/* = nullptr*/, BOOLEAN bIsEXE /* = false */)
	{
		if (!pPEFileData)
			return false;

		if (!SysCall::g_pNTTestAlertPtr)
		{
			// 0x51eb21ff
			HMODULE hNtdll = ptGetNtDll();
			constexpr unsigned long nt_alert_hash = PeToolsDefaultHasherConstExpr<const char*>("NtTestAlert");
			SysCall::g_pNTTestAlertPtr = _GetExportAddress(hNtdll, NULL, nt_alert_hash, PETools::PeToolsDefaultHasher);
		}


		PIMAGE_DOS_HEADER pDos = GetDosHeader(pPEFileData);

		if (pDos->e_magic != 0x5A4D)
			return false;

		PIMAGE_NT_HEADERS pNT = reinterpret_cast<PIMAGE_NT_HEADERS>((char*)pPEFileData + pDos->e_lfanew);
		PIMAGE_OPTIONAL_HEADER pOpt = &pNT->OptionalHeader;
		PIMAGE_FILE_HEADER pFile = &pNT->FileHeader;

		DWORD pOriginalBase = pOpt->ImageBase;

		// everyone allocates everything as PAGE_READWRITE_EXECUTE... that's not correct 
		LPVOID pMappedModuleMem = PtVirtualAlloc(hHandle, (LPVOID)pOpt->ImageBase, pOpt->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

		if (!pMappedModuleMem)
		{
			// This doesn't support dynamic base. crud!
			if ((pOpt->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE) == 0)
				return false;

			pMappedModuleMem = PtVirtualAlloc(hHandle, nullptr, pOpt->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		}

		if (!pMappedModuleMem)
		{
#ifdef _DEBUG
			printf("Unable To Allocate PE File Memory!\n");
#endif
			return false;
		}

		if (pModuleBaseAddress)
			*pModuleBaseAddress = pMappedModuleMem;


		if (!MapPESectionsToMemoryEx(hHandle, pPEFileData, nPESize, pMappedModuleMem, pOpt->SizeOfImage))
		{
#ifdef _DEBUG
			printf("Unable To Map PE Section Memory!\n");
#endif
			return false;
		}

		auto MapFunctionToMemory = [&](void* pFunctionPtr, size_t* nRegSize) -> void* [[msvc::forceinline]]
		{
			 PVOID BaseAddress = 0;
			 SIZE_T regSize = 0x1000;
			 DWORD dwoProtect = NULL;
			 ULONG ulNumBytesWritten = NULL;

			 NTSTATUS ntStat = PtNtAllocateVirtualMemory(hHandle, &BaseAddress, 0, &regSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

			 if (!NT_SUCCESS(ntStat))
				 return nullptr;

	
			 ntStat = PtWriteVirtualMemory(hHandle, BaseAddress, pFunctionPtr, regSize, &ulNumBytesWritten);

			 if (!NT_SUCCESS(ntStat))
				 return nullptr;

			 if (ulNumBytesWritten < regSize)
				 return nullptr;

			 *nRegSize = regSize;

			 PtVirtualProtect(hHandle, BaseAddress, regSize, PAGE_EXECUTE_READ, &dwoProtect);

			 return BaseAddress;
		};


		mapper_data_t map;
		size_t nMappedSize = 0;

#define COPY_FUNC(store, func, size) store = (decltype(store))MapFunctionToMemory(&func, &size);

		COPY_FUNC(map.m_pfnTlsCallBack, RunTLSCallBacks, nMappedSize);

		if(!bIsEXE)
			COPY_FUNC(map.m_pfnResolveImports, ResolveImports, nMappedSize);

		COPY_FUNC(map.m_pfnResolveRelocs, ResolveRelocsShellCode, nMappedSize);
		COPY_FUNC(map.m_pfnResolveMemProtections,_ResolveMemoryPermissionsShellCode, nMappedSize);
		COPY_FUNC(map.m_pfnLdrprocessrelocblocklong, LdrProcessRelocationBlockLongLong, nMappedSize);

		map.m_pBaseAddress = pMappedModuleMem;

		constexpr unsigned long kernel32_hash = PeToolsDefaultHasher((char*)"kernel32.dll");
		constexpr unsigned long load_lib_hash = PeToolsDefaultHasherConstExpr<const char*>("LoadLibraryA");
		constexpr unsigned long virt_pro_hash = PeToolsDefaultHasherConstExpr<const char*>("VirtualProtect");
		constexpr unsigned long get_proc_address_hash = PeToolsDefaultHasherConstExpr<const char*>("GetProcAddress");

		//auto kern = LoadLibraryA("kernel32.dll");
		HMODULE k32 = GetModuleHash(kernel32_hash, &PeToolsDefaultHasher);

		map.m_pfnGetProcAddress = (decltype(map.m_pfnGetProcAddress))_GetExportAddress(k32, 0, get_proc_address_hash, &PeToolsDefaultHasherConstExpr);
		map.m_pfnLoadLibraryA = (decltype(map.m_pfnLoadLibraryA))_GetExportAddress(k32, 0, load_lib_hash, &PeToolsDefaultHasherConstExpr);
		map.m_pfnVirtualProtect = (decltype(map.m_pfnVirtualProtect))_GetExportAddress(k32, 0, virt_pro_hash, &PeToolsDefaultHasherConstExpr);
		// PE Is Mapped, Functions Are Mapped, No We Write The Data And Spawn The Thread
		mapper_data_t* pMapperData = 0;
		SIZE_T nSize = sizeof(pMapperData);

		map.m_bCallDllMain = bCallDLLMain;
		map.m_bIsEXE = bIsEXE;
		PtNtAllocateVirtualMemory(hHandle, (PVOID*)&pMapperData, 0, &nSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		PtWriteVirtualMemory(hHandle, pMapperData, &map, sizeof(map), &nSize);


		LPTHREAD_START_ROUTINE pShellCodeAddr = (decltype(pShellCodeAddr))MapFunctionToMemory(&ShellCode, &nMappedSize);

		HANDLE hThread = 0;
		NTSTATUS ntStat = 0;
		//hThread = CreateRemoteThread(hHandle, 0, 0, pShellCodeAddr, pMapperData, 0, 0);



		ntStat = PtCreateRemoteThread(hHandle, &hThread, pShellCodeAddr, pMapperData);

		//0xC0000022
		// STATUS_ACCESS_DENIED

		if (ntStat == 0xC0000022 || ntStat == STATUS_ACCESS_VIOLATION)
		{
#ifdef _DEBUG
			printf("Couldn't Map To Process, Thread Creation Access Denied!\n");
#endif

			return false;
		}
		else if (!NT_SUCCESS(ntStat))
		{
#ifdef _DEBUG
			printf("Couldn't Spawn Thread!\n");
#endif

			return false;
		}

		return true;
	}

	NTSTATUS ResumeSuspendedProcess(HANDLE hProcess)
	{
		_PROCESS_BASIC_INFORMATION2 pi = { 0 };

		DWORD ReturnLength = 0;
		NTSTATUS ntStat = PtQueryInformationProcess(
			hProcess,
			(DWORD)PROCESSINFOCLASS2::ProcessBasicInformation,
			&pi,
			sizeof(_PROCESS_BASIC_INFORMATION2),
			&ReturnLength
		);

		if (!NT_SUCCESS(ntStat))
			return ntStat;

		PEB2 ProcessPEB;
		PPEB2 pPebAddr = pi.PebBaseAddress;
		ULONG BytesRead = NULL;

		ntStat = PtReadVirtualMemory(hProcess, pPebAddr, &ProcessPEB, sizeof(PEB2), &BytesRead);

		if (!NT_SUCCESS(ntStat))
			return ntStat;

		ULONGLONG imageBase = (ULONGLONG)ProcessPEB.ImageBaseAddress;

		if (!NT_SUCCESS(ntStat))
			return ntStat;

		char PEHeader[0x400];
		ULONG ulNumBytesRead = NULL;
		PtReadVirtualMemory(hProcess, (PVOID)imageBase, PEHeader, sizeof(PEHeader), &ulNumBytesRead);

		LPVOID pEntryAddress = GetFileEntryPoint(PEHeader, (void*)imageBase);

		HANDLE _hThread;
		ntStat = PtCreateRemoteThread(hProcess, &_hThread, (LPTHREAD_START_ROUTINE)pEntryAddress, NULL);

		return ntStat;
	}

	// AND NOW, SCOPE CREEP!
	NTSTATUS ProcessHallowExecSuspendedProcessx86(HANDLE hProcess, HANDLE hThread, void* pPEData, size_t nFileSize)
	{
		_PROCESS_BASIC_INFORMATION2 pi = { 0 };

		DWORD ReturnLength = 0;
		NTSTATUS ntStat = PtQueryInformationProcess(
			hProcess,
			(DWORD)PROCESSINFOCLASS2::ProcessBasicInformation,
			&pi,
			sizeof(_PROCESS_BASIC_INFORMATION2),
			&ReturnLength
		);

		if (!NT_SUCCESS(ntStat))
			return ntStat;

		PEB2 ProcessPEB;
		PPEB2 pPebAddr = pi.PebBaseAddress;
		ULONG BytesRead = NULL;

		ntStat = PtReadVirtualMemory(hProcess, pPebAddr, &ProcessPEB, sizeof(PEB2), &BytesRead);

		if (!NT_SUCCESS(ntStat))
			return ntStat;

		ULONGLONG imageBase = (ULONGLONG)ProcessPEB.ImageBaseAddress;

		

		if (!NT_SUCCESS(ntStat))
			return ntStat;

		PVOID pData = nullptr;
		if (!MapDLLToProcess(hProcess, pPEData, nFileSize, false, &pData))
			return STATUS_INVALID_HANDLE;
	
		ProcessPEB.ImageBaseAddress = pData;

		DWORD bytesWritten = NULL;
		ntStat = PtWriteVirtualMemory(hProcess, pPebAddr, &ProcessPEB, sizeof(PEB2), &bytesWritten);

		if (!NT_SUCCESS(ntStat))
			return ntStat;

		char PEHeader[0x400];
		ULONG ulNumBytesRead = NULL;
		PtReadVirtualMemory(hProcess, (PVOID)pData, PEHeader, sizeof(PEHeader), &ulNumBytesRead);

		LPVOID pEntryAddress = GetFileEntryPoint(PEHeader, pData);

		PCONTEXT pctxThread = NULL;
		ntStat = PtGetContextThread(hThread, pctxThread);

		if (ntStat == STATUS_ACCESS_VIOLATION)
		{
			// okay lets spawn our own then!
			NTSTATUS lessImportantNtStat = PtTerminateThread(hThread, STATUS_SUCCESS);

			HANDLE _hThread;
			ntStat = PtCreateRemoteThread(hProcess, &_hThread, (LPTHREAD_START_ROUTINE)pEntryAddress, NULL);
			// try to kill the previous thread, we sorta don't want it to wake up!
			// todo : byte patch a return if this doesn't work?
			//NTSTATUS lessImportantNtStat = PtTerminateThread(hThread, STATUS_SUCCESS);

			// unmap old
			//ntStat = PtUnmapViewOfSection(hProcess, (PVOID)imageBase);

			return ntStat;
		}
		else if (!NT_SUCCESS(ntStat))
		{
			return ntStat;
		}

#ifdef _DEBUG
		printf("Setting Context To Hijack!\n");
#endif
		//pctxThread->Eip = (DWORD)pEntryAddress;
		pctxThread->Eax = (DWORD)pEntryAddress;

		ntStat = PtSetContextThread(hThread, pctxThread);

		if (!NT_SUCCESS(ntStat))
			return ntStat;

		return PtResumeThread(hThread, 0);
	}


	NTSTATUS StartProcessThreadx64(HANDLE hProcess)
	{
		_PROCESS_BASIC_INFORMATION2 pi = { 0 };

		DWORD ReturnLength = 0;
		NTSTATUS ntStat = PtQueryInformationProcess(
			hProcess,
			(DWORD)PROCESSINFOCLASS2::ProcessBasicInformation,
			&pi,
			sizeof(_PROCESS_BASIC_INFORMATION2),
			&ReturnLength
		);

		if (!NT_SUCCESS(ntStat))
			return ntStat;

		PEB2 ProcessPEB;
		PPEB2 pPebAddr = pi.PebBaseAddress;
		ULONG BytesRead = NULL;

		ntStat = PtReadVirtualMemory(hProcess, pPebAddr, &ProcessPEB, sizeof(PEB2), &BytesRead);

		if (!NT_SUCCESS(ntStat))
			return ntStat;

		ULONGLONG imageBase = (ULONGLONG)ProcessPEB.ImageBaseAddress;

		char PEHeaderBuffer[0x400];

		ntStat = PtReadVirtualMemory(hProcess, (PVOID)imageBase, PEHeaderBuffer, sizeof(PEHeaderBuffer), &BytesRead);

		if (!NT_SUCCESS(ntStat))
			return ntStat;

		PVOID pFileAddr = GetFileEntryPoint(PEHeaderBuffer);

		// TODO : Process Params, Spawn Thread!
	}


	NTSTATUS CreateSuspendedProcessx64(WCHAR* szPath, PHANDLE phHandle)
	{
		// UGH! Rebuild Please!
		constexpr unsigned long kern_32_hash = PeToolsDefaultHasherConstExpr<const char*>("kernel32.dll");
		constexpr unsigned long create_trans_hash = PeToolsDefaultHasherConstExpr<const char*>("CreateFileTransactedW");
		HMODULE kern32 = GetModuleHash(kern_32_hash, &PeToolsDefaultHasher);
		decltype(&CreateFileTransactedW) _CreateFileTransactedW = (decltype(&CreateFileTransactedW))_GetExportAddress(kern32, 0,
			create_trans_hash, &PeToolsDefaultHasher);

		HANDLE hProcess;
		OBJECT_ATTRIBUTES objattr;
		UNICODE_STRING objname;
		NTSTATUS status;
		//WCHAR wstrObjName[MAX_PATH];


		// Initialize ObjectName UNICODE_STRING
		objname.Buffer = szPath;
		objname.Length = strlen(szPath) * sizeof(WCHAR); // Length in bytes of string, without null terminator
		objname.MaximumLength = MAX_PATH * sizeof(WCHAR);


		// Initialize OBJECT_ATTRIBUTES
		objattr.Length = sizeof(OBJECT_ATTRIBUTES);
		objattr.Attributes = OBJ_CASE_INSENSITIVE; // 
		objattr.ObjectName = NULL;
		objattr.RootDirectory = NULL;
		objattr.SecurityDescriptor = NULL;
		objattr.SecurityQualityOfService = NULL;


		HANDLE hTransaction = NULL;
		status = PtCreateTransaction(&hTransaction,
			TRANSACTION_ALL_ACCESS,
			&objattr,
			NULL,
			NULL,
			0,
			0,
			0,
			NULL,
			NULL);

		if (!NT_SUCCESS(status))
			return status;

		// TODO : Implement This Ourselves!
		HANDLE hTransactedFile = _CreateFileTransactedW(
			szPath,
			 GENERIC_READ, // GENERIC_WRITE |
			0 ,
			NULL,
			OPEN_EXISTING,
			FILE_ATTRIBUTE_NORMAL,
			NULL,
			hTransaction,
			NULL,
			NULL);

		if (hTransactedFile == INVALID_HANDLE_VALUE)
		{
#ifdef _DEBUG
			status = GetLastError();
			return status;
#endif
			return STATUS_ACCOUNT_LOCKED_OUT;
		}


		HANDLE hSection = NULL;
		status = PtCreateSection(&hSection,
			SECTION_ALL_ACCESS,
			NULL,
			0,
			PAGE_READONLY,
			SEC_IMAGE,
			hTransactedFile);

		if (!NT_SUCCESS(status))
			return status;

		status = 
			PtCreateProcessEx(&hProcess, PROCESS_ALL_ACCESS, NULL, NtCurrentProcess(),/*PS_INHERIT_HANDLES*/ 4, hSection, NULL, NULL, false);
		
		
		if (!NT_SUCCESS(status))
			return status;


		*phHandle = hProcess;

		
		DWORD pid = GetProcessId(hProcess);
		printf("Pid = %d\n", pid);

		//CloseHandle(hTransactedFile);
		//PtClose(hTransaction);
		//PtClose(hSection);

		return status;
	}



	NTSTATUS CreateSuspendedProcessx86(WCHAR* szPath, PHANDLE phProcessHandle, PHANDLE phThreadHandle)
	{
		WCHAR wszBuffer[MAX_PATH];
		UNICODE_STRING NtImagePath;
		ULONG Buffer = sizeof(wszBuffer);
		NTSTATUS ntStat = STATUS_SUCCESS;

		PtConvertDosPathNameToNT(szPath, wszBuffer, &Buffer);
		ptRtlInitUnicodeString(&NtImagePath, wszBuffer);

		// Create the process parameters
		PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
		ntStat = PtCreateProcessParametersEx(&ProcessParameters, &NtImagePath, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  RTL_USER_PROCESS_PARAMETERS_NORMALIZED);
		//ProcessParameters->ShowWindowFlags = SW_HIDE;
		//ProcessParameters->WindowFlags |= STARTF_USESHOWWINDOW;
		//ProcessParameters->WindowFlags |= STARTF_FORCEONFEEDBACK;

		if (!NT_SUCCESS(ntStat))
			return ntStat;

		// CREATE_NO_WINDOW

		// Initialize the PS_CREATE_INFO structure
		PS_CREATE_INFO2 CreateInfo = { 0 };
		CreateInfo.Size = sizeof(CreateInfo);
		CreateInfo.State = PS_CREATE_STATE2::PsCreateInitialState;

		// Initialize the PS_ATTRIBUTE_LIST structure
		PPS_ATTRIBUTE_LIST2 AttributeList = (PS_ATTRIBUTE_LIST2*)PtAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE2));
		memset(AttributeList, 0, sizeof(PS_ATTRIBUTE_LIST2));
		AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST2) - sizeof(PS_ATTRIBUTE2);
		AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
		AttributeList->Attributes[0].Size = NtImagePath.Length;
		AttributeList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;

		// Create the process
		HANDLE hProcess, hThread = NULL;
		// THREAD_ALL_ACCESS
		ntStat = PtCreateUserProcess(&hProcess, &hThread, PROCESS_ALL_ACCESS,  THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, NULL, NULL, NULL, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, ProcessParameters, &CreateInfo, AttributeList);

		if (!NT_SUCCESS(ntStat))
			return ntStat;

		// Clean up
		//PtFreeHeap(RtlProcessHeap(), 0, AttributeList);
		//PtDestroyProcessParameters(ProcessParameters);
		*phProcessHandle = hProcess;
		*phThreadHandle = hThread;

		return ntStat;
	}


#pragma runtime_checks( "", off )
	/* runtime checks are off in this region */
	__declspec(safebuffers) DWORD  __stdcall ShellCode(
		LPVOID lpThreadParameter
	)
	{
		//_asm int 3
		mapper_data_t* pMapperData = (mapper_data_t*)lpThreadParameter;
		if (!pMapperData->m_bIsEXE)
		{
			pMapperData->m_pfnResolveImports(pMapperData->m_pBaseAddress, pMapperData->m_pfnLoadLibraryA, pMapperData->m_pfnGetProcAddress);
		}

		pMapperData->m_pfnResolveRelocs(pMapperData->m_pBaseAddress, true, pMapperData->m_pfnLdrprocessrelocblocklong);
		pMapperData->m_pfnTlsCallBack(pMapperData->m_pBaseAddress);
		pMapperData->m_pfnResolveMemProtections(pMapperData->m_pBaseAddress, pMapperData->m_pfnVirtualProtect);

		PIMAGE_OPTIONAL_HEADER pHeader = &(reinterpret_cast<PIMAGE_NT_HEADERS>(
			reinterpret_cast<PIMAGE_DOS_HEADER>(pMapperData->m_pBaseAddress)->e_lfanew + (char*)pMapperData->m_pBaseAddress))->OptionalHeader;
		BOOL(WINAPI* _DLLMAIN)(void* hDll, DWORD dwReason, void* pReserved) = (decltype(_DLLMAIN))( (char*)pHeader->ImageBase + pHeader->AddressOfEntryPoint);

		if(pMapperData->m_bCallDllMain)
			_DLLMAIN(pMapperData->m_pBaseAddress, DLL_PROCESS_ATTACH, NULL);
		else if(false)
		{// okay lets call the main one then?
			_asm {
				mov eax, _DLLMAIN
				call eax
			}
		}


		return 0xDEADBEEF;
	}


	bool __declspec(safebuffers) _ResolveMemoryPermissionsShellCode(void* pMappedModuleMem, decltype(&VirtualProtect) virtprotect)
	{
		PIMAGE_SECTION_HEADER pSection = nullptr;
		PIMAGE_DOS_HEADER pDos = reinterpret_cast<PIMAGE_DOS_HEADER>(pMappedModuleMem);
		PIMAGE_NT_HEADERS pNT = reinterpret_cast<PIMAGE_NT_HEADERS>((char*)pMappedModuleMem + pDos->e_lfanew);
		PIMAGE_OPTIONAL_HEADER pOpt = &pNT->OptionalHeader;
		PIMAGE_FILE_HEADER pFile = &pNT->FileHeader;
		PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pNT);


		int nSections = pFile->NumberOfSections;
		for (int i = 0; i < nSections; i++)
		{
			PIMAGE_SECTION_HEADER pSection = &(pFirstSection[i]);
			DWORD dwFlags = 0;
			bool bCanRead = (pSection->Characteristics & IMAGE_SCN_MEM_READ) != 0;
			bool bCanExecute = ((pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) || ((pSection->Characteristics & IMAGE_SCN_CNT_CODE) != 0);
			bool bCanWrite = (pSection->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

			// why isn't virtual protect flags PAGE_EXECUTE | PAGE_READWRITE ...
			if (bCanExecute)
			{
				if (bCanRead && bCanWrite)
					dwFlags = PAGE_EXECUTE_READWRITE;
				else if (bCanRead)
					dwFlags = PAGE_EXECUTE_READ;
				else if (bCanExecute)
					dwFlags = PAGE_EXECUTE;
			}
			else if (bCanRead) // WINDOWS! COME ON! , WHO DESIGNED THIS!?
			{
				if (bCanWrite)
					dwFlags = PAGE_READWRITE;
				else
					dwFlags = PAGE_READONLY;
			}
			else if (!bCanExecute && !bCanRead && !bCanWrite)
			{
				dwFlags = PAGE_NOACCESS;
			}

			//dwFlags = PAGE_EXECUTE_READWRITE;

			DWORD oProtect;
			if (!virtprotect((char*)pMappedModuleMem + pSection->VirtualAddress, pSection->Misc.VirtualSize, dwFlags, &oProtect))
				return false;
		}

		return true;
	}
#pragma runtime_checks( "", restore )
	typedef NTSTATUS(NTAPI* fnNtQuerySystemTime_t)(
		PLARGE_INTEGER SystemTime
	);


	NTSTATUS NTAPI PtRtlHashUnicodeString(
			IN CONST UNICODE_STRING* String,
			IN BOOLEAN CaseInSensitive,
			IN ULONG HashAlgorithm,
			OUT PULONG HashValue)
	{
		if (String != NULL && HashValue != NULL)
		{
			switch (HashAlgorithm)
			{
			case HASH_STRING_ALGORITHM_DEFAULT:
			case HASH_STRING_ALGORITHM_X65599:
			{
				WCHAR* c, * end;

				*HashValue = 0;
				end = String->Buffer + (String->Length / sizeof(WCHAR));

				if (CaseInSensitive)
				{
					for (c = String->Buffer; c != end; c++)
					{
						/* only uppercase characters if they are 'a' ... 'z'! */
						*HashValue = ((65599 * (*HashValue)) +
							(ULONG)(((*c) >= L'a' && (*c) <= L'z') ?
								(*c) - L'a' + L'A' : (*c)));
					}
				}
				else
				{
					for (c = String->Buffer; c != end; c++)
					{
						*HashValue = ((65599 * (*HashValue)) + (ULONG)(*c));
					}
				}
				return STATUS_SUCCESS;
			}
			}
		}

		return STATUS_INVALID_PARAMETER;
	}

	ULONG LdrHashEntry(UNICODE_STRING UniName, BOOL XorHash) {
		ULONG ulRes = 0;

#if 0
		decltype(&PtRtlHashUnicodeString) HashUnic =
			(decltype(&PtRtlHashUnicodeString))GetProcAddress(GetModuleHandleA("ntdll.dll"),
				"RtlHashUnicodeString"
			);


		HashUnic(
			&UniName,
			TRUE,
			0,
			&ulRes
		);
#else
		PtRtlHashUnicodeString(
			&UniName,
			TRUE,
			0,
			&ulRes
		);
#endif

		if (XorHash)
		{
			ulRes &= (LDR_HASH_TABLE_ENTRIES - 1);
		}

		return ulRes;
	}


	VOID InsertTailList(
		PLIST_ENTRY ListHead,
		PLIST_ENTRY Entry
	)
	{
		PLIST_ENTRY Blink;

		Blink = ListHead->Blink;
		Entry->Flink = ListHead;
		Entry->Blink = Blink;
		Blink->Flink = Entry;
		ListHead->Blink = Entry;

		return;
	}

	PLIST_ENTRY FindHashTable() {
		PLIST_ENTRY pList = NULL;
		PLIST_ENTRY pHead = NULL;
		PLIST_ENTRY pEntry = NULL;
		PLDR_DATA_TABLE_ENTRY2 pCurrentEntry = NULL;

		PPEB2 pPeb = (PPEB2)READ_MEMLOC(PEB_OFFSET);

		pHead = &pPeb->Ldr->InInitializationOrderModuleList;
		pEntry = pHead->Flink;

		do
		{
			pCurrentEntry = CONTAINING_RECORD(
				pEntry,
				LDR_DATA_TABLE_ENTRY2,
				InInitializationOrderLinks
			);

			pEntry = pEntry->Flink;

			if (pCurrentEntry->HashLinks.Flink == &pCurrentEntry->HashLinks)
			{
				continue;
			}

			pList = pCurrentEntry->HashLinks.Flink;

			if (pList->Flink == &pCurrentEntry->HashLinks)
			{
				ULONG ulHash = LdrHashEntry(
					pCurrentEntry->BaseDllName,
					TRUE
				);

				pList = (PLIST_ENTRY)(
					(size_t)pCurrentEntry->HashLinks.Flink -
					ulHash *
					sizeof(LIST_ENTRY)
					);

				break;
			}

			pList = NULL;
		} while (pHead != pEntry);

		return pList;
	}

	BOOL AddHashTableEntry(
		PLDR_DATA_TABLE_ENTRY2 pLdrEntry
	)
	{
		PPEB2 pPeb;
		PPEB_LDR_DATA2 pPebData;
		PLIST_ENTRY LdrpHashTable;

		pPeb = (PPEB2)READ_MEMLOC(PEB_OFFSET);

		RtlInitializeListEntry(
			&pLdrEntry->HashLinks
		);

		LdrpHashTable = FindHashTable();
		if (!LdrpHashTable)
		{
			return FALSE;
		}

		pPebData = (PPEB_LDR_DATA2)pPeb->Ldr;

		// insert into hash table
		ULONG ulHash = LdrHashEntry(
			pLdrEntry->BaseDllName,
			TRUE
		);

		InsertTailList(
			&LdrpHashTable[ulHash],
			&pLdrEntry->HashLinks
		);

		// insert into other lists
		InsertTailList(
			&pPebData->InLoadOrderModuleList,
			&pLdrEntry->InLoadOrderLinks
		);

		InsertTailList(
			&pPebData->InMemoryOrderModuleList,
			&pLdrEntry->InMemoryOrderLinks
		);

		InsertTailList(
			&pPebData->InInitializationOrderModuleList,
			&pLdrEntry->InInitializationOrderLinks
		);

		return TRUE;
	}


	// Thanks to DarkLoader for helping me out a lot. Spent a few days reversing only to find
	// someone already did the heavy lifting for me!
	// https://github.com/bats3c/DarkLoadLibrary
	// major kudos!
	BOOLEAN PETOOLSCALL AddModuleToPEB(LPVOID pBaseAddress, LPVOID pOriginalMapBase, CHAR* szAccessName)
	{
		WINDOWS_SYSCALL(NtQuerySystemTime, fnNtQuerySystemTime_t, 1572954);
		PLDR_DATA_TABLE_ENTRY2 pldrEntry = (PLDR_DATA_TABLE_ENTRY2)ptAllocateMemory(sizeof(LDR_DATA_TABLE_ENTRY2), PAGE_READWRITE);
		PIMAGE_NT_HEADERS pNt = GetNTHeader(pBaseAddress);
		UNICODE_STRING usAccessName;

		if (!pldrEntry)
			return FALSE;

		_NtQuerySystemTime(&pldrEntry->LoadTime);

		pldrEntry->ReferenceCount = 1;
		pldrEntry->LoadReason = _LDR_DLL_LOAD_REASON::LoadReasonDynamicLoad;//;
		pldrEntry->OriginalBase = (ULONG_PTR)pOriginalMapBase;


		size_t nSizeOfName = strlen(szAccessName) + 1;
		wchar_t* BaseBuffer = (wchar_t*)ptAllocateMemory(nSizeOfName * sizeof(wchar_t), PAGE_READWRITE);
		usAccessName.MaximumLength = nSizeOfName * sizeof(wchar_t);
		usAccessName.Buffer = BaseBuffer;

		if (!ptCreateUnicodeStringFromCString(szAccessName, &usAccessName))
			return FALSE;


		usAccessName.Length = usAccessName.Length * sizeof(wchar_t);

		pldrEntry->BaseNameHashValue = LdrHashEntry(
			usAccessName,
			FALSE
		);

		pldrEntry->ImageDll = TRUE;
		pldrEntry->LoadNotificationsSent = TRUE; 
		pldrEntry->EntryProcessed = TRUE;
		pldrEntry->InLegacyLists = TRUE;
		pldrEntry->InIndexes = TRUE;
		pldrEntry->ProcessAttachCalled = TRUE;
		pldrEntry->InExceptionTable = FALSE;
		pldrEntry->DllBase = pBaseAddress;
		pldrEntry->SizeOfImage = pNt->OptionalHeader.SizeOfImage;
		pldrEntry->TimeDateStamp = pNt->FileHeader.TimeDateStamp;
		pldrEntry->BaseDllName = usAccessName;
		pldrEntry->FullDllName = usAccessName;
		pldrEntry->ObsoleteLoadCount = 1;
		pldrEntry->Flags = LDRP_IMAGE_DLL | LDRP_ENTRY_INSERTED | LDRP_ENTRY_PROCESSED | LDRP_PROCESS_ATTACH_CALLED;

		pldrEntry->DdagNode = (PLDR_DDAG_NODE)ptAllocateMemory(sizeof(LDR_DDAG_NODE), PAGE_READWRITE);

		if (!pldrEntry->DdagNode)
			return FALSE;

		pldrEntry->NodeModuleLink.Flink = &pldrEntry->DdagNode->Modules;
		pldrEntry->NodeModuleLink.Blink = &pldrEntry->DdagNode->Modules;
		pldrEntry->DdagNode->Modules.Flink = &pldrEntry->NodeModuleLink;
		pldrEntry->DdagNode->Modules.Blink = &pldrEntry->NodeModuleLink;
		pldrEntry->DdagNode->State = _LDR_DDAG_STATE::LdrModulesReadyToRun;
		pldrEntry->DdagNode->LoadCount = 1;

		AddHashTableEntry(
			pldrEntry
		);

		if (pNt->OptionalHeader.AddressOfEntryPoint)
			pldrEntry->EntryPoint = (PLDR_INIT_ROUTINE)((char*)pBaseAddress + pNt->OptionalHeader.AddressOfEntryPoint);
		else
			pNt->OptionalHeader.AddressOfEntryPoint = NULL;

		return TRUE;
	}






	void ReflectLoadImports(void* pMappedModuleMem)
	{	
		if (!ResolveImports(pMappedModuleMem, (decltype(&LoadLibraryA))&MapFromDisk, (decltype(&GetProcAddress))&GetExportAddress))
		{
#ifdef _DEBUG
			printf("Unable To Resolve IAT!\n");
#endif
		}

		if (!RunTLSCallBacks(pMappedModuleMem))
		{
#ifdef _DEBUG
			printf("Unable To Run TLS Callbacks!\n");
#endif
		}
	}

	void WINAPI ptRtlInitUnicodeString(void* pBull , PCWSTR SourceString)
	{

		PUNICODE_STRING DestinationString = (PUNICODE_STRING)pBull;
		SIZE_T DestSize;

		if (SourceString)
		{
			const WCHAR* s = SourceString;
			while (*s) s++;
			unsigned int nSize = (unsigned int)(s - SourceString);
			DestSize = nSize * sizeof(WCHAR);
			DestinationString->Length = (USHORT)DestSize;
			DestinationString->MaximumLength = (USHORT)DestSize + sizeof(WCHAR);
		}
		else
		{
			DestinationString->Length = 0;
			DestinationString->MaximumLength = 0;
		}

		DestinationString->Buffer = (PWCHAR)SourceString;
	}


#pragma runtime_checks( "", off )
	bool __declspec(safebuffers) RunTLSCallBacks(void* pMappedModuleMem)
	{
		PIMAGE_OPTIONAL_HEADER pOpt = &(reinterpret_cast<PIMAGE_NT_HEADERS>(
			reinterpret_cast<PIMAGE_DOS_HEADER>(pMappedModuleMem)->e_lfanew + (char*)pMappedModuleMem))->OptionalHeader;

		if (pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
			auto* pTLS = reinterpret_cast<IMAGE_TLS_DIRECTORY*>((char*)pMappedModuleMem + pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
			auto* pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTLS->AddressOfCallBacks);
			for (; pCallback && *pCallback; ++pCallback)
				(*pCallback)((char*)pMappedModuleMem, DLL_PROCESS_ATTACH, nullptr);
		}

		return true;
	}
#pragma runtime_checks( "", restore )
	bool ResolveMemoryPermissions(void* pMappedModuleMem)
	{

		return ResolveMemoryPermissionsEx(NtCurrentProcess(), pMappedModuleMem);
	}

	bool ResolveMemoryPermissionsEx(HANDLE hHandle, void* pMappedModuleMem)
	{
		char PEHeaderBuffer[0x400];

		PtReadVirtualMemoryInsure(hHandle, pMappedModuleMem, PEHeaderBuffer, sizeof(PEHeaderBuffer));

		PIMAGE_SECTION_HEADER pSection = nullptr;
		PIMAGE_DOS_HEADER pDos = GetDosHeader(PEHeaderBuffer);
		PIMAGE_NT_HEADERS pNT = reinterpret_cast<PIMAGE_NT_HEADERS>((char*)PEHeaderBuffer + pDos->e_lfanew);
		PIMAGE_OPTIONAL_HEADER pOpt = &pNT->OptionalHeader;
		PIMAGE_FILE_HEADER pFile = &pNT->FileHeader;
		PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pNT);


		int nSections = pFile->NumberOfSections;
		for (int i = 0; i < nSections; i++)
		{
			PIMAGE_SECTION_HEADER pSection = &(pFirstSection[i]);
			DWORD dwFlags = 0;
			bool bCanRead = (pSection->Characteristics & IMAGE_SCN_MEM_READ) != 0;
			bool bCanExecute = ((pSection->Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) || ((pSection->Characteristics & IMAGE_SCN_CNT_CODE) != 0);
			bool bCanWrite = (pSection->Characteristics & IMAGE_SCN_MEM_WRITE) != 0;

			// why isn't virtual protect flags PAGE_EXECUTE | PAGE_READWRITE ...
			if (bCanExecute)
			{
				if (bCanRead && bCanWrite)
					dwFlags = PAGE_EXECUTE_READWRITE;
				else if (bCanRead)
					dwFlags = PAGE_EXECUTE_READ;
				else if (bCanExecute)
					dwFlags = PAGE_EXECUTE;
			}
			else if (bCanRead) // WINDOWS! COME ON! , WHO DESIGNED THIS!?
			{
				if (bCanWrite)
					dwFlags = PAGE_READWRITE;
				else
					dwFlags = PAGE_READONLY;
			}
			else if (!bCanExecute && !bCanRead && !bCanWrite)
			{
				dwFlags = PAGE_NOACCESS;
			}

			//dwFlags = PAGE_EXECUTE_READWRITE;

			DWORD oProtect;
			if (!PtVirtualProtect(hHandle, (char*)pMappedModuleMem + pSection->VirtualAddress, pSection->Misc.VirtualSize, dwFlags, &oProtect))
				return false;
		}

		return true;
	}
#pragma runtime_checks( "", off )
#define SWAPQ( 	  	x	) 	   (x)
#define SWAPW( 	  	x	) 	   x
#define SWAPD( 	  	x	) 	   x
#define RVA(m, b) ((PVOID)((ULONG_PTR)(b) + (ULONG_PTR)(m)))
	PIMAGE_BASE_RELOCATION NTAPI LdrProcessRelocationBlockLongLong(IN ULONG_PTR  	Address,
		IN ULONG  	Count,
		IN PUSHORT  	TypeOffset,
		IN LONGLONG  	Delta
	)
	{
		SHORT Offset;
		USHORT Type;
		ULONG i;
		PUSHORT ShortPtr;
		PULONG LongPtr;
		PULONGLONG LongLongPtr;

		for (i = 0; i < Count; i++)
		{
			Offset = SWAPW(*TypeOffset) & 0xFFF;
			Type = SWAPW(*TypeOffset) >> 12;
			ShortPtr = (PUSHORT)(RVA(Address, Offset));
			/*
			* Don't relocate within the relocation section itself.
			* GCC/LD generates sometimes relocation records for the relocation section.
			* This is a bug in GCC/LD.
			* Fix for it disabled, since it was only in ntoskrnl and not in ntdll
			*/
			/*
			if ((ULONG_PTR)ShortPtr < (ULONG_PTR)RelocationDir ||
			(ULONG_PTR)ShortPtr >= (ULONG_PTR)RelocationEnd)
			{*/

			if(Type == IMAGE_REL_BASED_HIGH)
				*ShortPtr = HIWORD(MAKELONG(0, *ShortPtr) + (Delta & 0xFFFFFFFF));
			else if(Type == IMAGE_REL_BASED_LOW)
				*ShortPtr = SWAPW(*ShortPtr) + LOWORD(Delta & 0xFFFF);
			else if (Type == IMAGE_REL_BASED_HIGHLOW)
			{
				LongPtr = (PULONG)RVA(Address, Offset);
				*LongPtr = SWAPD(*LongPtr) + (Delta & 0xFFFFFFFF);
			}
			else if (Type == IMAGE_REL_BASED_DIR64)
			{
				LongLongPtr = (PUINT64)RVA(Address, Offset);
				*LongLongPtr = SWAPQ(*LongLongPtr) + Delta;
			}

			TypeOffset++;
		}

		return (PIMAGE_BASE_RELOCATION)TypeOffset;
	}
	// idk if im dense, but this got to be a pain to get working.
	// so reactos ftw!
	bool __declspec(safebuffers)ResolveRelocsShellCode(void* pMappedModuleMem, bool bSetImageBase /* = true */, decltype(&LdrProcessRelocationBlockLongLong) ldrProcessReloc)
	{
		PIMAGE_NT_HEADERS NtHeaders;
		PIMAGE_DATA_DIRECTORY RelocationDDir;
		PIMAGE_BASE_RELOCATION RelocationDir, RelocationEnd;
		ULONG Count;
		ULONG_PTR Address;
		PUSHORT TypeOffset;
		LONGLONG Delta;

		NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<PIMAGE_DOS_HEADER>(pMappedModuleMem)->e_lfanew + (char*)pMappedModuleMem);

		if (NtHeaders == NULL)
			return false;

		if (SWAPW(NtHeaders->FileHeader.Characteristics) & IMAGE_FILE_RELOCS_STRIPPED)
		{
			return false;
		}

		RelocationDDir = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

		if (SWAPD(RelocationDDir->VirtualAddress) == 0 || SWAPD(RelocationDDir->Size) == 0)
		{
			return true;
		}

		Delta = (ULONG_PTR)pMappedModuleMem - SWAPD(NtHeaders->OptionalHeader.ImageBase);
		RelocationDir = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)pMappedModuleMem + SWAPD(RelocationDDir->VirtualAddress));
		RelocationEnd = (PIMAGE_BASE_RELOCATION)((ULONG_PTR)RelocationDir + SWAPD(RelocationDDir->Size));

		while (RelocationDir < RelocationEnd &&
			SWAPW(RelocationDir->SizeOfBlock) > 0)
		{
			Count = (SWAPW(RelocationDir->SizeOfBlock) - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(USHORT);
			Address = (ULONG_PTR)RVA(pMappedModuleMem, SWAPD(RelocationDir->VirtualAddress));
			TypeOffset = (PUSHORT)(RelocationDir + 1);

			RelocationDir = ldrProcessReloc(Address,
				Count,
				TypeOffset,
				Delta);

			if (RelocationDir == NULL)
			{
				//printf("Error during call to LdrProcessRelocationBlockLongLong()!\n");
				return false;
			}
		}

		RelocationDDir = &NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];


		if (bSetImageBase)
			NtHeaders->OptionalHeader.ImageBase = (DWORD)pMappedModuleMem;

		return true;
	}

	bool __declspec(safebuffers) ResolveRelocs(void* pMappedModuleMem, bool bSetImageBase /* = true */)
	{
		return ResolveRelocsShellCode(pMappedModuleMem, bSetImageBase, &LdrProcessRelocationBlockLongLong);
	}

#pragma runtime_checks( "", restore )
#if 0
	bool ResolveRelocs(void* pMappedModuleMem, bool bSetImageBase /* = true */ )
	{
		PIMAGE_OPTIONAL_HEADER pOpt = GetOptionalHeader(pMappedModuleMem);
		// if we didn't get our desired base address
		if ((char*)pMappedModuleMem - pOpt->ImageBase)
		{
			DWORD dwOffset = (DWORD)((char*)pMappedModuleMem - pOpt->ImageBase);
			// No Reallocations????
			PIMAGE_DATA_DIRECTORY pRelocDirectory = &pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
			if (!pRelocDirectory->Size)
				return true;

			PIMAGE_BASE_RELOCATION pHeadReloc =
				reinterpret_cast<IMAGE_BASE_RELOCATION*>((char*)pMappedModuleMem + pRelocDirectory->VirtualAddress);

			
			while (pHeadReloc->SizeOfBlock)
			{
				DWORD dwPatchOffset = (DWORD)((char*)pMappedModuleMem + pHeadReloc->VirtualAddress);
				unsigned int AmountOfEntries = (pHeadReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOC);
				PIMAGE_RELOC pReloc = reinterpret_cast<PIMAGE_RELOC>((char*)pHeadReloc + sizeof(IMAGE_BASE_RELOCATION));

				UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(dwPatchOffset + ((*(WORD*)pReloc) & 0xFFF));

				for (unsigned int i = 0; i != AmountOfEntries; ++i, ++pReloc)
				{
					if (
#ifdef _WIN64
						pReloc->type == IMAGE_REL_BASED_DIR64
#else
						pReloc->type == IMAGE_REL_BASED_HIGHLOW
#endif					
						) {

						*pPatch += reinterpret_cast<UINT_PTR>((char*)dwOffset);
					}
					else if (pReloc->type == IMAGE_REL_BASED_HIGH)
						*pPatch += reinterpret_cast<UINT_PTR>((char*)HIWORD(dwOffset));
					else if (pReloc->type == IMAGE_REL_BASED_LOW)
						*pPatch += reinterpret_cast<UINT_PTR>((char*)LOWORD(dwOffset));
				}
				pHeadReloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
					reinterpret_cast<char*>(pHeadReloc) + pHeadReloc->SizeOfBlock);
			}
		}

		if(bSetImageBase)
			pOpt->ImageBase = (DWORD)pMappedModuleMem;

		return true;
	}
#endif
#pragma runtime_checks( "", off )
	bool __declspec(safebuffers) ResolveImports(void* pMappedPEFile, HMODULE(__stdcall* pfnlibLdr)(const char*), FARPROC(__stdcall* pfnGetFunc)(HMODULE, const char*))
	{



		auto pOpt = &(reinterpret_cast<PIMAGE_NT_HEADERS>(
			reinterpret_cast<PIMAGE_DOS_HEADER>(pMappedPEFile)->e_lfanew + (char*)pMappedPEFile))->OptionalHeader;

		// It's Basically The Same Code, Lets Just Do This
		char Tables[] = { IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT };
		PIMAGE_DATA_DIRECTORY pDataDirectory = &pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

		for (int i = 0; i < sizeof(Tables); i++, pDataDirectory = &(pOpt->DataDirectory[Tables[i]]))
		{
			if (!pDataDirectory->Size)
				continue;

			// Since Structures Are Slightly Different
			bool bDelayed = Tables[i] == IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT;

			PIMAGE_IMPORT_DESCRIPTOR piDescriptor = bDelayed ? nullptr :
				reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
					(char*)pMappedPEFile + pDataDirectory->VirtualAddress
			);

			PIMAGE_DELAYLOAD_DESCRIPTOR piDelayDescriptor = bDelayed ? reinterpret_cast<PIMAGE_DELAYLOAD_DESCRIPTOR>(
				(char*)pMappedPEFile + pDataDirectory->VirtualAddress
			) : nullptr;

			// Remove ? Keep ? Undecided Here. According to MSVC This Should Always Be Expanded
			// IDA Shows That Is True On All Build Options But DEBUG.
			// But If This Is Popped Out To ShellCode And It's Not, Isssues Will Arise!
#ifdef PE_TOOLS_ALLOW_INLINE_LAMBDAS // even msvc considers these experimental
			auto IncrementDescriptor = [&]() [[msvc::forceinline]]
			{
				if (bDelayed)
					piDelayDescriptor++;
				else
					 piDescriptor++;
			};
#endif

			for (
				; 
				bDelayed ? piDelayDescriptor->DllNameRVA : piDescriptor->Name; 
#ifdef PE_TOOLS_ALLOW_INLINE_LAMBDAS
				IncrementDescriptor()
#endif
			) // Iterate Each Module Within The Import Table
			{
				char* szMod = reinterpret_cast<char*>((char*)pMappedPEFile +
					(bDelayed ? piDelayDescriptor->DllNameRVA : piDescriptor->Name)
					);

					

				HMODULE hDll = NULL;
				_asm { // call in assembly to stop _Check_ESP call generation
					mov eax, szMod
					push eax
					call pfnlibLdr
					mov hDll, eax
				}
				//pfnlibLdr(szMod);
#ifdef PACK_HERE
				if (!(unsigned int)hDll || (hDll == INVALID_HANDLE_VALUE))
					int l = 0;
#endif

				if (!(unsigned int)hDll || (hDll == INVALID_HANDLE_VALUE))
					return false; // Awww Snap!
				
				PIMAGE_THUNK_DATA ptFirst
					= reinterpret_cast<PIMAGE_THUNK_DATA>((char*)pMappedPEFile + 
						(bDelayed ? piDelayDescriptor->ImportAddressTableRVA : piDescriptor->FirstThunk)
					);


				PIMAGE_THUNK_DATA ptOriginal
					= reinterpret_cast<PIMAGE_THUNK_DATA>((char*)pMappedPEFile +
						(bDelayed ? piDelayDescriptor->ImportNameTableRVA : piDescriptor->OriginalFirstThunk)
					);

				// Borland Compiler Fix.... But Who Still Uses That?
				if (!ptOriginal)
					ptOriginal = ptFirst;

				// Iterate Functions, Fetch Them
				for (; ptOriginal->u1.Function; ++ptOriginal, ++ptFirst) {
					if (IMAGE_SNAP_BY_ORDINAL(ptOriginal->u1.Ordinal)) {
						
						char* szArg = reinterpret_cast<char*>(ptOriginal->u1.Ordinal);
						DWORD dwRes = NULL;
						_asm { // call in assembly to stop _Check_ESP call generation
							mov eax, hDll;
							push eax
							mov eax, szArg
							push eax
							call pfnGetFunc
							mov dwRes, eax
						}

						ptFirst->u1.Function = dwRes;
					}
					else {
						PIMAGE_IMPORT_BY_NAME pImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>((char*)pMappedPEFile + ptOriginal->u1.AddressOfData);

						char* szArg = reinterpret_cast<char*>(pImport->Name);
						DWORD dwRes = NULL;
						_asm { // call in assembly to stop _Check_ESP call generation
							mov eax, szArg;
							push eax
							mov eax, hDll
							push eax
							call pfnGetFunc
							mov dwRes, eax
						}

						ptFirst->u1.Function = dwRes;


						//ptFirst->u1.Function = (ULONG_PTR)pfnGetFunc(hDll, pImport->Name);
					}

					if (!ptFirst->u1.Function)
					{
#ifdef _DEBUG
						if (!IMAGE_SNAP_BY_ORDINAL(ptOriginal->u1.Ordinal))
						{
							//PIMAGE_IMPORT_BY_NAME pImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>((char*)pMappedPEFile + ptOriginal->u1.AddressOfData);
							//printf("Error Fetching Function %s from %s\n", pImport->Name, szMod);
#ifdef PE_TOOLS_IGNORE_IMPORT_ERRORS
							continue;
#endif

						}
#endif
#ifdef PACKERSTUB
						PIMAGE_IMPORT_BY_NAME pImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>((char*)pMappedPEFile + ptOriginal->u1.AddressOfData);
						ptFirst->u1.Function = (DWORD)GetProcAddress(GetModuleHandleA(szMod), pImport->Name);
#endif

						return false;
					}
				}

#ifndef PE_TOOLS_ALLOW_INLINE_LAMBDAS
				if (bDelayed)
					piDelayDescriptor++;
				else
					piDescriptor++;
#endif
			}
		}

		return true;
	}
#pragma runtime_checks( "", restore )
	// todo

	typedef NTSTATUS(NTAPI* fnZwQuerySystemEnvironmentValue_t)(
			__in PUNICODE_STRING VariableName,
			__out_bcount(ValueLength) PWSTR VariableValue,
			__in USHORT ValueLength,
			__out_opt PUSHORT ReturnLength
		);

	typedef NTSTATUS(__stdcall* fnRtlQueryEnvironmentVariable_t)
		(PVOID Environment, PWSTR Name, size_t NameLength,
			PWSTR Value, size_t ValueLength, PSIZE_T ReturnLength
		);

	typedef NTSTATUS(WINAPI* fnRtlExpandEnvironmentStrings_U_t)(PCWSTR,
		const UNICODE_STRING*,
		UNICODE_STRING*,
		ULONG*
		);


	bool ptRtlGetEnviromentVariableA(LPCSTR szEnvVar, PWSTR pBuffer,
		USHORT usBufferSize, PULONG pulRequiredSize)
	{
		constexpr unsigned long RtlExpandEnviromentHash = 0xcf2c0350;

		fnRtlExpandEnvironmentStrings_U_t RtlExpandEnvironmentStrings_U =
			(fnRtlExpandEnvironmentStrings_U_t)_GetExportAddress(ptGetNtDll(), 0, RtlExpandEnviromentHash, PeToolsDefaultHasher);

		memset(pBuffer, 0, usBufferSize);
		UNICODE_STRING EnvVar;


		wchar_t VarStore[MAX_PATH];
		UNICODE_STRING uniName;
		uniName.Buffer = VarStore;
		uniName.Length = 0;
		uniName.MaximumLength = MAX_PATH;

		EnvVar.Buffer = pBuffer;
		EnvVar.Length = 0;
		EnvVar.MaximumLength = usBufferSize / sizeof(wchar_t);

	

		ptCreateUnicodeStringFromCString((char*)szEnvVar, &uniName);

		NTSTATUS ret = RtlExpandEnvironmentStrings_U(NULL, &uniName, &EnvVar, pulRequiredSize);


		return ret == STATUS_SUCCESS;
	}

	bool ptRtlGetEnviromentVariableW(LPWSTR szEnvVar, PWSTR pBuffer,
		USHORT usBufferSize, PULONG pulRequiredSize)
	{
		constexpr unsigned long RtlExpandEnviromentHash = 0xcf2c0350;

		fnRtlExpandEnvironmentStrings_U_t RtlExpandEnvironmentStrings_U =
			(fnRtlExpandEnvironmentStrings_U_t)_GetExportAddress(ptGetNtDll(), 0, RtlExpandEnviromentHash, PeToolsDefaultHasher);

		memset(pBuffer, 0, usBufferSize);
		UNICODE_STRING EnvVar;


		UNICODE_STRING uniName;
		uniName.Buffer = szEnvVar;
		uniName.Length = strlen(szEnvVar) * sizeof(wchar_t);
		uniName.MaximumLength = (strlen(szEnvVar) + 1) * sizeof(wchar_t);



		EnvVar.Buffer = pBuffer;
		EnvVar.Length = 0;
		EnvVar.MaximumLength = usBufferSize / sizeof(wchar_t);




		NTSTATUS ret = RtlExpandEnvironmentStrings_U(NULL, &uniName, &EnvVar, pulRequiredSize);


		return ret == STATUS_SUCCESS;
	}

	HMODULE ptGetNtDll() 
	{
#if 0
		char ntdll[12];
		memset(ntdll, 0, sizeof(ntdll));
		int i = 0;
		ntdll[i++] = PT_GET_STACK_CHARACTER(n, 0x43);
		ntdll[i++] = PT_GET_STACK_CHARACTER(t, 0x43);
		ntdll[i++] = PT_GET_STACK_CHARACTER(d, 0x43);
		ntdll[i++] = PT_GET_STACK_CHARACTER(l, 0x43);
		ntdll[i++] = PT_GET_STACK_CHARACTER(l, 0x43);
		ntdll[i++] = PT_GET_STACK_CHARACTER(dot, 0x43);
		ntdll[i++] = PT_GET_STACK_CHARACTER(d, 0x43);
		ntdll[i++] = PT_GET_STACK_CHARACTER(l, 0x43);
		ntdll[i++] = PT_GET_STACK_CHARACTER(l, 0x43);
		return GetModuleA(ntdll);
#endif
		return GetModuleHash(0x531fe11b, PeToolsDefaultHasher);
	}




//#include <ntdef.h>



	typedef NTSTATUS(WINAPI* fnNtOpenFile_t)(
		PHANDLE            FileHandle,
		ACCESS_MASK        DesiredAccess,
		OBJECT_ATTRIBUTES* ObjectAttributes,
		PIO_STATUS_BLOCK2   IoStatusBlock,
		ULONG              ShareAccess,
		ULONG              OpenOptions
	);

	typedef NTSTATUS(WINAPI* fnNtClose_t)(HANDLE Handle);

	typedef NTSTATUS(WINAPI* fnNtSetInformationFile_t)(
		HANDLE                 FileHandle,
		PIO_STATUS_BLOCK2      IoStatusBlock,
		PVOID                  FileInformation,
		ULONG                  Length,
		FILE_INFORMATION_CLASS2 FileInformationClass
	);


	typedef NTSTATUS(WINAPI* fnNtQueryDirectoryFile_t)(
		 HANDLE                 FileHandle,
		 HANDLE                 Event,
		 PIO_APC_ROUTINE2					ApcRoutine,
		 PVOID                  ApcContext,
		 PIO_STATUS_BLOCK2       IoStatusBlock,
		 PVOID                  FileInformation,
		 ULONG                  Length,
		 FILE_INFORMATION_CLASS2 FileInformationClass,
		 DWORD /*BOOLEAN*/        ReturnSingleEntry,
		 PUNICODE_STRING        FileName,
		 DWORD /*BOOLEAN*/               RestartScan
	);
	constexpr size_t check = sizeof(BOOLEAN);
	// int nLevel, PSTR prefix for debug only
	// https://stackoverflow.com/questions/41854736/windows-driver-kernel-how-enumerate-all-subdirectories-and-files
	



	NTSTATUS __stdcall PtNtAllocateVirtualMemory(
		HANDLE    ProcessHandle,
		PVOID* BaseAddress,
		ULONG_PTR ZeroBits,
		PSIZE_T   RegionSize,
		ULONG     AllocationType,
		ULONG     Protect
	)
	{
		WINDOWS_SYSCALL(NtAllocateVirtualMemory, decltype(&PtNtAllocateVirtualMemory), 24);
		return _NtAllocateVirtualMemory(ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);
	}
	LPVOID __stdcall ptAllocateMemory(SIZE_T Size, DWORD dwProtection)
	{
		LPVOID VirtualMemory = NULL;
		NTSTATUS ntStat = PtNtAllocateVirtualMemory(NtCurrentProcess(), &VirtualMemory, 0, &Size, MEM_RESERVE | MEM_COMMIT, dwProtection);

		if (!NT_SUCCESS(ntStat))
			return nullptr;

		return VirtualMemory;
	}


	LPVOID __stdcall PtVirtualAlloc(
		 LPVOID lpAddress,
		 SIZE_T dwSize,
		 DWORD  flAllocationType,
		 DWORD  flProtect)
	{
		LPVOID VirtualMemory = lpAddress;
		NTSTATUS ntStat = PtNtAllocateVirtualMemory(NtCurrentProcess(), &VirtualMemory, 0, &dwSize, flAllocationType, flProtect);

		if (!NT_SUCCESS(ntStat))
			return nullptr;

		return VirtualMemory;
	}

	LPVOID __stdcall PtVirtualAlloc(
		HANDLE hHandle,
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD  flAllocationType,
		DWORD  flProtect)
	{
		LPVOID VirtualMemory = lpAddress;
		NTSTATUS ntStat = PtNtAllocateVirtualMemory(hHandle, &VirtualMemory, 0, &dwSize, flAllocationType, flProtect);

		if (!NT_SUCCESS(ntStat))
			return nullptr;

		return VirtualMemory;
	}

	BOOL __stdcall PtVirtualProtect(
		 LPVOID lpAddress,
		 SIZE_T dwSize,
		 DWORD  flNewProtect,
		 PDWORD lpflOldProtect)
	{
		WINDOWS_SYSCALL(NtProtectVirtualMemory, fnNtProtectVirtualMemory_t, 80);

		ULONG ulBytesToProtect = dwSize;

		NTSTATUS ntStat = _NtProtectVirtualMemory(NtCurrentProcess(), &lpAddress, &ulBytesToProtect, flNewProtect, lpflOldProtect);

		if (!NT_SUCCESS(ntStat) || ulBytesToProtect < dwSize)
			return false;

		return true;
	}

	BOOL __stdcall PtVirtualProtect(
		HANDLE hHandle,
		LPVOID lpAddress,
		SIZE_T dwSize,
		DWORD  flNewProtect,
		PDWORD lpflOldProtect)
	{
		WINDOWS_SYSCALL(NtProtectVirtualMemory, fnNtProtectVirtualMemory_t, 80);

		ULONG ulBytesToProtect = dwSize;

		NTSTATUS ntStat = _NtProtectVirtualMemory(hHandle, &lpAddress, &ulBytesToProtect, flNewProtect, lpflOldProtect);

		if (!NT_SUCCESS(ntStat) || ulBytesToProtect < dwSize)
			return false;

		return true;
	}

	typedef NTSTATUS(WINAPI* fnNtFreeVirtualMemory_t)(
		HANDLE  ProcessHandle,
		PVOID* BaseAddress,
		PSIZE_T RegionSize,
		ULONG   FreeType
	);

	//constexpr size_t nSize = sizeof(HANDLE);

	typedef NTSTATUS(WINAPI* fnNtCreateFile_t)(
		PHANDLE,
		ACCESS_MASK,
		_OBJECT_ATTRIBUTES2*, 
		PIO_STATUS_BLOCK2,
		PLARGE_INTEGER,
		ULONG,
		ULONG, 
		ULONG,
		ULONG, 
		PVOID, 
		ULONG
	);

	typedef NTSTATUS (WINAPI* fnNtWaitForSingleObject_t)(
		HANDLE         Handle,
		DWORD /*BOOLEAN   */    Alertable,
		PLARGE_INTEGER Timeout
	);

	typedef NTSTATUS(NTAPI*  fnNtCreateEvent_t)(
		 PHANDLE            EventHandle,
		 ACCESS_MASK        DesiredAccess,
		 OBJECT_ATTRIBUTES* ObjectAttributes,
		 EVENT_TYPE2        EventType,
		DWORD /*BOOLEAN   */             InitialState
	);

	void __stdcall ptFreeMemory(LPVOID pAddress)
	{
		WINDOWS_SYSCALL(NtFreeVirtualMemory, fnNtFreeVirtualMemory_t, 30);
		SIZE_T stSize = NULL;
		NTSTATUS ntStat = _NtFreeVirtualMemory(NtCurrentProcess(), &pAddress, &stSize, MEM_RELEASE);
#ifdef _DEBUG
		if (!NT_SUCCESS(ntStat))
			int k = 0;
		else
			int o = 0;
#endif
	}
	typedef NTSTATUS(WINAPI*  fnNtReadFile_t)(
		_In_     HANDLE           FileHandle,
		_In_opt_ HANDLE           Event,
		_In_opt_ PIO_APC_ROUTINE2  ApcRoutine,
		_In_opt_ PVOID            ApcContext,
		_Out_    PIO_STATUS_BLOCK2 IoStatusBlock,
		_Out_    PVOID            Buffer,
		_In_     ULONG            Length,
		_In_opt_ PLARGE_INTEGER   ByteOffset,
		_In_opt_ PULONG           Key
	);

	typedef NTSTATUS(NTAPI* fnNtQueryInformationFile_t)(
		HANDLE                 FileHandle,
		PIO_STATUS_BLOCK2       IoStatusBlock,
		PVOID                  FileInformation,
		ULONG                  Length,
		FILE_INFORMATION_CLASS2 FileInformationClass
	);

	WINDOWS_SYSCALL(ZwOpenDirectoryObject, fnZwOpenDirectoryObject_t, 88);
	WINDOWS_SYSCALL(ZwQuerySystemEnvironmentValue, fnZwQuerySystemEnvironmentValue_t, 351);
	WINDOWS_SYSCALL(NtOpenFile, fnNtOpenFile_t, 51);
	WINDOWS_SYSCALL(NtClose, fnNtClose_t, 196623);
	WINDOWS_SYSCALL(NtSetInformationFile, fnNtSetInformationFile_t, 196623);
	WINDOWS_SYSCALL(NtQueryDirectoryFile, fnNtQueryDirectoryFile_t, 53);
	WINDOWS_SYSCALL(NtCreateFile, fnNtCreateFile_t, 85);
	WINDOWS_SYSCALL(NtWaitForSingleObject, fnNtWaitForSingleObject_t, 851972);
	WINDOWS_SYSCALL(NtCreateEvent, fnNtCreateEvent_t, 72);
	WINDOWS_SYSCALL(NtReadFile , fnNtReadFile_t, 1703942);
	WINDOWS_SYSCALL(NtQueryInformationFile, fnNtQueryInformationFile_t, 17);



	VOID NTAPI OnQueryComplete(
		_In_ PVOID ApcContext,
		_In_ PIO_STATUS_BLOCK2 IoStatusBlock,
		_In_ ULONG Reserved
		)
	{
		int l = 0;
	}


	WCHAR* UnicodeStringToNulTerminated(UNICODE_STRING* str)
	{
		WCHAR* result;
		if (str == NULL)
			return NULL;
		result = (WCHAR*)ptAllocateMemory(str->Length + 2, PAGE_READWRITE);
		if (result == NULL)
			return NULL;

		memcpy_s(result, str->Length + 2, str->Buffer, str->Length);
		result[str->Length] = L'\0';
		return result;
	}

	WCHAR* UnicodeStringToNulTerminated(UNICODE_STRING* str, WCHAR* wszBuffer)
	{
		WCHAR* result;
		if (str == NULL)
			return NULL;

		result = wszBuffer;

		if (result == NULL)
			return NULL;

		memcpy_s(result, str->Length + 2, str->Buffer, str->Length);
		result[str->Length] = L'\0';
		result[str->Length + 1] = L'\0';
		return result;
	}


	NTSTATUS SearchDirectoriesForFile(const WCHAR* pszDirectoryName, const WCHAR* szDllName, WCHAR* pBuffer, SIZE_T nBufferSize, BOOLEAN bDoRecursiveSearch = TRUE, int nRecursion = 0);


	NTSTATUS IsPEFileHeaderAMD64(LPVOID pBuffer, SIZE_T nBufferSize, PBOOLEAN pbIsAMD64)
	{
		if (nBufferSize < 0x0400)
			return STATUS_ACCESS_VIOLATION;


		PIMAGE_DOS_HEADER pDos = GetDosHeader(pBuffer);

		if (pDos->e_magic != 0x5a4d) // any ideas as to why???
		{
			*pbIsAMD64 = true; 
			return STATUS_SUCCESS;
		}

		PIMAGE_FILE_HEADER pFile = GetFileHeader(pBuffer);

		*pbIsAMD64 = (pFile->Machine == IMAGE_FILE_MACHINE_AMD64) || (pFile->Machine == IMAGE_FILE_MACHINE_IA64);
		return STATUS_SUCCESS;
	}

	typedef NTSTATUS(NTAPI* fnRtlDosPathNameToNtPathName_U)(
		_In_opt_z_ PCWSTR  	DosPathName,
		_Out_ PUNICODE_STRING  	NtPathName,
		_Out_opt_ PCWSTR* NtFileNamePart,
		_Out_opt_ PRTL_RELATIVE_NAME_U2  	DirectoryInfo
	);


	BOOLEAN PtConvertDosPathNameToNT(PWSTR wszPath, PWSTR wszBuffer, PULONG BufferSize)
	{
#if 1
		constexpr unsigned long hash_RtlDosPathNameToNtPathName = PeToolsDefaultHasherConstExpr<const char*>("RtlDosPathNameToNtPathName_U");
		fnRtlDosPathNameToNtPathName_U RtlDosPathNameToNtPathName_U =
			(fnRtlDosPathNameToNtPathName_U)_GetExportAddress(ptGetNtDll(), 0, hash_RtlDosPathNameToNtPathName, &PeToolsDefaultHasher);
#endif // undocumented sux!
		UNICODE_STRING NtPath;
		RTL_RELATIVE_NAME_U2 RelPathName;
		PCWSTR FilePart{};

		if (!RtlDosPathNameToNtPathName_U(wszPath, &NtPath, &FilePart, &RelPathName))
			return FALSE;

		memset(wszBuffer, 0, *BufferSize);

		UnicodeStringToNulTerminated(&NtPath, wszBuffer);
		*BufferSize = NtPath.Length;
		return TRUE;
	}


	NTSTATUS ReadFileToBuffer(PWSTR wszPath, BOOLEAN bDosPathName, LPVOID* plpBuffer, SIZE_T* pnFileSize)
	{
		WCHAR wszPathBuffer[MAX_PATH];

		if (bDosPathName)
		{
			ULONG ulBufferSize = sizeof(wszPathBuffer);
			if (!PtConvertDosPathNameToNT(wszPath, wszPathBuffer, &ulBufferSize))
				return STATUS_INVALID_PARAMETER;
		}
		else
		{
			memset(wszPathBuffer, 0, sizeof(wszPathBuffer));
			memcpy_s(wszPathBuffer, sizeof(wszPathBuffer), wszPath, strlen(wszPath));
		}

		LARGE_INTEGER      byteOffset;
		HANDLE handle;
		IO_STATUS_BLOCK2    ioStatusBlock;
		UNICODE_STRING     uniName;
		OBJECT_ATTRIBUTES  objAttr;

		ptRtlInitUnicodeString(&uniName, wszPathBuffer);  // or L"\\SystemRoot\\example.txt"
		InitializeObjectAttributes(&objAttr, &uniName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL, NULL);

		NTSTATUS ntStatus = _NtCreateFile(
			&handle,
			(FILE_READ_DATA | READ_CONTROL | FILE_READ_EA | SYNCHRONIZE), // | SYNCHRONIZE
			&objAttr,
			&ioStatusBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE),
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE, // FILE_SYNCHRONOUS_IO_NONALERT
			NULL, 0);


		if (!NT_SUCCESS(ntStatus))
			return ntStatus;

		if (!NT_SUCCESS(ntStatus))
			return ntStatus;

		_FILE_STANDARD_INFORMATION2 fileInfo = { 0 };
		ntStatus = _NtQueryInformationFile(
			handle,
			&ioStatusBlock,
			&fileInfo,
			sizeof(fileInfo),
			FILE_INFORMATION_CLASS2::FileStandardInformation
		);

		if (!NT_SUCCESS(ntStatus)) {
			return ntStatus;
		}

		SIZE_T nReadOutSize = NULL;
		PVOID pFileMem = nullptr;

		if (!*plpBuffer)
		{
			nReadOutSize = fileInfo.AllocationSize.LowPart;

			if (*pnFileSize)
				nReadOutSize = min(fileInfo.AllocationSize.LowPart, *pnFileSize);

			pFileMem = ptAllocateMemory(nReadOutSize, PAGE_READWRITE);
		}
		else
		{
			nReadOutSize = min(fileInfo.AllocationSize.LowPart, *pnFileSize);
			pFileMem = *plpBuffer;
		}

		if (!pFileMem)
			return STATUS_NO_MEMORY;

		memset(pFileMem, 0xCC, nReadOutSize);

		ioStatusBlock = IO_STATUS_BLOCK2();

		byteOffset.LowPart = byteOffset.HighPart = 0;
		ntStatus = _NtReadFile(handle, NULL, NULL, NULL, &ioStatusBlock,
			pFileMem, nReadOutSize, &byteOffset, NULL);

		if (ntStatus == STATUS_PENDING)
			ntStatus = _NtWaitForSingleObject(handle, TRUE, NULL);


		if (!NT_SUCCESS(ntStatus))
			return ntStatus;

		_NtClose(handle);

		*plpBuffer = pFileMem;
		*pnFileSize = ioStatusBlock.Information;

		return STATUS_SUCCESS;
	}

	bool IsPEFileAMD64(PWCHAR szSearchPathResult, PBOOLEAN pbIsAMD64)
	{
		LARGE_INTEGER      byteOffset;
		HANDLE handle;
		IO_STATUS_BLOCK2    ioStatusBlock;
		UNICODE_STRING     uniName;
		OBJECT_ATTRIBUTES  objAttr;

		ptRtlInitUnicodeString(&uniName, szSearchPathResult);  // or L"\\SystemRoot\\example.txt"
		InitializeObjectAttributes(&objAttr, &uniName,
			OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
			NULL, NULL);

#if 0
		NTSTATUS ntStatus = _NtOpenFile(
			&handle,
			FILE_READ_ATTRIBUTES | FILE_READ_DATA,
			&objAttr,
			&ioStatusBlock,
			FILE_SHARE_READ,
			USE_DELETE_ON_CLOSE
		);
#else
		NTSTATUS ntStatus = _NtCreateFile(
			&handle,
			(FILE_READ_DATA | READ_CONTROL | FILE_READ_EA | SYNCHRONIZE), // | SYNCHRONIZE
			&objAttr,
			&ioStatusBlock,
			NULL,
			FILE_ATTRIBUTE_NORMAL,
			(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE),
			FILE_OPEN,
			FILE_NON_DIRECTORY_FILE, // FILE_SYNCHRONOUS_IO_NONALERT
			NULL, 0);
#endif

		if (!NT_SUCCESS(ntStatus))
			return ntStatus;

		_FILE_STANDARD_INFORMATION2 fileInfo = { 0 };
		ntStatus = _NtQueryInformationFile(
			handle,
			&ioStatusBlock,
			&fileInfo,
			sizeof(fileInfo),
			FILE_INFORMATION_CLASS2::FileStandardInformation
		);

		if (!NT_SUCCESS(ntStatus)) {
			return ntStatus;
		}


		if ((SIZE_T)fileInfo.AllocationSize.LowPart < 0x0400)
			return STATUS_ACCESS_VIOLATION;

		PVOID pFileMem = ptAllocateMemory(0x400, PAGE_READWRITE);

		if (!pFileMem)
			return STATUS_NO_MEMORY;

		memset(pFileMem, 0xCC, 0x0400);

		ioStatusBlock = IO_STATUS_BLOCK2();

		byteOffset.LowPart = byteOffset.HighPart = 0;
		ntStatus = _NtReadFile(handle, NULL, NULL, NULL, &ioStatusBlock,
			pFileMem, 0x400, &byteOffset, NULL);

		if (ntStatus == STATUS_PENDING)
			ntStatus = _NtWaitForSingleObject(handle, TRUE, NULL);


		if (!NT_SUCCESS(ntStatus))
			return ntStatus;

		_NtClose(handle);

		NTSTATUS res = IsPEFileHeaderAMD64(pFileMem, 0x0400, pbIsAMD64);
		ptFreeMemory(pFileMem);
		return res;
	}


	NTSTATUS HandleDirectoryResultReturned(const WCHAR* pszDirectoryName, LPVOID pBuf, const WCHAR* szDllName, WCHAR* pBuffer, SIZE_T nBufferSize, BOOLEAN bDoRecursiveSearch = TRUE, int nRecursion = 0) [[msvc::forceinline]]
	{
		PFILE_BOTH_DIR_INFORMATION2 DirInformation = (PFILE_BOTH_DIR_INFORMATION2)pBuf;

		while (1)
		{
			UNICODE_STRING EntryName;
			EntryName.MaximumLength = EntryName.Length = (USHORT)DirInformation->FileNameLength;
			EntryName.Buffer = &DirInformation->FileName[0];


			if (0 == DirInformation->NextEntryOffset && EntryName.Length == 0)
				return STATUS_NO_MORE_FILES;

			for (;;)
			{
				if (DirInformation->FileAttributes & FILE_ATTRIBUTE_DIRECTORY)
				{
					if (EntryName.Buffer[0] == L'.')
						break;

					wchar_t _name[MAX_PATH];
					memset(_name, 0, sizeof(_name));
					int nOurPathLen = strlen(pszDirectoryName);
					memcpy_s(_name, sizeof(_name), (void*)pszDirectoryName, (nOurPathLen * sizeof(wchar_t)));
					_name[nOurPathLen++] = '\\';
					wchar_t* pCleaned = UnicodeStringToNulTerminated(&EntryName);

					if (!pCleaned)
						break;

					size_t nSize = strlen(pCleaned);

					for (int i = 0; i < nSize; i++)
						_name[nOurPathLen + i] = pCleaned[i];

					ptFreeMemory(pCleaned);

					if (bDoRecursiveSearch)
						SearchDirectoriesForFile(_name, szDllName, pBuffer, nBufferSize, bDoRecursiveSearch, nRecursion + 1);

					if (*pBuffer)
						break;
				}
				else
				{

//#define _PE_TOOLS_STD_LIB_ALLOW_TESTS
#ifdef _PE_TOOLS_STD_LIB_ALLOW_TESTS
					static std::ofstream out_filedebug("out_dump.txt", std::ios::out);

					char buffer[4096];
					memset(buffer, 0, sizeof(buffer));
					snprintf(buffer, sizeof(buffer), "%wZ\n", &EntryName);

					out_filedebug.write(buffer, strlen(buffer));
					out_filedebug.flush();
#endif _PE_TOOLS_STD_LIB_ALLOW_TESTS

					wchar_t* pCleaned = UnicodeStringToNulTerminated(&EntryName);
					wchar_t* pName = GetFileNameFromPath(pCleaned, true);

					if (!pCleaned || !pName)
						break;

					//  msvcrt.dll!0x00cd0000 L"msvcirt.dll"

					//if (pName[0] == L'm' && pName[1] == L's' && pName[2] == L'v' && pName[3] == L'c' && pName[4] == L'r' && pName[5] == L't')
					//	int i = 0;

					//if (pName[0] == L'u' && pName[1] == L's' && pName[2] == L'e' && pName[3] == L'r' && pName[4] == L'3' && pName[5] == L'2'
					//	&& !_wcsicmp(szDllName, L"user32.dll"))
					//	int i = 0;

					if (!_pet__wcsicmp_s1(pName, szDllName))
					{

						wchar_t _name[MAX_PATH];
						memset(_name, 0, sizeof(_name));
						int nOurPathLen = strlen(pszDirectoryName);
						memcpy_s(_name, sizeof(_name), (void*)pszDirectoryName, (nOurPathLen * sizeof(wchar_t)));
#if 1
						_name[nOurPathLen++] = '\\';

						size_t nSize = strlen(pName);

						for (int i = 0; i < nSize; i++)
							_name[nOurPathLen + i] = pName[i];

						ptFreeMemory(pCleaned);
						pCleaned = 0;

#endif

						strcpy(pBuffer, _name);

						// Verify we CAN actually load this module
						BOOLEAN bIsAmd64 = 0;
						if (!NT_SUCCESS(IsPEFileAMD64(_name, &bIsAmd64)) 
							||
#ifdef _M_AMD64
							!
#endif
							bIsAmd64
							)
						{
							memset(pBuffer, 0, nBufferSize); 						
						}

					}

					if(pCleaned)
						ptFreeMemory(pCleaned);

					break;
				}
				break;
			}

			if (*pBuffer)
				break;

			if (0 == DirInformation->NextEntryOffset)
				break;
			else {
				DirInformation = (PFILE_BOTH_DIR_INFORMATION2)(((PUCHAR)DirInformation) + DirInformation->NextEntryOffset);
			}
		}


		return STATUS_SUCCESS;
	}

	NTSTATUS SearchDirectoriesForFile(const WCHAR* pszDirectoryName, const WCHAR* szDllName, WCHAR* pBuffer, SIZE_T nBufferSize, BOOLEAN bDoRecursiveSearch /*= TRUE*/, int nRecursion /*= 0*/)
	{
		UNICODE_STRING RootDirectoryName;
		OBJECT_ATTRIBUTES RootDirectoryAttributes;
		OBJECT_ATTRIBUTES DirectoryAttributes;
		NTSTATUS ntStatus = STATUS_SUCCESS;
		HANDLE RootDirectoryHandle;
		IO_STATUS_BLOCK2 iosb;
		HANDLE Event;
		

		if (nRecursion == 0)
			pBuffer[0] = L'\0';

		if (nRecursion > 15)
			return STATUS_STACK_OVERFLOW;

		ptRtlInitUnicodeString(&RootDirectoryName, pszDirectoryName);

		InitializeObjectAttributes(&RootDirectoryAttributes, &RootDirectoryName, OBJ_CASE_INSENSITIVE, 0, 0);
		RootDirectoryAttributes.Attributes |= OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
	

		UNICODE_STRING ObjectName;
		DirectoryAttributes = { sizeof(DirectoryAttributes), 0, &ObjectName };
		DirectoryAttributes.Attributes |= OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;

		ntStatus = _NtOpenFile(
			&DirectoryAttributes.RootDirectory,
			FILE_READ_ATTRIBUTES | FILE_READ_DATA/*FILE_READ_ATTRIBUTES*/,
			&RootDirectoryAttributes, &iosb, FILE_SHARE_READ, USE_DELETE_ON_CLOSE
		);


		RootDirectoryHandle = DirectoryAttributes.RootDirectory;


		if (!NT_SUCCESS(ntStatus))
			return ntStatus;
		
		//	while (0 <= (status = _NtQueryDirectoryFile(oa.RootDirectory, NULL, &OnQueryComplete, NULL, &iosb,
		//	pv = buffer, ALLOCSIZE * 4096, FILE_INFORMATION_CLASS2::FileDirectoryInformation, 0, NULL, FALSE)))


		int nBaseAllocationAmount = ALLOCSIZE * 10;

		if(nRecursion == 0)
			nBaseAllocationAmount = ALLOCSIZE * 40;

		for (;;)
		{
			void* pBuf = ptAllocateMemory(nBaseAllocationAmount, PAGE_READWRITE);

			if (!pBuf)
				return STATUS_INSUFFICIENT_RESOURCES;

			_FILE_BOTH_DIR_INFORMATION2 Info;


			ntStatus = _NtCreateEvent(&Event, EVENT_ALL_ACCESS, 0, EVENT_TYPE2::NotificationEvent, FALSE);

			if (!NT_SUCCESS(ntStatus))
				return ntStatus;

			ntStatus = _NtQueryDirectoryFile(
				RootDirectoryHandle,
				Event, NULL, NULL,
				&iosb,
				pBuf,
				nBaseAllocationAmount,
				FILE_INFORMATION_CLASS2::FileBothDirectoryInformation,
				FALSE,
				NULL,
				FALSE
			);


			// STATUS_USER_APC

			if (ntStatus == STATUS_NO_MORE_FILES)
				return ntStatus;

			if (ntStatus == STATUS_PENDING)
				ntStatus = _NtWaitForSingleObject(Event, TRUE, 0);
			else if (!NT_SUCCESS(ntStatus))
				return ntStatus;

			if (!NT_SUCCESS(ntStatus) || ntStatus == STATUS_NO_MORE_FILES)
				return ntStatus; //printf("Unable to query directory contents, error 0x%x\n", ntStatus);

			_NtClose(Event);

			PFILE_BOTH_DIR_INFORMATION2 DirInformation = (PFILE_BOTH_DIR_INFORMATION2)pBuf;

			if (DirInformation->NextEntryOffset == 0)
			{
				ptFreeMemory(pBuf);
				return STATUS_NO_MORE_FILES;
			}


			NTSTATUS ntStat = HandleDirectoryResultReturned(
				pszDirectoryName, pBuf, szDllName,
				pBuffer, nBufferSize, bDoRecursiveSearch,
				nRecursion
			);


			if (ntStat == STATUS_NO_MORE_FILES)
				return STATUS_NO_MORE_FILES;

			if (pBuf)
				ptFreeMemory(pBuf);

			if (pBuffer[0])
				break;
		
		}


		_NtClose(RootDirectoryHandle);

		return STATUS_SUCCESS;
	}


	void FindDllPath(char* szDllName, wchar_t* pBuffer, size_t nBufferSize, bool bDosName = false)
	{
#ifdef _M_AMD64 
#define OPATH L"\\SystemRoot\\System32"
#else 
#define OPATH L"\\SystemRoot\\SysWOW64"
#endif

		UNICODE_STRING     uniName;
		wchar_t SystemRoot[MAX_PATH];
		memset(SystemRoot, 0, sizeof(SystemRoot));
		memset(pBuffer, 0, nBufferSize);
		int d = 0;

		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(backslash, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(S, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(y, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(s, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(t, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(e, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(m, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(R, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(o, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(o, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(t, 0x4332);

		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(backslash, 0x4332);

		int end_of_back_slash = d;

		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(S, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(y, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(s, 0x4332);
#if 1
#ifdef _M_AMD64 
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(t, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(e, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(m, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(3, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(2, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(null, 0x4332);
#else 
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(W, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(O, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(W, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(6, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(4, 0x4332);
		SystemRoot[d++] = PT_GET_STACK_CHARACTERW(null, 0x4332);
#endif
#endif
		//wchar_t wszSystemRoot[MAX_PATH];
		//
		//ULONG RequiredSize = 0;
		//ptRtlGetEnviromentVariableW(SystemRoot, wszSystemRoot, MAX_PATH, &RequiredSize);

		wchar_t wszDllName[MAX_PATH * 2];


		memset(wszDllName, 0, sizeof(wszDllName));
		int nDllNameLen = strlen(szDllName);
		for (int i = 0; i < nDllNameLen; i++)
			wszDllName[i] = szDllName[i];

		// don't do recursive at first
		wchar_t buffer[MAX_PATH * 2];
		memset(buffer, 0x00, sizeof(buffer));
		SearchDirectoriesForFile((WCHAR*)SystemRoot, wszDllName, (WCHAR*)&buffer, sizeof(buffer), FALSE);

		// okay...
		if(!buffer[0])
			SearchDirectoriesForFile((WCHAR*)SystemRoot, wszDllName, (WCHAR*)&buffer, sizeof(buffer), TRUE);

#if 0 // FOR WinSXS
		// alright lets try SxS
		if (!buffer[0])
		{
			d = end_of_back_slash;
			SystemRoot[d++] = PT_GET_STACK_CHARACTERW(W, 0x4332);
			SystemRoot[d++] = PT_GET_STACK_CHARACTERW(i, 0x4332);
			SystemRoot[d++] = PT_GET_STACK_CHARACTERW(n, 0x4332);
			SystemRoot[d++] = PT_GET_STACK_CHARACTERW(S, 0x4332);
			SystemRoot[d++] = PT_GET_STACK_CHARACTERW(x, 0x4332);
			SystemRoot[d++] = PT_GET_STACK_CHARACTERW(S, 0x4332);
			SystemRoot[d++] = PT_GET_STACK_CHARACTERW(null, 0x4332);
			SearchDirectoriesForFile((WCHAR*)SystemRoot, wszDllName, (WCHAR*)&buffer, sizeof(buffer), TRUE);
		}
#endif

#ifdef _DEBUG
		if (!buffer[0])
			printf("Unable To Find %s!\n", szDllName);
		else
			printf("Found %s @ %ls!\n", szDllName, buffer);
#endif

		if (buffer[0])
		{
			if (bDosName)
			{
				constexpr size_t nOpenerSize = strlen(L"\\SystemRoot\\");
				constexpr size_t nDosSize = strlen(L"C:\\Windows\\");

				int nBufferLen = strlen(buffer);
				if (nBufferLen < nOpenerSize)
					return;
				int nIndex = 1;
#define add_character(_c) buffer[nIndex++] = PT_GET_STACK_CHARACTERW(_c, 0x4332);
				add_character(C);
				add_character(colon);
				add_character(backslash);
				add_character(W);
				add_character(i);
				add_character(n);
				add_character(d);
				add_character(o);
				add_character(w);
				add_character(s);
				add_character(backslash);
#undef add_character
				memset(pBuffer, 0, nBufferSize);
				for (int i = 1; (i < nBufferLen) && ((i - 1) < nBufferSize); i++)
					pBuffer[i - 1] = buffer[i];
			}
			else
			{
				int nBufferLen = strlen(buffer);
				memset(pBuffer, 0, nBufferSize);
				for (int i = 0; (i < nBufferLen) && ((i) < nBufferSize); i++)
					pBuffer[i] = buffer[i];
			}
			// RtlNtPathNameToDosPathNameHash
			// SUCKS!
		}


	}
	// https://github.com/Speedi13/ManualMapped_SEH_32bit
	LONG NTAPI ExceptionHandler(_EXCEPTION_POINTERS* ExceptionInfo)
	{
		PVOID ExceptionAddress = ExceptionInfo->ExceptionRecord->ExceptionAddress;
		if (!g_pModList || !g_pModList->IsAddressWithinOurModules(ExceptionAddress))
			return EXCEPTION_CONTINUE_SEARCH;

		DWORD RegisterESP = ExceptionInfo->ContextRecord->Esp;
		EXCEPTION_REGISTRATION_RECORD* pFs = (EXCEPTION_REGISTRATION_RECORD*)__readfsdword(0); // mov pFs, large fs:0 ; <= reading the segment register
		if ((DWORD_PTR)pFs > (RegisterESP - 0x10000) && (DWORD_PTR)pFs < (RegisterESP + 0x10000))
		{
			EXCEPTION_ROUTINE* ExceptionHandlerRoutine = pFs->Handler;
			if (g_pModList->IsAddressWithinOurModules(ExceptionHandlerRoutine))
			{
				EXCEPTION_DISPOSITION ExceptionDisposition = ExceptionHandlerRoutine(ExceptionInfo->ExceptionRecord, pFs, ExceptionInfo->ContextRecord, nullptr);
				if (ExceptionDisposition == ExceptionContinueExecution)
					return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
		return EXCEPTION_CONTINUE_SEARCH;
	}

	


	_Check_return_  _Ret_maybenull_ [[nodiscard]] void* PETOOLSCALL MapFromDisk(
		_In_z_ const char* szPath
	)
	{
		// For Now!
		void* pRet = GetModuleA(szPath);

		if (pRet)
			return pRet;


		// Final Thing To Do Is Link To PEB and we are set!!!!
		// Once that's implemented, loader will be recursive!!
		//pRet = ldrLoadFromDisk(szPath);
		//return pRet;

		pRet = ldrLoadFromDisk(szPath);;
		return pRet;


		wchar_t szSearchPathResult[MAX_PATH];
		FindDllPath((char*)szPath, szSearchPathResult, sizeof(szSearchPathResult));

		if (szSearchPathResult[0])
		{
			LARGE_INTEGER      byteOffset;
			HANDLE handle;
			IO_STATUS_BLOCK2    ioStatusBlock;
			UNICODE_STRING     uniName;
			OBJECT_ATTRIBUTES  objAttr;

			ptRtlInitUnicodeString(&uniName, szSearchPathResult);  // or L"\\SystemRoot\\example.txt"
			InitializeObjectAttributes(&objAttr, &uniName,
				OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
				NULL, NULL);

#if 0
			NTSTATUS ntStatus = _NtOpenFile(
				&handle, 
				FILE_READ_ATTRIBUTES | FILE_READ_DATA,
				&objAttr,
				&ioStatusBlock,
				FILE_SHARE_READ,
				USE_DELETE_ON_CLOSE
			);
#else
			NTSTATUS ntStatus = _NtCreateFile(
				&handle,
				(FILE_READ_DATA | READ_CONTROL | FILE_READ_EA | SYNCHRONIZE), // | SYNCHRONIZE
				&objAttr, 
				&ioStatusBlock,
				NULL,
				FILE_ATTRIBUTE_NORMAL,
				(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE),
				FILE_OPEN,
				FILE_NON_DIRECTORY_FILE, // FILE_SYNCHRONOUS_IO_NONALERT
				NULL, 0);
#endif

			if (NT_SUCCESS(ntStatus)) {
				_FILE_STANDARD_INFORMATION2 fileInfo = { 0 };
				ntStatus = _NtQueryInformationFile(
					handle,
					&ioStatusBlock,
					&fileInfo,
					sizeof(fileInfo),
					FILE_INFORMATION_CLASS2::FileStandardInformation
				);

				if (!NT_SUCCESS(ntStatus)) {
					return nullptr;
				}

				PVOID pFileMem = ptAllocateMemory((SIZE_T)fileInfo.AllocationSize.LowPart, PAGE_READWRITE);

				if (!pFileMem)
					return nullptr;

				memset(pFileMem, 0xCC, fileInfo.AllocationSize.LowPart);

				ioStatusBlock = IO_STATUS_BLOCK2();

				byteOffset.LowPart = byteOffset.HighPart = 0;
				ntStatus = _NtReadFile(handle, NULL, NULL, NULL, &ioStatusBlock,
					pFileMem, fileInfo.AllocationSize.LowPart, &byteOffset, NULL);

				if(ntStatus == STATUS_PENDING)
					ntStatus = _NtWaitForSingleObject(handle, TRUE, NULL);

#if 0
				std::ofstream dump_pe;
				dump_pe.open(szPath);
				dump_pe.write((const char*)pFileMem, ioStatusBlock.Information);
				dump_pe.close();
#endif


				if (!NT_SUCCESS(ntStatus))
					return nullptr;

				// pass in call entry!!
				void* pHandle = MapToMemory(pFileMem, fileInfo.EndOfFile.LowPart, szPath, true);
				_NtClose(handle);
				ptFreeMemory(pFileMem);
				return pHandle;
			}
		}
		
		// todo 
		// when things arent found KernelBase.dll is returned?
		pRet = ldrLoadFromDisk(szPath);;
		return pRet;
	}

	_Check_return_  _Ret_maybenull_ [[nodiscard]] void* PETOOLSCALL ldrLoadFromDisk(
		_In_z_ const char* szPath
	) {

		std::string path = szPath;
		std::wstring w_str_path(path.begin(), path.end());
		HANDLE hHandle;
		UNICODE_STRING usDllFile;
		ptRtlInitUnicodeString(&usDllFile, w_str_path.c_str()); //Initialize UNICODE_STRING for LdrLoadDll function
		// LOAD_WITH_ALTERED_SEARCH_PATH
		fnLdrLoadDll_t ldrLoadDll = NULL;
		constexpr unsigned long nt_alert_hash = PeToolsDefaultHasherConstExpr<const char*>("LdrLoadDll");
		if (!g_Globals || !g_Globals->m_pfnLdrLoadDll)
			ldrLoadDll = (fnLdrLoadDll_t)_GetExportAddress(ptGetNtDll(), NULL, nt_alert_hash, PeToolsDefaultHasher);
		else
			ldrLoadDll = g_Globals->m_pfnLdrLoadDll;
		


		NTSTATUS result = ldrLoadDll(NULL, NULL, &usDllFile, &hHandle); //Error on this line!
		return hHandle;
	}


	NTSTATUS SpawnProcessFromMemoryDLL()
	{

		return false;
	}


	void _CalculateSectionHeaderRelativeToPrevious(PIMAGE_SECTION_HEADER pCurrent, PIMAGE_SECTION_HEADER pPrevious, DWORD dwFileAlignment, DWORD dwSectionAlignment)
	{
		DWORD dwSectionSize = pCurrent->Misc.VirtualSize;
		if (!(pPrevious->Misc.VirtualSize % dwSectionAlignment)) {
			pCurrent->VirtualAddress = pPrevious->Misc.VirtualSize
				+ pPrevious->VirtualAddress;
		}
		else {
			pCurrent->VirtualAddress = pPrevious->VirtualAddress
				+ ((pPrevious->Misc.VirtualSize / dwSectionAlignment) + 1) * dwSectionAlignment;
		}
		pCurrent->SizeOfRawData = align(dwSectionSize, dwFileAlignment, 0);
		pCurrent->PointerToRawData = align(pPrevious->SizeOfRawData,
			dwFileAlignment, pPrevious->PointerToRawData);
	}


	// ref : http://www.rohitab.com/discuss/topic/41466-add-a-new-pe-section-code-inside-of-it/
	_Check_return_ _Ret_maybenull_ void* PETOOLSCALL AddSection(
		_In_z_ const char* szSectionName,
		_In_reads_(nFileSize) void* pPEFile,
		_In_ size_t& nFileSize,
		_In_reads_opt_(nSectionDataSizeSize) void* pSectionData,
		_In_ size_t nSectionDataSizeSize,
		_In_ size_t nSectionSize,
		_In_ int nSectionCharacteristics /* = 0 */,
		_In_ bool bRealloc /* = false */
	)
	{
		PIMAGE_DOS_HEADER pDos;
		PIMAGE_NT_HEADERS pNTHeaders;
		PIMAGE_FILE_HEADER pFileHeader;
		PIMAGE_OPTIONAL_HEADER pOptionalHeader;
		PIMAGE_SECTION_HEADER pFirstSectionHeader;
		IMAGE_SECTION_HEADER NewSectionHeader;
		DWORD LastSectionEndAddress;

		int nPreviousNumberOfSections = 0;

		pDos = (PIMAGE_DOS_HEADER)pPEFile;

		if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr; 

		if (nSectionDataSizeSize > nSectionSize)
			return nullptr;

		pNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((char*)pPEFile + pDos->e_lfanew);
		pFileHeader = &pNTHeaders->FileHeader;
		pOptionalHeader = &pNTHeaders->OptionalHeader;
		pFirstSectionHeader = GetSectionHeaderByIndex(pPEFile, 0);

		if (!pFileHeader)
			return nullptr;

		nPreviousNumberOfSections = pFileHeader->NumberOfSections;

		// Zero Out Of Section Header And Copy Name
		memset(&NewSectionHeader, 0x00, sizeof(IMAGE_SECTION_HEADER));

		memcpy_s(&NewSectionHeader.Name,sizeof(IMAGE_SECTION_HEADER::Name),
			(void*)szSectionName, sizeof(IMAGE_SECTION_HEADER::Name)
		);

		NewSectionHeader.Misc.VirtualSize = nSectionSize;

		_CalculateSectionHeaderRelativeToPrevious(&NewSectionHeader,
			&pFirstSectionHeader[nPreviousNumberOfSections - 1], pOptionalHeader->FileAlignment,
			pOptionalHeader->SectionAlignment
		);

		NewSectionHeader.Characteristics = nSectionCharacteristics;

		// Allocate New PE File Buffer
		void* pNewPEFile = nullptr;
		if (bRealloc)
			pNewPEFile = realloc(pPEFile, NewSectionHeader.VirtualAddress + NewSectionHeader.Misc.VirtualSize);
		else
		{
			pNewPEFile = malloc(NewSectionHeader.VirtualAddress + NewSectionHeader.Misc.VirtualSize);
			if(pNewPEFile)
				memcpy_s(pNewPEFile, NewSectionHeader.VirtualAddress + NewSectionHeader.Misc.VirtualSize,
					pPEFile, nFileSize
				);
		}

		if (!pNewPEFile)
			return nullptr;

		pDos = (PIMAGE_DOS_HEADER)pNewPEFile;
		pNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((char*)pNewPEFile + pDos->e_lfanew);
		pFileHeader = &pNTHeaders->FileHeader;
		pOptionalHeader = &pNTHeaders->OptionalHeader;
		pFirstSectionHeader = GetSectionHeaderByIndex(pNewPEFile, 0);
		nPreviousNumberOfSections = pFileHeader->NumberOfSections;

		if (!pFileHeader) // uhhhhhh
		{
			free(pNewPEFile);
			return nullptr;
		}

		PIMAGE_SECTION_HEADER pSectionHeaderAddress = &(pFirstSectionHeader[nPreviousNumberOfSections]);
		memcpy_s(pSectionHeaderAddress, sizeof(IMAGE_SECTION_HEADER), &NewSectionHeader, sizeof(IMAGE_SECTION_HEADER));

		if (pSectionData)
		{
			memcpy_s((char*)pNewPEFile + NewSectionHeader.PointerToRawData, nSectionSize, pSectionData, nSectionDataSizeSize);
		}

		pOptionalHeader->SizeOfImage = NewSectionHeader.VirtualAddress + NewSectionHeader.Misc.VirtualSize;
		pFileHeader->NumberOfSections = nPreviousNumberOfSections + 1;
		nFileSize = NewSectionHeader.PointerToRawData + NewSectionHeader.SizeOfRawData;
		return pNewPEFile;
	}



	_Check_return_ _Ret_maybenull_ void* PETOOLSCALL ResizeSection(
		_In_z_ const char* szSectionName,
		_In_reads_(nFileSize) void* pPEFile,
		_In_ size_t& nFileSize,
		_In_ size_t nNewSectionSize,
		_Outptr_opt_ void** pNewMemoryStartAddress /* = nullptr */,
		_In_ bool bRealloc /* = false */
	)
	{
		PIMAGE_DOS_HEADER pDos;
		PIMAGE_NT_HEADERS pNTHeaders;
		PIMAGE_FILE_HEADER pFileHeader;
		PIMAGE_OPTIONAL_HEADER pOptionalHeader;
		PIMAGE_SECTION_HEADER pFirstSectionHeader;
		PIMAGE_SECTION_HEADER ResizeSection;
		IMAGE_SECTION_HEADER SectionRel;
		DWORD LastSectionEndAddress;
		DWORD dwNewImageSize;
		int nIndex = -1;

		int nPreviousNumberOfSections = 0;

		pDos = (PIMAGE_DOS_HEADER)pPEFile;

		if (pDos->e_magic != IMAGE_DOS_SIGNATURE)
			return nullptr;

		pNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((char*)pPEFile + pDos->e_lfanew);
		pFileHeader = &pNTHeaders->FileHeader;
		pOptionalHeader = &pNTHeaders->OptionalHeader;
		pFirstSectionHeader = GetSectionHeaderByIndex(pPEFile, 0);

		if (!pFirstSectionHeader)
			return nullptr;

		nIndex = GetSectionIndexByName(pPEFile,szSectionName);

		if (nIndex == -1)
			return nullptr;

		if (!pFileHeader)
			return nullptr;


		ResizeSection = &pFirstSectionHeader[nIndex];
		SectionRel = *ResizeSection;
		SectionRel.Misc.VirtualSize = nNewSectionSize;
		if (nIndex != 0)
			_CalculateSectionHeaderRelativeToPrevious(&SectionRel, &pFirstSectionHeader[nIndex - 1], pOptionalHeader->FileAlignment, pOptionalHeader->SectionAlignment);
		else
		{
			IMAGE_SECTION_HEADER DummySection;
			memset(&DummySection, 0x00, sizeof(IMAGE_SECTION_HEADER));
			_CalculateSectionHeaderRelativeToPrevious(&SectionRel, &DummySection, pOptionalHeader->FileAlignment, pOptionalHeader->SectionAlignment);
			SectionRel.VirtualAddress = ResizeSection->VirtualAddress;
			SectionRel.PointerToRawData = ResizeSection->PointerToRawData;
		}

		dwNewImageSize = (nFileSize - ResizeSection->SizeOfRawData) + (SectionRel.SizeOfRawData) + 5000; // add 5k extra for alignment and stuff

		void* pNewFile = malloc(dwNewImageSize);
		memset(pNewFile, 0x00, dwNewImageSize);

		if (!pNewFile)
			return nullptr;

		// Copy Start Of File
		memcpy_s(pNewFile, dwNewImageSize, pPEFile, ResizeSection->PointerToRawData);

		// Copy existing Section Data
		memcpy_s((char*)pNewFile + ResizeSection->PointerToRawData,
			dwNewImageSize - ResizeSection->PointerToRawData,
			(char*)pPEFile + ResizeSection->PointerToRawData, ResizeSection->SizeOfRawData);


		DWORD dwOldCutOffAddress = ResizeSection->PointerToRawData + ResizeSection->SizeOfRawData;
		DWORD dwAddition = (SectionRel.PointerToRawData + SectionRel.SizeOfRawData) - dwOldCutOffAddress;

		DWORD dwOldVirtCutOffAddress = ResizeSection->VirtualAddress + ResizeSection->Misc.VirtualSize;
		DWORD dwVirtAddition = (SectionRel.VirtualAddress + SectionRel.Misc.VirtualSize) - dwOldCutOffAddress;

#if 0
		// Copy Data Afterwards if any
		if ((nIndex + 1) < pFileHeader->NumberOfSections)
		{
			//PIMAGE_SECTION_HEADER pLastSection = &pFirstSectionHeader[pFileHeader->NumberOfSections - 1];
			DWORD dwSectionSizeNewFile = SectionRel.PointerToRawData + SectionRel.SizeOfRawData;
			DWORD dwSectionSizePreviousDLL = ResizeSection->PointerToRawData + ResizeSection->SizeOfRawData;
			memcpy_s((char*)pNewFile + dwSectionSizeNewFile,
				dwNewImageSize - dwSectionSizeNewFile,
				(char*)pPEFile + dwSectionSizePreviousDLL,
				nFileSize - dwSectionSizePreviousDLL);
		}
#endif


		// fix headers
		pFirstSectionHeader = GetSectionHeaderByIndex(pNewFile, 0);
		nIndex = GetSectionIndexByName(pNewFile, szSectionName);

		pDos = (PIMAGE_DOS_HEADER)pNewFile;
		pNTHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>((char*)pNewFile + pDos->e_lfanew);
		pFileHeader = &pNTHeaders->FileHeader;
		pOptionalHeader = &pNTHeaders->OptionalHeader;

		PIMAGE_SECTION_HEADER WriteHeader = &(pFirstSectionHeader[nIndex]);
		memcpy(WriteHeader, &SectionRel, sizeof(IMAGE_SECTION_HEADER));

		for (int i = (nIndex + 1); i < pFileHeader->NumberOfSections; i++)
		{
			PIMAGE_SECTION_HEADER pOldSectionHeader = GetSectionHeaderByIndex(pPEFile, i);

			_CalculateSectionHeaderRelativeToPrevious(&(pFirstSectionHeader[i]), &pFirstSectionHeader[i - 1],
				pOptionalHeader->FileAlignment, pOptionalHeader->SectionAlignment
			);

			memcpy_s((char*)pNewFile + pFirstSectionHeader[i].PointerToRawData,
				((DWORD)pNewFile + dwNewImageSize) - pFirstSectionHeader[i].PointerToRawData, (char*)pPEFile + pOldSectionHeader->PointerToRawData,
				min(pOldSectionHeader->SizeOfRawData, pFirstSectionHeader[i].SizeOfRawData)
			);	

		}
		nFileSize = dwNewImageSize;
		pOptionalHeader->SizeOfImage = pFirstSectionHeader[pFileHeader->NumberOfSections - 1].VirtualAddress + pFirstSectionHeader[pFileHeader->NumberOfSections - 1].Misc.VirtualSize;

		DWORD dwSizeOfCode = 0;
		DWORD dwFirstCodeOffset = 0;
		for (int i = 0; i < pFileHeader->NumberOfSections; i++)
		{
			PIMAGE_SECTION_HEADER pHead = &pFirstSectionHeader[i];
			if (pHead->Characteristics & IMAGE_SCN_CNT_CODE)
			{
				if (!dwFirstCodeOffset)
					dwFirstCodeOffset = pHead->VirtualAddress;

				dwSizeOfCode += pHead->SizeOfRawData;
			}
		}

		pOptionalHeader->SizeOfCode = dwSizeOfCode;
		pOptionalHeader->BaseOfCode = dwFirstCodeOffset;


		// fix data directorys

		PIMAGE_DATA_DIRECTORY* pDirectory;
		for (unsigned short i = 0; i < pOptionalHeader->NumberOfRvaAndSizes; i++)
		{
			PIMAGE_DATA_DIRECTORY pDataDir = &(pOptionalHeader->DataDirectory[i]);
			PIMAGE_DATA_DIRECTORY _pDataDir = &(GetOptionalHeader(pPEFile)->DataDirectory[i]);
			if (!pDataDir->VirtualAddress)
				continue;

			int nSectionIndex = GetSectionIndexForVirtualAddress(pPEFile, pDataDir->VirtualAddress);
			PIMAGE_SECTION_HEADER pHeader = GetSectionHeaderForVirtualAddress(pPEFile, pDataDir->VirtualAddress);

			if (!pHeader || !nSectionIndex)
				continue;

			if (pDataDir->VirtualAddress < ResizeSection->VirtualAddress)
				continue;

			pDataDir->VirtualAddress = (pDataDir->VirtualAddress - pHeader->VirtualAddress) + pFirstSectionHeader[nSectionIndex].VirtualAddress;
			int l = 0;
		}


		// fix .reloc 

		DWORD dwCalculatedSize = GetSectionHeaderByIndex(pNewFile, pFileHeader->NumberOfSections - 1)->PointerToRawData +
			GetSectionHeaderByIndex(pNewFile, pFileHeader->NumberOfSections - 1)->SizeOfRawData;

		nFileSize = dwCalculatedSize;

		if (bRealloc)
		{
			void* pNewData = realloc(pPEFile, dwNewImageSize);

			if (!pNewData)
				return nullptr;

			memcpy_s(pNewData, dwNewImageSize, pNewFile, dwNewImageSize);
			free(pNewFile);
			pNewFile = pNewData;
		}

		return pNewFile;

	}


	FARPROC WINAPI _GetExportAddress(_In_ HMODULE hModule, _In_opt_ LPCSTR lpProcName, _In_ unsigned long ulHash, fnPEToolsHasher_t pfnHasher)
	{
		if (hModule == NULL)
			return NULL;

		PIMAGE_NT_HEADERS pNT = GetNTHeader(hModule);
		PIMAGE_OPTIONAL_HEADER pOpt = &(pNT->OptionalHeader);

		PIMAGE_DATA_DIRECTORY pExportDataDirectoryInfo = &pNT->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		if (!pExportDataDirectoryInfo->Size)
			return NULL;

		PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)
			((char*)hModule + pExportDataDirectoryInfo->VirtualAddress);

		unsigned long usNumberOfExports = 
			(lpProcName != NULL || ulHash) ? pExportDirectory->NumberOfNames : pExportDirectory->NumberOfFunctions;


		// Get Code Section
		PIMAGE_SECTION_HEADER pSection = GetSectionHeaderByIndex(hModule, 0);

		if (!pSection)
			return NULL;

		for (; ((pSection->Characteristics & IMAGE_SCN_CNT_CODE) == 0) && pSection->Name; pSection++);
		

		char* pStartAddress = (char*)hModule + pSection->VirtualAddress;
		char* pEndAddress = pStartAddress + pSection->Misc.VirtualSize;

		// TODO : Finish Implement Detecting!
		USHORT ulProcOrdinal = NULL;

		for (int i = 0; i < usNumberOfExports; i++)
		{
			ULONG32 ulOrdinal = NULL;
			if (!ulProcOrdinal)
			{
				ULONG32* ulAddrOfName = (ULONG32*)((char*)hModule + pExportDirectory->AddressOfNames +
					(i * sizeof(DWORD)));

				LPCSTR plExProcName = (LPCSTR)((char*)hModule + *ulAddrOfName);

				if (((ulHash && pfnHasher) && (pfnHasher((char*)plExProcName) != ulHash)) || (lpProcName && strcmp(plExProcName, lpProcName)))
					continue;
				
				USHORT* usNameOfOrdinal = (USHORT*)((char*)hModule + pExportDirectory->AddressOfNameOrdinals +
					(i * sizeof(USHORT)));

				ulOrdinal = pExportDirectory->Base + *usNameOfOrdinal;				
			}
			else
			{
				USHORT* usNameOfOrdinal = (USHORT*)((char*)hModule + pExportDirectory->AddressOfNameOrdinals +
					(i * sizeof(USHORT)));

				ULONG32 ulFunctionOrdinal = pExportDirectory->Base + *usNameOfOrdinal;
				if (ulFunctionOrdinal != ulProcOrdinal)
					continue;

				ulOrdinal = ulFunctionOrdinal;
					
			}

			ULONG32* pulFunctionRVA = (ULONG32*)(
				(char*)hModule + 
				(pExportDirectory->AddressOfFunctions + 4 * (ulOrdinal - pExportDirectory->Base))
			);

			PVOID pFunc = (char*)hModule + *pulFunctionRVA;

			// if you load a module (YOU NEED TO IMPORT FROM) in the .data segment or smth
			// you deserve this to break!

			if(pFunc <= pEndAddress && pFunc >= pStartAddress)
				return (FARPROC)pFunc;


			// Forwarded Function
			const char* pszSeperator = strchr((const char*)pFunc, PT_GET_STACK_CHARACTER(dot, 0x43));

			if (!pszSeperator)
				continue; // uhhh, idk man. Lets Keep Searching in case...

			unsigned short pos = pszSeperator - pFunc;

			char szLibName[MAX_PATH];
			memset(szLibName, 0x00, sizeof(szLibName));

			strncpy(szLibName, (const char*)pFunc, pos);

			// needed? put it on the stack incase...

			szLibName[pos] = PT_GET_STACK_CHARACTER(dot, 0x43);
			szLibName[pos + 1] = PT_GET_STACK_CHARACTER(d , 0x43);
			szLibName[pos + 2] = PT_GET_STACK_CHARACTER(l, 0x43);
			szLibName[pos + 3] = PT_GET_STACK_CHARACTER(l, 0x43);

			char* szFunctionName = (char*)pFunc + pos + 1;


			HMODULE hMod = (HMODULE)MapFromDisk(szLibName);

			if (!hMod)
				return NULL;

			return GetExportAddress(hMod, szFunctionName);
		}

		return NULL;
	}

	HMODULE GetModuleW(const wchar_t* lpModuleName)
	{
		PEB2* ProcessEnvironmentBlock = ((PEB2*)((TEB2*)((TEB2*)NtCurrentTeb())->ProcessEnvironmentBlock));
		if (lpModuleName == nullptr)
			return (HMODULE)(ProcessEnvironmentBlock->ImageBaseAddress);

		PEB_LDR_DATA2* Ldr = ProcessEnvironmentBlock->Ldr;

		LIST_ENTRY* ModuleLists[3] = { 0,0,0 };
		ModuleLists[0] = &Ldr->InLoadOrderModuleList;
		ModuleLists[1] = &Ldr->InMemoryOrderModuleList;
		ModuleLists[2] = &Ldr->InInitializationOrderModuleList;
		for (int j = 0; j < 3; j++)
		{
			for (LIST_ENTRY* pListEntry = ModuleLists[j]->Flink;
				pListEntry != ModuleLists[j];
				pListEntry = pListEntry->Flink)
			{
				LDR_DATA_TABLE_ENTRY2* pEntry = (LDR_DATA_TABLE_ENTRY2*)((BYTE*)pListEntry - sizeof(LIST_ENTRY) * j); //= CONTAINING_RECORD( pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

				if (_wcsicmp(pEntry->BaseDllName.Buffer, lpModuleName) == 0)
					return (HMODULE)pEntry->DllBase;

				wchar_t* FileName = GetFileNameFromPath(pEntry->FullDllName.Buffer);
				if (!FileName)
					continue;

				if (_wcsicmp(FileName, lpModuleName) == 0)
					return (HMODULE)pEntry->DllBase;

				wchar_t FileNameWithoutExtension[256];
				RemoveFileExtension(FileName, FileNameWithoutExtension, 256);

				if (_wcsicmp(FileNameWithoutExtension, lpModuleName) == 0)
					return (HMODULE)pEntry->DllBase;
			}
		}
		return nullptr;
	}
	FORCEINLINE
		PVOID
		_RtlSecureZeroMemory(
			_Out_writes_bytes_all_(cnt) PVOID ptr,
			_In_ SIZE_T cnt
		)
	{
		volatile char* vptr = (volatile char*)ptr;

#if defined(_M_AMD64) && !defined(_M_ARM64EC)

		__stosb((PBYTE)((DWORD64)vptr), 0, cnt);

#else

		while (cnt) {

#if !defined(_M_CEE) && (defined(_M_ARM) || defined(_M_ARM64) || defined(_M_ARM64EC))

			__iso_volatile_store8(vptr, 0);

#else

			* vptr = 0;

#endif

			vptr++;
			cnt--;
		}

#endif // _M_AMD64 && !defined(_M_ARM64EC)

		return ptr;
	}


	HMODULE GetModuleHash(unsigned long ulHash, fnPEToolsHasher_t pfnHasher)
	{
		PEB2* ProcessEnvironmentBlock = ((PEB2*)((TEB2*)((TEB2*)NtCurrentTeb())->ProcessEnvironmentBlock));
		if (ulHash == 0)
			return (HMODULE)(ProcessEnvironmentBlock->ImageBaseAddress);

		PEB_LDR_DATA2* Ldr = ProcessEnvironmentBlock->Ldr;

		LIST_ENTRY* ModuleLists[3] = { 0,0,0 };
		ModuleLists[0] = &Ldr->InLoadOrderModuleList;
		ModuleLists[1] = &Ldr->InMemoryOrderModuleList;
		ModuleLists[2] = &Ldr->InInitializationOrderModuleList;
		for (int j = 0; j < 3; j++)
		{
			for (LIST_ENTRY* pListEntry = ModuleLists[j]->Flink;
				pListEntry != ModuleLists[j];
				pListEntry = pListEntry->Flink)
			{
				LDR_DATA_TABLE_ENTRY2* pEntry = (LDR_DATA_TABLE_ENTRY2*)((BYTE*)pListEntry - sizeof(LIST_ENTRY) * j); //= CONTAINING_RECORD( pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks );

				char ansi_string[MAX_PATH];
				memset(ansi_string, 0, sizeof(ansi_string));
				for (int i = 0; i < pEntry->BaseDllName.Length; i++)
					ansi_string[i] = pEntry->BaseDllName.Buffer[i];


				if (pfnHasher(ansi_string) == ulHash)
					return (HMODULE)pEntry->DllBase;

				wchar_t* FileName = GetFileNameFromPath(pEntry->FullDllName.Buffer);
				if (!FileName)
					continue;

				int nLen = strlen(FileName);
				memset(ansi_string, 0, sizeof(ansi_string));
				for (int i = 0; i < nLen; i++)
					ansi_string[i] = FileName[i];

				if (pfnHasher(ansi_string) == ulHash)
					return (HMODULE)pEntry->DllBase;

				wchar_t FileNameWithoutExtension[256];
				RemoveFileExtension(FileName, FileNameWithoutExtension, 256);

				nLen = strlen(FileNameWithoutExtension);
				memset(ansi_string, 0, sizeof(ansi_string));
				for (int i = 0; i < nLen; i++)
					ansi_string[i] = FileNameWithoutExtension[i];

				if (pfnHasher(ansi_string) == ulHash)
					return (HMODULE)pEntry->DllBase;

			}
		}
		return nullptr;
	}

	HMODULE GetModuleA(const char* lpModuleName)
	{
		if (!lpModuleName) return GetModuleW(NULL);

		DWORD ModuleNameLength = (DWORD)strlen(lpModuleName) + 1;

		// alloca is no bueno
		// calls some probe crap...
		wchar_t W_ModuleName[MAX_PATH];

		DWORD NewBufferSize = sizeof(wchar_t) * ModuleNameLength;
		if (NewBufferSize > sizeof(W_ModuleName))
			return NULL;

		//allocate buffer for the string on the stack:
		for (DWORD i = 0; i < ModuleNameLength; i++)
			W_ModuleName[i] = lpModuleName[i];

		HMODULE hReturnModule = GetModuleW(W_ModuleName);

		RtlSecureZeroMemory(W_ModuleName, NewBufferSize);

		return hReturnModule;
	}

	bool WINAPI ptCreateUnicodeStringFromCString(char* szStr, void* str1)
	{

		PUNICODE_STRING str = (PUNICODE_STRING)str1;
		DWORD StringLength = (DWORD)strlen(szStr) + 1;

		DWORD NewBufferSize = sizeof(wchar_t) * StringLength;
		if (NewBufferSize > str->MaximumLength)
			return false;

		//allocate buffer for the string on the stack:
		for (DWORD i = 0; i < StringLength; i++)
			str->Buffer[i] = szStr[i];

		str->Length = StringLength;

		return true;
	}



	// Hashed Functions

	_Ret_maybenull_ PIMAGE_SECTION_HEADER PETOOLSCALL GetSectionHeaderByHash(
		_In_ void* pPEStart,
		_In_ unsigned long ulHash
	)
	{
		if (!g_Globals->m_pfnHasher)
			return nullptr;

		PIMAGE_SECTION_HEADER pSection = GetSectionHeaderByIndex(pPEStart, 0);

		if (!pSection)
			return nullptr;

		int nNumSections = PETools::GetNumberOfSections(pPEStart);
		for (int i = 0; i < nNumSections; i++, pSection++)
		{
			char name[sizeof(pSection->Name) + 1]{ 0 };
			memcpy_s(name, sizeof(name), pSection->Name, sizeof(pSection->Name));

			if (g_Globals->m_pfnHasher(name) == ulHash)
				return pSection;
		}

		return nullptr;
	}


	_Ret_maybenull_ int PETOOLSCALL GetSectionIndexByHash(
		_In_ void* pPEStart,
		_In_ unsigned long ulHash
	) {
		PIMAGE_SECTION_HEADER pSection = GetSectionHeaderByIndex(pPEStart, 0);

		if (!pSection)
			return -1;

		int nNumSections = PETools::GetNumberOfSections(pPEStart);
		for (int i = 0; i < nNumSections; i++, pSection++)
		{
			char name[sizeof(pSection->Name) + 1]{ 0 };
			memcpy_s(name, sizeof(name), pSection->Name, sizeof(pSection->Name));
			if (g_Globals->m_pfnHasher(name) == ulHash)
				return i;
		}

		return -1;
	}







	// MISC


	std::vector<std::string> FetchAllImportedModules(void* pPEFile, size_t nFileSize, bool bIsMapped)
	{

		std::vector<std::string> mods_to_load;

		void* pMappedPEFile = pPEFile;

		if (!bIsMapped)
		{

			if (!SysCall::g_pNTTestAlertPtr)
			{
				HMODULE hNtdll = ptGetNtDll();
				SysCall::g_pNTTestAlertPtr = _GetExportAddress(hNtdll, NULL, 0x51eb21ff, PETools::PeToolsDefaultHasher);
			}

			PIMAGE_DOS_HEADER pDos = GetDosHeader(pPEFile);

			if (pDos->e_magic != 0x5A4D)
				return {};


			PIMAGE_OPTIONAL_HEADER _pOpt = GetOptionalHeader(pPEFile);
			if (_pOpt->Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
				return {};

			PIMAGE_NT_HEADERS pNT = reinterpret_cast<PIMAGE_NT_HEADERS>((char*)pPEFile + pDos->e_lfanew);
			PIMAGE_OPTIONAL_HEADER pOpt = &pNT->OptionalHeader;
			PIMAGE_FILE_HEADER pFile = &pNT->FileHeader;


			// everyone allocates everything as PAGE_READWRITE_EXECUTE... that's not correct 
			LPVOID pMappedModuleMem = PtVirtualAlloc((LPVOID)pOpt->ImageBase, pOpt->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);



			if (!pMappedModuleMem)
				pMappedModuleMem = PtVirtualAlloc(nullptr, pOpt->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

			if (pMappedModuleMem)
			{
				for (int i = 0; i < 200; i++)
				{
					pMappedModuleMem = PtVirtualAlloc(nullptr, pOpt->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
					if (pMappedModuleMem)
						break;
				}
			}

			if (!pMappedModuleMem)
			{
//#ifdef _DEBUG
				printf("Unable To Allocate PE File Memory!\n");
//#endif
				return {};
			}

#ifdef PE_TOOLS_ALLOW_INLINE_LAMBDAS
			static FreeBuffer = [&]() [[msvc::forceinline]]
			{
				ptFreeMemory(pMappedModuleMem);
			};
#define FREE_AND_EXIT() FreeBuffer(); return {};
#else
#define FREE_AND_EXIT() ptFreeMemory(pMappedModuleMem); return {};
#endif


			if (!MapPESectionsToMemory(pPEFile, nFileSize, pMappedModuleMem, pOpt->SizeOfImage))
			{
#ifdef _DEBUG
				printf("Unable To Map PE Sections To Memory!\n");
#endif
				FREE_AND_EXIT();
			}

			pMappedPEFile = pMappedModuleMem;
		}



		auto pOpt = GetOptionalHeader(pMappedPEFile);

		// It's Basically The Same Code, Lets Just Do This
		char Tables[] = { IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT };
		PIMAGE_DATA_DIRECTORY pDataDirectory = &pOpt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

		for (int i = 0; i < sizeof(Tables); i++, pDataDirectory = &(pOpt->DataDirectory[Tables[i]]))
		{
			if (!pDataDirectory->Size)
				continue;

			// Since Structures Are Slightly Different
			bool bDelayed = Tables[i] == IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT;

			PIMAGE_IMPORT_DESCRIPTOR piDescriptor = bDelayed ? nullptr :
				reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(
					(char*)pMappedPEFile + pDataDirectory->VirtualAddress
					);

			PIMAGE_DELAYLOAD_DESCRIPTOR piDelayDescriptor = bDelayed ? reinterpret_cast<PIMAGE_DELAYLOAD_DESCRIPTOR>(
				(char*)pMappedPEFile + pDataDirectory->VirtualAddress
				) : nullptr;

			// Remove ? Keep ? Undecided Here. According to MSVC This Should Always Be Expanded
			// IDA Shows That Is True On All Build Options But DEBUG.
			// But If This Is Popped Out To ShellCode And It's Not, Isssues Will Arise!
#ifdef PE_TOOLS_ALLOW_INLINE_LAMBDAS // even msvc considers these experimental
			auto IncrementDescriptor = [&]() [[msvc::forceinline]]
			{
				if (bDelayed)
					piDelayDescriptor++;
				else
					 piDescriptor++;
			};
#endif

			for (
				;
				bDelayed ? piDelayDescriptor->DllNameRVA : piDescriptor->Name;
#ifdef PE_TOOLS_ALLOW_INLINE_LAMBDAS
				IncrementDescriptor()
#endif
				) // Iterate Each Module Within The Import Table
			{
				char* szMod = reinterpret_cast<char*>((char*)pMappedPEFile +
					(bDelayed ? piDelayDescriptor->DllNameRVA : piDescriptor->Name)
					);

				mods_to_load.push_back(std::string(szMod));
			
#ifndef PE_TOOLS_ALLOW_INLINE_LAMBDAS
				if (bDelayed)
					piDelayDescriptor++;
				else
					piDescriptor++;
#endif
			}
		}

		ptFreeMemory(pMappedPEFile);

		return mods_to_load;

	}

}