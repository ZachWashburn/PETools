#include <PETools.h>
#include <WindowsSysCalls.h>
#include <PEBStructs.h>


namespace PETools
{
	typedef NTSTATUS(NTAPI* fnNtWriteVirtualMemory_t)(
		IN HANDLE               ProcessHandle,
		IN PVOID                BaseAddress,
		IN PVOID                Buffer,
		IN ULONG                NumberOfBytesToWrite,
		OUT PULONG              NumberOfBytesWritten OPTIONAL
		);

	typedef NTSTATUS(NTAPI* fnNtReadVirtualMemory_t)(
		IN HANDLE               ProcessHandle,
		IN PVOID                BaseAddress,
		OUT PVOID               Buffer,
		IN ULONG                NumberOfBytesToRead,
		OUT PULONG              NumberOfBytesReaded OPTIONAL
		);

	NTSTATUS PETOOLSCALL PtWriteVirtualMemory(HANDLE hHand, LPVOID plBaseAddr, LPVOID lpBuffer, ULONG ulNumBytesToWrite, PULONG ulBytesWritten)
	{
		WINDOWS_SYSCALL(NtWriteVirtualMemory, fnNtWriteVirtualMemory_t, 58);
		return _NtWriteVirtualMemory(hHand, plBaseAddr, lpBuffer, ulNumBytesToWrite, ulBytesWritten);
	}


	NTSTATUS PETOOLSCALL PtWriteVirtualMemoryInsure(HANDLE hHand, LPVOID plBaseAddr, LPVOID lpBuffer, ULONG ulNumBytesToWrite)
	{
		ULONG ulBytesWritten = NULL;
		NTSTATUS ntStat;
		while (NT_SUCCESS(ntStat = PtWriteVirtualMemory(hHand, plBaseAddr, lpBuffer, ulNumBytesToWrite, &ulBytesWritten))
			&& NT_SUCCESS(ntStat)
			&& ulBytesWritten < ulNumBytesToWrite)
		{
		}

		return ntStat;
	}

	NTSTATUS PETOOLSCALL PtReadVirtualMemory(
		HANDLE               ProcessHandle,
		PVOID                BaseAddress,
		PVOID               Buffer,
		ULONG                NumberOfBytesToRead,
		PULONG              NumberOfBytesReaded
	) {
		WINDOWS_SYSCALL(NtReadVirtualMemory, fnNtReadVirtualMemory_t, 63);
		return _NtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
	}


	NTSTATUS PETOOLSCALL PtReadVirtualMemoryInsure(
		HANDLE               ProcessHandle,
		PVOID                BaseAddress,
		PVOID               Buffer,
		ULONG                NumberOfBytesToRead
	) {
		WINDOWS_SYSCALL(NtReadVirtualMemory, fnNtReadVirtualMemory_t, 63);
		NTSTATUS ntStat;
		ULONG ulBytesRead = NULL;
		while (NT_SUCCESS(ntStat = PtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, &ulBytesRead))
			&& NT_SUCCESS(ntStat)
			&& ulBytesRead < NumberOfBytesToRead)
		{
		}

		return ntStat;
	}

	typedef NTSTATUS(NTAPI* fnNtCreateThreadEx_t)
		(
			OUT PHANDLE hThread,
			IN ACCESS_MASK DesiredAccess,
			IN PVOID ObjectAttributes,
			IN HANDLE ProcessHandle,
			IN PVOID lpStartAddress,
			IN PVOID lpParameter,
			IN ULONG Flags,
			IN SIZE_T StackZeroBits,
			IN SIZE_T SizeOfStackCommit,
			IN SIZE_T SizeOfStackReserve,
			OUT PVOID lpBytesBuffer
			);
	// https://securityxploded.com/ntcreatethreadex.php#About_NtCreateThreadEx_function
	struct NtCreateThreadExBuffer
	{
		ULONG Size;
		ULONG Unknown1;
		ULONG Unknown2;
		PULONG Unknown3;
		ULONG Unknown4;
		ULONG Unknown5;
		ULONG Unknown6;
		PULONG Unknown7;
		ULONG Unknown8;
	};

	NTSTATUS PtCreateRemoteThread(HANDLE hHandle, PHANDLE phThread, LPTHREAD_START_ROUTINE pFunc, LPVOID pRemoteParam)
	{

		WINDOWS_SYSCALL(NtCreateThreadEx, fnNtCreateThreadEx_t, 193);


		NTSTATUS status = _NtCreateThreadEx(
			phThread,
			0x1FFFFF,
			NULL,
			hHandle,
			(LPTHREAD_START_ROUTINE)pFunc,
			pRemoteParam,
			FALSE, //start instantly
			NULL,
			NULL,
			NULL,
			NULL
		);



		return status;
	}

	typedef NTSTATUS(NTAPI* fnNtQueryInformationThread_t)(
		HANDLE          ThreadHandle,
		THREADINFOCLASS2 ThreadInformationClass,
		PVOID           ThreadInformation,
		ULONG           ThreadInformationLength,
		PULONG          ReturnLength
		);

	BOOL WINAPI PtGetExitCodeThread(IN HANDLE hThread,
		OUT LPDWORD lpExitCode)
	{
		WINDOWS_SYSCALL(NtQueryInformationThread, fnNtQueryInformationThread_t, 37);
		THREAD_BASIC_INFORMATION2 ThreadBasic;
		NTSTATUS Status;

		Status = _NtQueryInformationThread(hThread,
			THREADINFOCLASS2::ThreadBasicInformation,
			&ThreadBasic,
			sizeof(_THREAD_BASIC_INFORMATION2),
			NULL);

		if (!NT_SUCCESS(Status))
			return FALSE;

		*lpExitCode = ThreadBasic.ExitStatus;
		return TRUE;
	}


	typedef NTSTATUS(NTAPI* fnNtCreateTransaction_t)
		(
			PHANDLE            TransactionHandle,
			ACCESS_MASK        DesiredAccess,
			_OBJECT_ATTRIBUTES2* ObjectAttributes,
			LPGUID             Uow,
			HANDLE             TmHandle,
			ULONG              CreateOptions,
			ULONG              IsolationLevel,
			ULONG              IsolationFlags,
			PLARGE_INTEGER     Timeout,
			PUNICODE_STRING    Description
			);


	NTSTATUS NTAPI PtCreateTransaction [[msvc::forceinline]]
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
		)
	{
		WINDOWS_SYSCALL(NtCreateTransaction, fnNtCreateTransaction_t, 198);

		return _NtCreateTransaction(
			TransactionHandle, DesiredAccess, (_OBJECT_ATTRIBUTES2*)ObjectAttributes,
			Uow, TmHandle, CreateOptions, IsolationLevel, IsolationFlags, (PLARGE_INTEGER)pLargeIntTimeout, (PUNICODE_STRING)puniDescription
		);
	}

	typedef NTSTATUS(NTAPI* fnNtCreateSection_t)
		(
			PHANDLE SectionHandle,
			ACCESS_MASK DesiredAccess,
			_OBJECT_ATTRIBUTES2* ObjectAttributes,
			PLARGE_INTEGER MaximumSize,
			ULONG SectionPageProtection,
			ULONG AllocationAttributes,
			HANDLE FileHandle
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
	)
	{
		WINDOWS_SYSCALL(NtCreateSection, fnNtCreateSection_t, 74);

		return _NtCreateSection(
			SectionHandle, DesiredAccess, (_OBJECT_ATTRIBUTES2*)ObjectAttributes,
			(PLARGE_INTEGER)pLargIntMaximumSize, SectionPageProtection,
			AllocationAttributes, FileHandle
		);
	}

	typedef NTSTATUS(NTAPI* fnZwCreateProcessEx_t)
		(
			PHANDLE     ProcessHandle,
			ACCESS_MASK  DesiredAccess,
			_OBJECT_ATTRIBUTES2* ObjectAttributes  OPTIONAL,
			HANDLE   ParentProcess,
			ULONG    Flags,
			HANDLE SectionHandle     OPTIONAL,
			HANDLE DebugPort     OPTIONAL,
			HANDLE ExceptionPort     OPTIONAL,
			/*BOOLEAN*/ DWORD  InJob
			);

	// Only Works On 64 Bit Processes
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
	)
	{
		WINDOWS_SYSCALL(ZwCreateProcessEx, fnZwCreateProcessEx_t, 77);

		return _ZwCreateProcessEx(
			ProcessHandle, DesiredAccess, (_OBJECT_ATTRIBUTES2*)ObjectAttributes,
			ParentProcess, Flags, SectionHandle, DebugPort, ExceptionPort, InJob
		);
	}

	typedef NTSTATUS(WINAPI* _fnNtClose_t)(HANDLE Handle);

	NTSTATUS WINAPI PtClose(HANDLE Handle)
	{
		HASH_OF_DEF(NtClose);
		SysCall::_windows_syscall_t<_fnNtClose_t> __NtClose(-1, HASH_OF_REF(NtClose));

		return __NtClose(Handle);
	}

	typedef NTSTATUS(NTAPI* fnZwQueryInformationProcess_t)(
		_In_      HANDLE           ProcessHandle,
		_In_      PROCESSINFOCLASS2 ProcessInformationClass,
		_Out_     PVOID            ProcessInformation,
		_In_      ULONG            ProcessInformationLength,
		_Out_opt_ PULONG           ReturnLength
		);

	NTSTATUS NTAPI  PtQueryInformationProcess(
		_In_      HANDLE           ProcessHandle,
		_In_      DWORD			   ProcessInformationClass,
		_Out_     PVOID            ProcessInformation,
		_In_      ULONG            ProcessInformationLength,
		_Out_opt_ PULONG           ReturnLength
	)
	{
		WINDOWS_SYSCALL(ZwQueryInformationProcess, fnZwQueryInformationProcess_t, 25);

		return _ZwQueryInformationProcess(ProcessHandle,
			(PROCESSINFOCLASS2)ProcessInformationClass, ProcessInformation,
			ProcessInformationLength, ReturnLength
		);
	}

	typedef NTSTATUS(NTAPI* fnNtCreateUserProcess_t)(
		_Out_ PHANDLE ProcessHandle,
		_Out_ PHANDLE ThreadHandle,
		_In_ ACCESS_MASK ProcessDesiredAccess,
		_In_ ACCESS_MASK ThreadDesiredAccess,
		_In_opt_ _OBJECT_ATTRIBUTES2* ProcessObjectAttributes,
		_In_opt_ _OBJECT_ATTRIBUTES2* ThreadObjectAttributes,
		_In_ ULONG ProcessFlags,
		_In_ ULONG ThreadFlags,
		_In_ PRTL_USER_PROCESS_PARAMETERS ProcessParameters,
		_Inout_ PPS_CREATE_INFO2 CreateInfo,
		_In_ PPS_ATTRIBUTE_LIST2 AttributeList
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
	)
	{
		WINDOWS_SYSCALL(NtCreateUserProcess, fnNtCreateUserProcess_t, 200);

		return _NtCreateUserProcess(
			ProcessHandle, ThreadHandle, ProcessDesiredAccess, ThreadDesiredAccess,
			(_OBJECT_ATTRIBUTES2*)ProcessObjectAttributes, (_OBJECT_ATTRIBUTES2*)ThreadObjectAttributes,
			ProcessFlags, ThreadFlags,
			(PRTL_USER_PROCESS_PARAMETERS)ProcessParameters, (PPS_CREATE_INFO2)CreateInfo,
			(PPS_ATTRIBUTE_LIST2)AttributeList
		);
	}

	typedef NTSTATUS(NTAPI* fnRtlCreateProcessParametersEx_t)(
		_Out_ PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
		_In_ PUNICODE_STRING ImagePathName,
		_In_opt_ PUNICODE_STRING DllPath,
		_In_opt_ PUNICODE_STRING CurrentDirectory,
		_In_opt_ PUNICODE_STRING CommandLine,
		_In_opt_ PVOID Environment,
		_In_opt_ PUNICODE_STRING WindowTitle,
		_In_opt_ PUNICODE_STRING DesktopInfo,
		_In_opt_ PUNICODE_STRING ShellInfo,
		_In_opt_ PUNICODE_STRING RuntimeData,
		_In_ ULONG Flags
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
	)
	{
		constexpr unsigned long rtl_create_process_param_hash = PeToolsDefaultHasherConstExpr<const char*>("RtlCreateProcessParametersEx");
		fnRtlCreateProcessParametersEx_t _RtlCreateProcessParametersEx =
			(fnRtlCreateProcessParametersEx_t)_GetExportAddress(ptGetNtDll(), 0,
				rtl_create_process_param_hash, &PeToolsDefaultHasher);


		return  _RtlCreateProcessParametersEx((PRTL_USER_PROCESS_PARAMETERS*)pProcessParameters,
			(PUNICODE_STRING)ImagePathName, (PUNICODE_STRING)DllPath, (PUNICODE_STRING)CurrentDirectory,
			(PUNICODE_STRING)CommandLine, Environment, (PUNICODE_STRING)WindowTitle,
			(PUNICODE_STRING)DesktopInfo, (PUNICODE_STRING)ShellInfo, (PUNICODE_STRING)RuntimeData,
			Flags
		);
	}



#define NTDLLIMPORT(Name, type) constexpr unsigned long hash_##Name = PeToolsDefaultHasherConstExpr<const char*>(#Name); \
								type _##Name = (type)_GetExportAddress(ptGetNtDll(), 0, hash_##Name, &PeToolsDefaultHasher);


	typedef PVOID(NTAPI* fnRtlAllocateHeap_t)(
		PVOID  HeapHandle,
		ULONG  Flags,
		SIZE_T Size
		);

	PVOID NTAPI PtAllocateHeap(
		PVOID  HeapHandle,
		ULONG  Flags,
		SIZE_T Size
	)
	{
		NTDLLIMPORT(RtlAllocateHeap, fnRtlAllocateHeap_t);
#if 0
		constexpr unsigned long rtl_create_process_param_hash = PeToolsDefaultHasherConstExpr<const char*>("RtlAllocateHeap");
		fnRtlAllocateHeap_t _RtlAllocateHeap =
			(fnRtlAllocateHeap_t)_GetExportAddress(ptGetNtDll(), 0,
				rtl_create_process_param_hash, &PeToolsDefaultHasher);
#endif
		return _RtlAllocateHeap(HeapHandle, Flags, Size);
	}




	typedef DWORD(NTAPI* fnRtlFreeHeap_t)(
		PVOID                 HeapHandle,
		ULONG                 Flags,
		_Frees_ptr_opt_ PVOID BaseAddress
		);

	DWORD NTAPI PtFreeHeap(
		PVOID                 HeapHandle,
		ULONG                 Flags,
		_Frees_ptr_opt_ PVOID BaseAddress
	)
	{
		NTDLLIMPORT(RtlFreeHeap, fnRtlFreeHeap_t);
		return _RtlFreeHeap(HeapHandle, Flags, BaseAddress);
	}


	NTSTATUS PtDestroyProcessParameters(
		IN /*PRTL_USER_PROCESS_PARAMETERS*/ PVOID ProcessParameters
	)
	{
		PtFreeHeap(RtlProcessHeap(), 0, ProcessParameters);
		return STATUS_SUCCESS;
	}

	typedef NTSTATUS(NTAPI* fnZwUnmapViewOfSection_t)(
		HANDLE ProcessHandle,
		PVOID  BaseAddress
		);

	NTSTATUS PtUnmapViewOfSection(
		HANDLE ProcessHandle,
		PVOID  BaseAddress
	)
	{
		WINDOWS_SYSCALL(ZwUnmapViewOfSection, fnZwUnmapViewOfSection_t, 460);
		return _ZwUnmapViewOfSection(ProcessHandle, BaseAddress);
	}

	typedef NTSTATUS(NTAPI* fnZwResumeThread_t)(
		HANDLE ThreadHandle,
		PULONG PreviousSuspendCount
		);

	NTSTATUS PtResumeThread(
		HANDLE ThreadHandle,
		PULONG PreviousSuspendCount
	)
	{
		WINDOWS_SYSCALL(ZwResumeThread, fnZwResumeThread_t, 458834);
		return _ZwResumeThread(ThreadHandle, PreviousSuspendCount);
	}

	
	typedef	NTSTATUS (NTAPI* fnZwSetContextThread_t)(
			IN HANDLE               ThreadHandle,
			IN PCONTEXT             Context
	);

	NTSTATUS NTAPI PtSetContextThread(
		IN HANDLE               ThreadHandle,
		IN PCONTEXT             Context
	)
	{
		WINDOWS_SYSCALL(ZwSetContextThread, fnZwSetContextThread_t, 395);
		return _ZwSetContextThread(ThreadHandle, Context);
	}

	
	typedef NTSTATUS(NTAPI* fnNtGetContextThread_t)
		(
		IN HANDLE               ThreadHandle,
		OUT PCONTEXT            pContext
		);

	NTSTATUS NTAPI PtGetContextThread
	(
		IN HANDLE               ThreadHandle,
		OUT PCONTEXT            pContext
	)
	{
		WINDOWS_SYSCALL(NtGetContextThread, fnNtGetContextThread_t, 242);
		return _NtGetContextThread(ThreadHandle, pContext);
	}


	typedef NTSTATUS(NTAPI* fnZwTerminateThread_t)(
		HANDLE ThreadHandle,
		NTSTATUS ExitStatus
	);

	NTSTATUS NTAPI PtTerminateThread(
		HANDLE ThreadHandle,
		NTSTATUS ExitStatus
	)
	{
		WINDOWS_SYSCALL(ZwTerminateThread, fnZwTerminateThread_t, 242);
		return _ZwTerminateThread(ThreadHandle, 458835);
	}


}
