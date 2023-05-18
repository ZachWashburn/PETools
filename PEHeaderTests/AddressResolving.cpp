#include <PETools.h>
#include <PEBStructs.h>



namespace PETools
{
	bool ResolveImportsEx(HANDLE hHandle, void* pMappedPEFile, HMODULE(__stdcall* pfnlibLdr)(const char*), FARPROC(__stdcall* pfnGetFunc)(HMODULE, const char*))
	{
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

				HMODULE hDll = pfnlibLdr(szMod);

				if (!hDll || (hDll == INVALID_HANDLE_VALUE))
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
						ULONG_PTR pAddr = (ULONG_PTR)pfnGetFunc(hDll, reinterpret_cast<char*>(ptOriginal->u1.Ordinal));
						//ptFirst->u1.Function = 
						PtWriteVirtualMemoryInsure(hHandle, &ptFirst->u1.Function, &pAddr, sizeof(pAddr));				
					}
					else {
						PIMAGE_IMPORT_BY_NAME pImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>((char*)pMappedPEFile + ptOriginal->u1.AddressOfData);
						ULONG_PTR pAddr = (ULONG_PTR)pfnGetFunc(hDll, pImport->Name);
						PtWriteVirtualMemoryInsure(hHandle, &ptFirst->u1.Function, &pAddr, sizeof(pAddr));

					}

					if (!ptFirst->u1.Function)
					{
#ifdef _DEBUG
						if (!IMAGE_SNAP_BY_ORDINAL(ptOriginal->u1.Ordinal))
						{
							PIMAGE_IMPORT_BY_NAME pImport = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>((char*)pMappedPEFile + ptOriginal->u1.AddressOfData);
							printf("Error Fetching Function %s from %s\n", pImport->Name, szMod);
#ifdef PE_TOOLS_IGNORE_IMPORT_ERRORS
							continue;
#endif

						}
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



}