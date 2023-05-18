#include <PETools.h>
#include <PEBStructs.h>

namespace PETools
{
	bool MapPESectionsToMemoryEx(
		HANDLE hHandle,
		void* pPEFileData,
		size_t nImageSize,
		void* pMemory,
		size_t nMemorySize
	)
	{
		char pe_header_mem[0x400];


		PIMAGE_SECTION_HEADER pSection = GetSectionHeaderByIndex(pPEFileData, 0);

		if (!pSection)
			return false;

		PIMAGE_OPTIONAL_HEADER pOpt = GetOptionalHeader(pe_header_mem);

		PtWriteVirtualMemoryInsure(hHandle, pMemory, pPEFileData, min(0x400, nImageSize));
		PtReadVirtualMemoryInsure(hHandle, pMemory, pe_header_mem, sizeof(pe_header_mem));

		PIMAGE_DOS_HEADER pDos = GetDosHeader(pe_header_mem);
		PIMAGE_NT_HEADERS pNT = reinterpret_cast<PIMAGE_NT_HEADERS>((char*)pe_header_mem + pDos->e_lfanew);
		pOpt = &pNT->OptionalHeader;
		PIMAGE_FILE_HEADER pFile = &pNT->FileHeader;


		PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pNT);
		int nSections = pFile->NumberOfSections;
		for (int i = 0; i < nSections; i++)
		{
			PIMAGE_SECTION_HEADER pSection = &(pFirstSection[i]);
			void* pWriteOffset = (char*)pMemory + pSection->VirtualAddress;

			PtWriteVirtualMemoryInsure(hHandle, pWriteOffset,
				(char*)pPEFileData + pSection->PointerToRawData, pSection->SizeOfRawData
			);
		}

		return true;
	}

	bool MapPESectionsToMemory(
		void* pPEFileData,
		size_t nImageSize,
		void* pMemory,
		size_t nMemorySize
	)
	{
		return MapPESectionsToMemoryEx(
			NtCurrentProcess(),
			pPEFileData,
			nImageSize,
			pMemory,
			nMemorySize
		);
	}




}
