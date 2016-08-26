#include "PELoader.h"


PELoader::PELoader()
{
	ZwUnmapViewOfSection = (pfnZwUnmapViewOfSection)GetProcAddress(
		GetModuleHandleA("ntdll.dll"), "ZwUnmapViewOfSection");
}


PELoader::~PELoader()
{
}

int PELoader::LoadFile(string path)
{
	int ret = PE_SUCCESS;
	FILE *fp = NULL;

	if (FileBuffer != NULL)
		delete[] FileBuffer;
	FileBuffer = NULL;
	FileSize = 0;
	printf("Opening %s...\n", path.data());
	fopen_s(&fp, path.data(), "rb");
	if (fp == NULL)
	{
		ret = PE_FILE_OPEN_FAIL;
		goto END;
	}
	fseek(fp, 0, SEEK_END);
	FileSize = ftell(fp);
	printf("File size: %d\n", FileSize);
	fseek(fp, 0, SEEK_SET);
	FileBuffer = new char[FileSize];

	if (FileBuffer == 0)
	{
		ret = PE_MEM_ALLOC_FAIL;
		goto END;
	}
	if (fread(FileBuffer, FileSize, 1, fp) != 1)
	{
		ret = PE_FILE_READ_FAIL;
		goto CLEAN;
	}

	goto END;

CLEAN:
	delete[] FileBuffer;

END:
	if (fp)
	{
		fclose(fp);
		fp = NULL;
	}
	return ret;
}

int PELoader::InjectFromFile(string path)
{
	int ret = PE_SUCCESS;

	if (path.empty())
	{
		ret = PE_PARAM_INVALID;
		goto END;
	}

	ret = LoadFile(path);
	if (ret != PE_SUCCESS)
	{
		goto END;
	}
	
	ret = AnalyzePE();
	if (ret != PE_SUCCESS)
	{
		goto END;
	}

END:
	return ret;
}

int PELoader::CreateFakeProc(string path)
{
	int ret = PE_SUCCESS;
	STARTUPINFO si = { 0 };
	if (path.empty())
	{
		ret = PE_PARAM_INVALID;
		goto END;
	}

	memset(&pi, 0, sizeof(PROCESS_INFORMATION));
	if (!CreateProcess(NULL, (LPSTR)path.data(), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
	{
		ret = PE_CREATE_PROC_FAIL;
		goto END;
	}

	ThreadCxt.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(pi.hThread, &ThreadCxt))
	{
		ret = PE_GET_CONTEXT_FAIL;
		goto END;
	}


END:
	return ret;
}

int PELoader::MapImage(DWORD base)
{
	int ret = PE_SUCCESS;
	unsigned char *tmp_buf = NULL;
	
	if (base == 0)
		base = NTHeader->OptionalHeader.ImageBase;

	tmp_buf = (unsigned char *)malloc(OpHeader->SizeOfImage);
	if (!tmp_buf)
	{
		ret = PE_MEM_ALLOC_FAIL;
		goto END;
	}
	memset(tmp_buf, 0, OpHeader->SizeOfImage);

	base = GetRemoteProcessImageBase(ThreadCxt.Ebx);
	
	if (ZwUnmapViewOfSection)
	{
		
		
		ret = ZwUnmapViewOfSection(pi.hProcess, (LPVOID)base);
		if (ret)
		{
			printf("Fail to unmap mem: %d\n",ret);
			exit(-1);
		}
		
		BaseAddress = VirtualAllocEx(pi.hProcess, NULL, OpHeader->SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	}

	if (!BaseAddress)
	{
		printf("Fail to malloc %d bytes mem on %p with code: %d\n", OpHeader->SizeOfImage, base, GetLastError());
		ret = PE_MEM_ALLOC_FAIL;
		goto END;
	}

	

	
	memcpy(tmp_buf, MZHeader, NTHeader->OptionalHeader.SizeOfHeaders);
	//WriteProcessMemory(pi.hProcess, BaseAddress, MZHeader, NTHeader->OptionalHeader.SizeOfHeaders, NULL);

	// Replace sections
	PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)((DWORD)MZHeader + MZHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
	for (int idx = 0; idx < NTHeader->FileHeader.NumberOfSections; ++idx, pSectionHeader++)
	{
		memcpy(tmp_buf + pSectionHeader->VirtualAddress, (char *)MZHeader + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);
	}
	
	WriteProcessMemory(pi.hProcess, (LPVOID)BaseAddress, (LPCVOID)tmp_buf, NTHeader->OptionalHeader.SizeOfImage, NULL);
	WriteProcessMemory(pi.hProcess, (LPVOID)(ThreadCxt.Ebx + 8), (LPCVOID)&BaseAddress, sizeof(PVOID), NULL);
	printf("Src Base: %p\n", base);
	printf("Src EP: %p\n", ThreadCxt.Eax);
	//ThreadCxt.Eax = (DWORD)BaseAddress + NTHeader->OptionalHeader.AddressOfEntryPoint;
	ThreadCxt.Eax = OpHeader->ImageBase + NTHeader->OptionalHeader.AddressOfEntryPoint;
	//ThreadCxt.Eax = 0;
	SetThreadContext(pi.hThread, &ThreadCxt);
	printf("Base: %p\n", BaseAddress);
	printf("EP: %p\n", ThreadCxt.Eax);

END:
	if (tmp_buf)
	{
		free(tmp_buf);
	}
	return ret;
}

int PELoader::Run()
{
	ResumeThread(pi.hThread);
	return PE_SUCCESS;
}

int PELoader::AnalyzePE()
{
	int ret = PE_SUCCESS;

	MZHeader = (IMAGE_DOS_HEADER *)FileBuffer;
	NTHeader = (IMAGE_NT_HEADERS *)(FileBuffer + MZHeader->e_lfanew);
	FileHeader = &(NTHeader->FileHeader);
	OpHeader = &(NTHeader->OptionalHeader);
	
	return ret;
}


DWORD PELoader::GetRemoteProcessImageBase(int ebx)
{
	DWORD dwBaseRet;
	ReadProcessMemory(pi.hProcess, (LPVOID)(ebx + 8), &dwBaseRet, sizeof(DWORD), NULL);
	return dwBaseRet;
}