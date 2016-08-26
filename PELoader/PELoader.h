<<<<<<< HEAD
#pragma once
#include <iostream>
#include <string>
#include <Windows.h>

using std::string;

class PELoader
{
public:
	PELoader();
	~PELoader();

	enum ErrCode
	{
		PE_SUCCESS = 0,
		PE_MEM_ALLOC_FAIL = -50,
		PE_FILE_READ_FAIL,
		PE_FILE_OPEN_FAIL,
		PE_PARAM_INVALID,
		PE_CREATE_PROC_FAIL,
		PE_GET_CONTEXT_FAIL
	};

	int InjectFromFile(string path);
	int CreateFakeProc(string path);
	int MapImage(DWORD base);
	int Run();

private:

	typedef NTSTATUS(__stdcall *pfnZwUnmapViewOfSection)(
		IN HANDLE ProcessHandle,
		IN LPVOID BaseAddress
		);


	DWORD FileSize;
	char *FileBuffer;

	IMAGE_DOS_HEADER *MZHeader;
	IMAGE_NT_HEADERS *NTHeader;
	IMAGE_FILE_HEADER *FileHeader;
	IMAGE_OPTIONAL_HEADER *OpHeader;




	PROCESS_INFORMATION pi;
	CONTEXT ThreadCxt;
	PVOID BaseAddress;

	int AnalyzePE();
	int LoadFile(string path);
	DWORD GetRemoteProcessImageBase(int ebx);
	BOOL PerformBaseRelocation(unsigned char *codeBase, ptrdiff_t delta);
	pfnZwUnmapViewOfSection ZwUnmapViewOfSection;
};

=======
#pragma once
#include <iostream>
#include <string>
#include <Windows.h>

using std::string;

class PELoader
{
public:
	PELoader();
	~PELoader();

	enum ErrCode
	{
		PE_SUCCESS = 0,
		PE_MEM_ALLOC_FAIL = -50,
		PE_FILE_READ_FAIL,
		PE_FILE_OPEN_FAIL,
		PE_PARAM_INVALID,
		PE_CREATE_PROC_FAIL,
		PE_GET_CONTEXT_FAIL
	};

	int InjectFromFile(string path);
	int CreateFakeProc(string path);
	int MapImage(DWORD base);
	int Run();

private:

	typedef NTSTATUS(__stdcall *pfnZwUnmapViewOfSection)(
		IN HANDLE ProcessHandle,
		IN LPVOID BaseAddress
		);


	DWORD FileSize;
	char *FileBuffer;

	IMAGE_DOS_HEADER *MZHeader;
	IMAGE_NT_HEADERS *NTHeader;
	IMAGE_FILE_HEADER *FileHeader;
	IMAGE_OPTIONAL_HEADER *OpHeader;




	PROCESS_INFORMATION pi;
	CONTEXT ThreadCxt;
	PVOID BaseAddress;

	int AnalyzePE();
	int LoadFile(string path);
	DWORD GetRemoteProcessImageBase(int ebx);
	BOOL PerformBaseRelocation(unsigned char *codeBase, ptrdiff_t delta);
	pfnZwUnmapViewOfSection ZwUnmapViewOfSection;
};

>>>>>>> e167402864d2211599708597626a859cc3ea0e47
