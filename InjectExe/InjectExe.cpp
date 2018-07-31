// InjectExe.cpp: Inject the whole exe into another process
//

#include "stdafx.h"
#include <array>

#include "InjectExe.h"

using namespace std;

namespace
{
	bool isInRemoteProcess = false;

	struct InjectionContext
	{
		LPVOID imageBase; // remoteImageBase
		uintptr_t offset; // remoteImageBase - imageBase
		array<TCHAR, MAX_PATH> filePath;
	};
	DWORD WINAPI RemoteStartup(InjectionContext* ctx);
	bool RelocateModuleBase(InjectionContext* ctx);
	bool ResolveImportTable(InjectionContext* ctx);
	//bool RestoreGlobalVariables(InjectionContext* ctx);
	bool ExecuteTlsCallback(InjectionContext* ctx);
	bool CallModuleEntry(InjectionContext* ctx);
}


bool IsInRemoteProcess()
{
	return isInRemoteProcess;
}

// Inject the whole exe into another process. Call main() in the target process.
// Return the address of exe in the target process, or NULL if fail
LPVOID InjectExe(HANDLE process)
{
	HMODULE module = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)module;
	PIMAGE_NT_HEADERS ntHeader = PIMAGE_NT_HEADERS((uintptr_t)dosHeader + dosHeader->e_lfanew);
	LPVOID imageBase = (LPVOID)module;
	SIZE_T imageSize = ntHeader->OptionalHeader.SizeOfImage;

	LPVOID remoteImageBase = NULL;
	LPVOID remoteCtx = NULL;
	HANDLE remoteThread = NULL;
	try
	{
		// Write the whole exe
		remoteImageBase = VirtualAllocEx(process, imageBase, imageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (remoteImageBase == NULL)
		{
			remoteImageBase = VirtualAllocEx(process, NULL, imageSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (remoteImageBase == NULL)
				throw runtime_error("Failed to allocate remoteImageBase");
		}
		if (!WriteProcessMemory(process, remoteImageBase, imageBase, imageSize, NULL))
			throw runtime_error("Failed to write remoteImageBase");

		// Prepare InjectionContext
		uintptr_t offset = (uintptr_t)remoteImageBase - (uintptr_t)imageBase;
		InjectionContext ctx;
		ctx.imageBase = remoteImageBase;
		ctx.offset = offset;
		GetModuleFileName(module, &ctx.filePath.front(), (DWORD)ctx.filePath.size());

		// Write InjectionContext
		remoteCtx = VirtualAllocEx(process, NULL, imageSize, MEM_COMMIT, PAGE_READWRITE);
		if (remoteCtx == NULL)
			throw runtime_error("Failed to allocate remoteCtx");
		if (!WriteProcessMemory(process, remoteCtx, &ctx, sizeof(ctx), NULL))
			throw runtime_error("Failed to write remoteCtx");

		// Call RemoteStartup in the target process
		LPTHREAD_START_ROUTINE remoteStartup = LPTHREAD_START_ROUTINE((uintptr_t)RemoteStartup + offset);
		remoteThread = CreateRemoteThread(process, NULL, 0, remoteStartup, remoteCtx, 0, NULL);
		if (remoteThread == NULL)
			throw runtime_error("Failed to create remote thread");
		WaitForSingleObject(remoteThread, INFINITE);
		DWORD exitCode;
		GetExitCodeThread(remoteThread, &exitCode);
		if (exitCode != 0)
		{
			SetLastError(exitCode);
			throw runtime_error("RemoteStartup failed");
		}
		
		return remoteImageBase;
	}
	catch (runtime_error& e)
	{
		cerr << e.what() << ": " << GetLastError() << endl;
		CloseHandle(remoteThread);
		VirtualFreeEx(process, remoteCtx, sizeof(InjectionContext), MEM_DECOMMIT);
		VirtualFreeEx(process, remoteImageBase, imageSize, MEM_DECOMMIT);
		return NULL;
	}
	CloseHandle(remoteThread);
	VirtualFreeEx(process, remoteCtx, sizeof(InjectionContext), MEM_DECOMMIT);
	return remoteImageBase;
}

namespace
{
	// Called in the target process
	DWORD WINAPI RemoteStartup(InjectionContext* ctx)
	{
		if (!RelocateModuleBase(ctx))
			return 1;
		if (!ResolveImportTable(ctx))
			return 2;
		/*if (!RestoreGlobalVariables(ctx))
			return 3;*/
		isInRemoteProcess = true;
		if (!ExecuteTlsCallback(ctx))
			return 4;
		if (!CallModuleEntry(ctx))
			return 5;
		return 0;
	}

	// Copyed from mmLoader: https://github.com/tishion/mmLoader

	bool RelocateModuleBase(InjectionContext* ctx)
	{
		// This module has been loaded to the ImageBase, no need to do relocation
		if (ctx->offset == 0)
			return true;

		auto dosHeader = (PIMAGE_DOS_HEADER)ctx->imageBase;
		auto ntHeader = PIMAGE_NT_HEADERS((uintptr_t)dosHeader + dosHeader->e_lfanew);
		if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress == 0
			|| ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size == 0)
			return true;

		auto relocation = PIMAGE_BASE_RELOCATION((uintptr_t)ctx->imageBase +
			ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		if (relocation == NULL) // Invalid
			return false;
		while (relocation->VirtualAddress + relocation->SizeOfBlock != 0)
		{
			auto relocationData = PWORD((uintptr_t)relocation + sizeof(IMAGE_BASE_RELOCATION));
			int nRelocationData = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			for (int i = 0; i < nRelocationData; i++)
			{
				if (relocationData[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
				{
					auto address = (uint32_t*)((uintptr_t)ctx->imageBase + relocation->VirtualAddress + (relocationData[i] & 0x0FFF));
					*address += (uint32_t)ctx->offset;
				}
#ifdef _WIN64
				if (relocationData[i] >> 12 == IMAGE_REL_BASED_DIR64)
				{
					auto address = (uint64_t*)((uintptr_t)ctx->imageBase + relocation->VirtualAddress + (relocationData[i] & 0x0FFF));
					*address += ctx->offset;
				}
#endif
			}
			relocation = PIMAGE_BASE_RELOCATION((uintptr_t)relocation + relocation->SizeOfBlock);
		}
		return true;
	}

	bool ResolveImportTable(InjectionContext* ctx)
	{
		auto dosHeader = (PIMAGE_DOS_HEADER)ctx->imageBase;
		auto ntHeader = PIMAGE_NT_HEADERS((uintptr_t)dosHeader + dosHeader->e_lfanew);
		if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0
			|| ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size == 0)
			return true;

		auto importTable = PIMAGE_IMPORT_DESCRIPTOR((uintptr_t)ctx->imageBase +
			ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		for (; importTable->Name != NULL; importTable++)
		{
			// Load the dependent module
			auto dllName = PCHAR((uintptr_t)ctx->imageBase + importTable->Name);
			// Assuming kernel32.dll is at the same address, we can call some APIs before fixing IAT
			HMODULE module = LoadLibraryA(dllName);
			if (module == NULL)
				return false;
			
			PIMAGE_THUNK_DATA originalThunk;
			if (importTable->OriginalFirstThunk)
				originalThunk = PIMAGE_THUNK_DATA((uintptr_t)ctx->imageBase + importTable->OriginalFirstThunk);
			else
				originalThunk = PIMAGE_THUNK_DATA((uintptr_t)ctx->imageBase + importTable->FirstThunk);
			auto iatThunk = PIMAGE_THUNK_DATA((uintptr_t)ctx->imageBase + importTable->FirstThunk);
			for (; originalThunk->u1.AddressOfData != NULL; originalThunk++, iatThunk++)
			{
				FARPROC function;
				if (IMAGE_SNAP_BY_ORDINAL(originalThunk->u1.Ordinal))
					function = GetProcAddress(module, (LPCSTR)IMAGE_ORDINAL(originalThunk->u1.Ordinal));
				else
				{
					auto nameInfo = PIMAGE_IMPORT_BY_NAME((uintptr_t)ctx->imageBase + originalThunk->u1.AddressOfData);
					function = GetProcAddress(module, nameInfo->Name);
				}

				iatThunk->u1.Function = (uintptr_t)function;
			}
		}
		return true;
	}

	//bool RestoreGlobalVariables(InjectionContext* ctx)
	//{
	//	auto dosHeader = (PIMAGE_DOS_HEADER)ctx->imageBase;
	//	auto ntHeader = PIMAGE_NT_HEADERS((uintptr_t)dosHeader + dosHeader->e_lfanew);

	//	// Map the exe file into memory
	//	HANDLE file = CreateFile(&ctx->filePath.front(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	//	if (file == INVALID_HANDLE_VALUE)
	//		return false;
	//	HANDLE mapping = CreateFileMapping(file, NULL, PAGE_READONLY, 0, 0, NULL);
	//	if (mapping == NULL)
	//	{
	//		CloseHandle(file);
	//		return false;
	//	}
	//	LPVOID fileBuffer = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
	//	if (fileBuffer == NULL)
	//	{
	//		CloseHandle(mapping);
	//		CloseHandle(file);
	//		return false;
	//	}

	//	auto sectionHeader = PIMAGE_SECTION_HEADER((uintptr_t)ntHeader + sizeof(IMAGE_NT_HEADERS));
	//	int nSections = ntHeader->FileHeader.NumberOfSections;
	//	for (int i = 0; i < nSections; ++i)
	//	{
	//		if (sectionHeader[i].VirtualAddress == 0)
	//			continue;
	//		constexpr DWORD DATA_CHARACTERISTICS = IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_CNT_INITIALIZED_DATA;
	//		// This section stores initialized global variables
	//		if ((sectionHeader[i].Characteristics & DATA_CHARACTERISTICS) == DATA_CHARACTERISTICS)
	//		{
	//			memcpy((BYTE*)ctx->imageBase + sectionHeader[i].VirtualAddress,
	//				(BYTE*)fileBuffer + sectionHeader[i].PointerToRawData,
	//				sectionHeader[i].SizeOfRawData);
	//		}
	//	}

	//	UnmapViewOfFile(fileBuffer);
	//	CloseHandle(mapping);
	//	CloseHandle(file);
	//	return true;
	//}

	bool ExecuteTlsCallback(InjectionContext* ctx)
	{
		auto dosHeader = (PIMAGE_DOS_HEADER)ctx->imageBase;
		auto ntHeader = PIMAGE_NT_HEADERS((uintptr_t)dosHeader + dosHeader->e_lfanew);
		if (ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress == 0)
			return true;

		auto tls = PIMAGE_TLS_DIRECTORY((uintptr_t)ctx->imageBase +
			ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		for (auto callback = (PIMAGE_TLS_CALLBACK*)tls->AddressOfCallBacks; callback != NULL; callback++)
			(*callback)(ctx->imageBase, DLL_PROCESS_ATTACH, NULL);
		return true;
	}

	bool CallModuleEntry(InjectionContext* ctx)
	{
		auto dosHeader = (PIMAGE_DOS_HEADER)ctx->imageBase;
		auto ntHeader = PIMAGE_NT_HEADERS((uintptr_t)dosHeader + dosHeader->e_lfanew);

		auto crtStartup = (int(*)())((uintptr_t)ctx->imageBase + ntHeader->OptionalHeader.AddressOfEntryPoint);
		if (crtStartup == NULL)
			return false;
		crtStartup(); // This function should never return
		return true;
	}
}
