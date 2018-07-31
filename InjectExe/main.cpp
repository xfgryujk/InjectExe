// main.cpp: Main functions
//

#include "stdafx.h"
#include <array>
#include <sstream>
#include <string>

#include "InjectExe.h"

using namespace std;

void __stdcall RemoteMain();


int main()
{
	// Inject into notepad
	HWND hwnd = FindWindow(_T("Notepad"), NULL);
	DWORD pid;
	GetWindowThreadProcessId(hwnd, &pid);
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (process == NULL)
	{
		cerr << "Failed to open process: " << GetLastError() << endl;
		return 1;
	}
	if (InjectExe(process, RemoteMain) == NULL)
		return 1;
	return 0;
}

// Called in the target process after this exe is loaded
void __stdcall RemoteMain()
{
	WCHAR processPath[MAX_PATH];
	GetModuleFileNameW(GetModuleHandle(NULL), processPath, MAX_PATH);
	wstringstream stream;
	stream << L"Hello world!\nI'm called from " << processPath;
	MessageBoxW(NULL, stream.str().c_str(), L"InjectExe", MB_OK);

	/*wstring processPath(MAX_PATH, L'\0');
	GetModuleFileNameW(GetModuleHandle(NULL), &processPath.front(), (DWORD)processPath.size());
	MessageBoxW(NULL, processPath.c_str(), L"InjectExe", MB_OK);*/

	/*array<TCHAR, MAX_PATH> processPath;
	GetModuleFileName(GetModuleHandle(NULL), &processPath.front(), (DWORD)processPath.size());
	MessageBox(NULL, &processPath.front(), _T("InjectExe"), MB_OK);*/
}
