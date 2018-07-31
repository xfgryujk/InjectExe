// main.cpp: Main functions
//

#include "stdafx.h"
#include <array>
#include <sstream>
#include <string>

#include "InjectExe.h"

using namespace std;

int RemoteMain();


int main()
{
	if (IsInRemoteProcess())
	{
		int result = RemoteMain();
		// main() should never return, or the process will exit
		TerminateThread(GetCurrentThread(), result);
	}

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
	LPVOID remoteImageBase = InjectExe(process);
	if (remoteImageBase == NULL)
		return 1;
	cout << "remoteImageBase = 0x" << remoteImageBase << endl;
	return 0;
}

// Called in the target process after this exe is loaded
int RemoteMain()
{
	/*WCHAR processPath[MAX_PATH];
	GetModuleFileNameW(GetModuleHandle(NULL), processPath, MAX_PATH);
	wstringstream stream;
	stream << L"Hello world!\nI'm called from " << processPath;
	MessageBoxW(NULL, stream.str().c_str(), L"InjectExe", MB_OK);*/

	//WCHAR* processPath = new WCHAR[MAX_PATH];
	WCHAR* processPath = (WCHAR*)malloc(sizeof(WCHAR) * MAX_PATH);
	GetModuleFileNameW(GetModuleHandle(NULL), processPath, MAX_PATH);
	MessageBox(NULL, processPath, _T("InjectExe"), MB_OK);

	return 0;
}
