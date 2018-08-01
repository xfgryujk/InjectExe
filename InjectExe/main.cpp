// main.cpp: Main functions
//

#include "stdafx.h"
#include <array>
#include <sstream>

#include "Hook.h"
#include "InjectExe.h"

using namespace std;

int RemoteMain();
int WINAPI MyMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType);

unique_ptr<InlineHook> messageBoxWHook;


int main()
{
	// Inject into notepad
	HWND hwnd = FindWindow(_T("Notepad"), NULL);
	DWORD pid;
	GetWindowThreadProcessId(hwnd, &pid);
	HANDLE process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (process == NULL)
	{
		cerr << "Failed to open process: 0x" << hex << GetLastError() << oct << endl;
		return 1;
	}
	LPVOID remoteImageBase = InjectExe(process, RemoteMain);
	if (remoteImageBase == NULL)
		return 1;
	cout << "remoteImageBase = 0x" << remoteImageBase << endl;
	return 0;
}

// Called in the target process after this exe is loaded
int RemoteMain()
{
	// Test API
	MessageBox(NULL, _T("RemoteMain()"), _T("InjectExe"), MB_OK);

	// Test malloc()
	free(malloc(1));

	// Current program path
	array<WCHAR, MAX_PATH> processPath;
	GetModuleFileNameW(GetModuleHandle(NULL), &processPath.front(), MAX_PATH);
	wstringstream stream;
	stream << L"Hello world!\nI'm called from " << &processPath.front();
	MessageBoxW(NULL, stream.str().c_str(), L"InjectExe", MB_OK);

	// Test hook
	messageBoxWHook = make_unique<decltype(messageBoxWHook)::element_type>(MessageBoxW, MyMessageBoxW);
	MessageBoxW(NULL, L"blahblah", L"InjectExe", MB_OK);
	messageBoxWHook = nullptr;

	return 0;
}

int WINAPI MyMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)
{
	messageBoxWHook->Disable();
	int result = MessageBoxW(hWnd, _T("MessageBoxW is hooked!"), lpCaption, uType);
	messageBoxWHook->Enable();
	return result;
}
