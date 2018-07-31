#pragma once

typedef void(__stdcall* RemoteCallbackType)();
LPVOID InjectExe(HANDLE process, RemoteCallbackType callback);
