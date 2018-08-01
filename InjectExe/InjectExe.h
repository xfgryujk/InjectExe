#pragma once

typedef int(* RemoteCallbackType)();
LPVOID InjectExe(HANDLE process, RemoteCallbackType callback);
