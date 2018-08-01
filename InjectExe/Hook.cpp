#include "stdafx.h"

#include "Hook.h"


InlineHook::InlineHook(void* _originalFunction, void* _hookFunction, bool enable) :
	originalFunction(_originalFunction),
	hookFunction(_hookFunction)
{
	memcpy(oldCode, originalFunction, sizeof(oldCode));

	if (enable)
		Enable();
}

InlineHook::~InlineHook()
{
	Disable();
}

void InlineHook::Enable()
{
	if (isEnabled)
		return;

	JmpCode code((uintptr_t)originalFunction, (uintptr_t)hookFunction);
	DWORD oldProtect, oldProtect2;
	VirtualProtect(originalFunction, sizeof(JmpCode), PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(originalFunction, &code, sizeof(JmpCode));
	VirtualProtect(originalFunction, sizeof(JmpCode), oldProtect, &oldProtect2);

	isEnabled = true;
}

void InlineHook::Disable()
{
	if (!isEnabled)
		return;

	DWORD oldProtect, oldProtect2;
	VirtualProtect(originalFunction, sizeof(JmpCode), PAGE_EXECUTE_READWRITE, &oldProtect);
	memcpy(originalFunction, oldCode, sizeof(JmpCode));
	VirtualProtect(originalFunction, sizeof(JmpCode), oldProtect, &oldProtect2);

	isEnabled = false;
}
