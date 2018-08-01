#pragma once

class InlineHook
{
private:
#pragma pack(push)
#pragma pack(1)
#ifndef _WIN64
	class JmpCode
	{
	private:
		const BYTE code = 0xE9;
		uintptr_t address = 0;

	public:
		JmpCode() = default;

		JmpCode(uintptr_t srcAddr, uintptr_t dstAddr)
		{
			SetAddress(srcAddr, dstAddr);
		}

		void SetAddress(uintptr_t srcAddr, uintptr_t dstAddr)
		{
			address = dstAddr - srcAddr - sizeof(JmpCode);
		}
	};
#else
	class JmpCode
	{
	private:
		const BYTE code[6] = { 0xFF, 0x25, 0x00, 0x00, 0x00, 0x00 };
		uintptr_t address = 0;

	public:
		JmpCode() = default;

		JmpCode(uintptr_t srcAddr, uintptr_t dstAddr)
		{
			SetAddress(srcAddr, dstAddr);
		}

		void SetAddress(uintptr_t srcAddr, uintptr_t dstAddr)
		{
			address = dstAddr;
		}
	};
#endif
#pragma pack(pop)

private:
	void* const originalFunction = nullptr;
	void* const hookFunction = nullptr;
	bool isEnabled = false;
	BYTE oldCode[sizeof(JmpCode)];

public:
	InlineHook(void* originalFunction, void* hookFunction, bool enable = true);
	~InlineHook();
	void Enable();
	void Disable();
};
