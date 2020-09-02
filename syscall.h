#pragma once
#include <Windows.h>
#include <functional>
#include <vector>
#include "nt_defs.h"

class TSyscall
{
	static void* pCodeLoc;
public:

	template<class T>
	static std::function<T> GetInvoke( const char* sFunction, T* pAddress = nullptr );
};

template<class T>
std::function<T> TSyscall::GetInvoke( const char* sFunction, T * pAddress )
{
	if ( !pCodeLoc )
	{
		pCodeLoc = VirtualAlloc( nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE );
#ifdef _WIN64
		BYTE cb[] = { 0x4C, 0x8B, 0xD1, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xC3 };
		auto size = ARRAYSIZE( cb );
		memcpy( pCodeLoc, cb, size);
#endif
	}

	auto pStub = (DWORD*) GetProcAddress( GetModuleHandle( "ntdll.dll" ), sFunction );
#ifdef _WIN64
	memcpy( (DWORD*) pCodeLoc + 1, pStub + 1, sizeof( DWORD ) );
#else
	memcpy( pCodeLoc, pStub, 15 );
#endif
	return std::function<T>( (T*) pCodeLoc );
}

#define _sc(t, s) TSyscall::GetInvoke(s, (t)nullptr)

#include "syscall_defs.h"