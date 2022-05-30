#ifndef KAYNSTRIKE_KAYNSTRIKE_H
#define KAYNSTRIKE_KAYNSTRIKE_H

#include <windows.h>
#include <Native.h>
#include <Macros.h>

#define DLL_QUERY_HMODULE   6

typedef struct {

    struct {
        WIN32_FUNC( RtlCaptureContext )
        WIN32_FUNC( RtlExitUserThread )

        WIN32_FUNC( LdrLoadDll );
        WIN32_FUNC( LdrGetProcedureAddress )

        WIN32_FUNC( NtAllocateVirtualMemory )
        WIN32_FUNC( NtProtectVirtualMemory )
        WIN32_FUNC( NtFreeVirtualMemory )
        WIN32_FUNC( NtContinue )
        WIN32_FUNC( NtResumeThread )

        NTSTATUS ( NTAPI* NtCreateThreadEx ) (
                PHANDLE     hThread,
                ACCESS_MASK DesiredAccess,
                PVOID       ObjectAttributes,
                HANDLE      ProcessHandle,
                PVOID       lpStartAddress,
                PVOID       lpParameter,
                ULONG       Flags,
                SIZE_T      StackZeroBits,
                SIZE_T      SizeOfStackCommit,
                SIZE_T      SizeOfStackReserve,
                PVOID       lpBytesBuffer
        );

        WIN32_FUNC( NtGetContextThread )
        WIN32_FUNC( NtSetContextThread )

        // Spoof thread start addr
        PVOID TpReleaseCleanupGroupMembers;

    } Win32;

    struct {
        PVOID   Ntdll;
    } Modules ;

} INSTANCE, *PINSTANCE ;

PVOID KaynCaller();
PVOID KRip();
PVOID KEnd();

#endif
