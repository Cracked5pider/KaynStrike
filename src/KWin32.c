#include <KaynStrike.h>
#include <KWin32.h>

#ifdef _WIN64
#define IMAGE_REL_TYPE IMAGE_REL_BASED_DIR64
#else
#define IMAGE_REL_TYPE IMAGE_REL_BASED_HIGHLOW
#endif

PVOID KLoadLibrary( PINSTANCE Instance, LPSTR ModuleName )
{
    if ( ! ModuleName )
        return NULL;

    UNICODE_STRING  UnicodeString           = { 0 };
    WCHAR           ModuleNameW[ MAX_PATH ] = { 0 };
    DWORD           dwModuleNameSize        = KStringLengthA( ModuleName );
    HMODULE         Module                  = NULL;

    KCharStringToWCharString( ModuleNameW, ModuleName, dwModuleNameSize );

    if ( ModuleNameW )
    {
        USHORT DestSize             = KStringLengthW( ModuleNameW ) * sizeof( WCHAR );
        UnicodeString.Length        = DestSize;
        UnicodeString.MaximumLength = DestSize + sizeof( WCHAR );
    }

    UnicodeString.Buffer = ModuleNameW;

    if ( NT_SUCCESS( Instance->Win32.LdrLoadDll( NULL, 0, &UnicodeString, &Module ) ) )
        return Module;
    else
        return NULL;
}

PVOID KGetModuleByHash( DWORD ModuleHash )
{
    PLDR_DATA_TABLE_ENTRY   LoaderEntry = NULL;
    PLIST_ENTRY             ModuleList  = NULL;
    PLIST_ENTRY             NextList    = NULL;

    /* Get pointer to list */
    ModuleList = & ( ( PPEB ) PPEB_PTR )->Ldr->InLoadOrderModuleList;
    NextList   = ModuleList->Flink;

    for ( ; ModuleList != NextList ; NextList = NextList->Flink )
    {
        LoaderEntry = NextList;

        if ( KHashString( LoaderEntry->BaseDllName.Buffer, LoaderEntry->BaseDllName.Length ) == ModuleHash )
            return LoaderEntry->DllBase;
    }

    return NULL;
}

PVOID KGetProcAddressByHash( PVOID DllModuleBase, DWORD FunctionHash )
{
    PIMAGE_NT_HEADERS       ModuleNtHeader          = NULL;
    PIMAGE_EXPORT_DIRECTORY ModuleExportedDirectory = NULL;
    PDWORD                  AddressOfFunctions      = NULL;
    PDWORD                  AddressOfNames          = NULL;
    PWORD                   AddressOfNameOrdinals   = NULL;

    ModuleNtHeader          = C_PTR( DllModuleBase + ( ( PIMAGE_DOS_HEADER ) DllModuleBase )->e_lfanew );
    ModuleExportedDirectory = C_PTR( DllModuleBase + ModuleNtHeader->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress );

    AddressOfNames          = C_PTR( DllModuleBase + ModuleExportedDirectory->AddressOfNames );
    AddressOfFunctions      = C_PTR( DllModuleBase + ModuleExportedDirectory->AddressOfFunctions );
    AddressOfNameOrdinals   = C_PTR( DllModuleBase + ModuleExportedDirectory->AddressOfNameOrdinals );

    for (DWORD i = 0; i < ModuleExportedDirectory->NumberOfNames; i++)
    {
        if ( KHashString( C_PTR( DllModuleBase + AddressOfNames[i] ), 0 ) == FunctionHash )
            return C_PTR( DllModuleBase + AddressOfFunctions[ AddressOfNameOrdinals[ i ] ] );
    }
}

VOID KResolveIAT( PINSTANCE Instance, PVOID KaynImage, PVOID IatDir )
{
    PIMAGE_THUNK_DATA        OriginalTD    = NULL;
    PIMAGE_THUNK_DATA        FirstTD       = NULL;

    PIMAGE_IMPORT_DESCRIPTOR ImpDescriptor = NULL;
    PIMAGE_IMPORT_BY_NAME    ImpByName     = NULL;

    PCHAR                    ModuleName    = NULL;
    HMODULE                  hModule       = NULL;
    PVOID                    Function      = 0;
    ANSI_STRING              AnsiString    = { 0 };

    for ( ImpDescriptor = IatDir; ImpDescriptor->Name != 0; ++ImpDescriptor )
    {
        ModuleName  = C_PTR( KaynImage + ImpDescriptor->Name );
        OriginalTD  = C_PTR( KaynImage + ImpDescriptor->OriginalFirstThunk );
        FirstTD     = C_PTR( KaynImage + ImpDescriptor->FirstThunk );

        hModule     = KLoadLibrary( Instance, ModuleName );

        for ( ; OriginalTD->u1.AddressOfData != 0 ; ++OriginalTD, ++FirstTD )
        {
            if ( IMAGE_SNAP_BY_ORDINAL( OriginalTD->u1.Ordinal ) )
            {
                if ( NT_SUCCESS( Instance->Win32.LdrGetProcedureAddress( hModule, NULL, IMAGE_ORDINAL( OriginalTD->u1.Ordinal ), &Function ) ) )
                    FirstTD->u1.Function = U_PTR( Function );
            }
            else
            {
                ImpByName = C_PTR( U_PTR( KaynImage ) + OriginalTD->u1.AddressOfData );

                // ANSI STRING
                {
                    AnsiString.Length        = KStringLengthA( ImpByName->Name );
                    AnsiString.MaximumLength = AnsiString.Length + sizeof( CHAR );
                    AnsiString.Buffer        = ImpByName->Name;
                }

                if ( NT_SUCCESS( Instance->Win32.LdrGetProcedureAddress( hModule, &AnsiString, 0, &Function ) ) )
                    FirstTD->u1.Function = U_PTR( Function );
            }
        }
    }
}

VOID KReAllocSections( PVOID KaynImage, PVOID ImageBase, PVOID BaseRelocDir )
{
    PIMAGE_BASE_RELOCATION  pImageBR = C_PTR( BaseRelocDir );
    LPVOID                  OffsetIB = C_PTR( U_PTR( KaynImage ) - U_PTR( ImageBase ) );
    PIMAGE_RELOC            Reloc    = NULL;

    while( pImageBR->VirtualAddress != 0 )
    {
        Reloc = ( PIMAGE_RELOC ) ( pImageBR + 1 );

        while ( ( PBYTE ) Reloc != ( PBYTE ) pImageBR + pImageBR->SizeOfBlock )
        {
            if ( Reloc->type == IMAGE_REL_TYPE )
                *( ULONG_PTR* ) ( U_PTR( KaynImage ) + pImageBR->VirtualAddress + Reloc->offset ) += ( ULONG_PTR ) OffsetIB;

            else if ( Reloc->type != IMAGE_REL_BASED_ABSOLUTE )
                __debugbreak(); // TODO: handle this error

            Reloc++;
        }

        pImageBR = ( PIMAGE_BASE_RELOCATION ) Reloc;
    }
}

DWORD KHashString( PVOID String, SIZE_T Length )
{
    ULONG	Hash = HASH_KEY;
    PUCHAR	Ptr  = String;

    do
    {
        UCHAR character = *Ptr;

        if ( ! Length )
        {
            if ( !*Ptr ) break;
        }
        else
        {
            if ( (ULONG) ( Ptr - (PUCHAR)String ) >= Length ) break;
            if ( !*Ptr ) ++Ptr;
        }

        if ( character >= 'a' )
            character -= 0x20;

        Hash = ( ( Hash << 5 ) + Hash ) + character;
        ++Ptr;
    } while ( TRUE );

    return Hash;
}

SIZE_T KStringLengthA( LPCSTR String )
{
    LPCSTR String2 = NULL;

    for (String2 = String; *String2; ++String2);

    return (String2 - String);
}

SIZE_T KStringLengthW(LPCWSTR String)
{
    LPCWSTR String2 = NULL;

    for ( String2 = String; *String2; ++String2 );

    return (String2 - String);
}

SIZE_T KCharStringToWCharString( PWCHAR Destination, PCHAR Source, SIZE_T MaximumAllowed )
{
    INT Length = MaximumAllowed;

    while (--Length >= 0)
    {
        if (!(*Destination++ = *Source++))
            return MaximumAllowed - Length - 1;
    }

    return MaximumAllowed - Length;
}