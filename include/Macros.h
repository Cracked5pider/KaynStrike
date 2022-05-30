#ifndef KAYNSTRIKE_MACROS_H
#define KAYNSTRIKE_MACROS_H

#define HASH_KEY 5381

#ifdef _WIN64
#define PPEB_PTR __readgsqword( 0x60 )
#else
#define PPEB_PTR __readgsqword( 0x30 )
#endif

#define MemCopy                         __builtin_memcpy
#define NTDLL_HASH                      0x70e61753

// RtlCaptureContext
#define SYS_RTLCAPTURECONTEXT           0xeba8d910
#define SYS_RTLEXITUSERTHREAD           0x2f6db5e8

#define SYS_LDRLOADDLL                  0x9e456a43
#define SYS_LDRGETPROCEDUREADDRESS      0xfce76bb6
#define SYS_NTALLOCATEVIRTUALMEMORY     0xf783b8ec
#define SYS_NTPROTECTEDVIRTUALMEMORY    0x50e92888
#define SYS_NTFREEVIRTUALMEMORY         0x2802c609
#define SYS_NTCONTINUE                  0xfc3a6c2c
#define SYS_NTQUEUEAPCTHREAD            0xa6664b8
#define SYS_NTALERTTHREAD               0xd96aec97

#define DLLEXPORT                       __declspec( dllexport )
#define WIN32_FUNC( x )                 __typeof__( x ) * x;

#define U_PTR( x )                      ( ( UINT_PTR ) x )
#define C_PTR( x )                      ( ( LPVOID ) x )

#endif
