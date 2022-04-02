#ifndef WOW64_HEAVENSGATE_H
#define WOW64_HEAVENSGATE_H

#if defined( _WIN64 )
#else

#pragma warning( disable : 4996 )

#include <Windows.h>

#define HEAVENSGATE_NOINLINE __declspec( noinline )
#define HEAVENSGATE_INLINE	 __forceinline

#define db( _VALUE_ ) __asm __emit ( 0x##_VALUE_ )

//
// Switch the CPU to x64 mode
//
#define ENTER_X64_MODE( )							\
db( 6A ) db( 33 )									\
db( E8 ) db( 00 ) db( 00 ) db( 00 ) db( 00 )		\
db( 83 ) db( 04 ) db( 24 ) db( 05 )					\
db( CB )											

//
// Switch the CPU to x86-32 mode
//
#define EXIT_X64_MODE( )												\
db( E8 ) db( 00 ) db( 00 ) db( 00 ) db( 00 )							\
db( C7 ) db( 44 ) db( 24 ) db( 04 ) db( 23 ) db( 00 ) db( 00 ) db( 00 ) \
db( 83 ) db( 04 ) db( 24 ) db( 0D )										\
db( CB )

#define X64_CALL_GET_ARG( _ARGS_, _NUMARGS_, _COUNTER_ ) \
( _COUNTER_ > _NUMARGS_ || _ARGS_ == NULL ) ? ( NULL ) : ( _ARGS_[ _COUNTER_++ ] )

/**
 * @brief Copy data from a 64-bit address to another region
 * @param [in] Destination: The destination to copy the data to
 * @param [in] Source: The source to copy the data from
 * @param [in] Len: The length in bytes to copy
*/
#define HgCopyMemory( _DEST_, _SRC_, _LEN_ ) \
X64_MEMCPY( ( DWORD64 )( _DEST_ ), ( DWORD64 )( _SRC_ ), ( DWORD64 )( _LEN_ ) )

#define HgZeroMemory( _DEST_, _LEN_ ) \
X64_MEMSET( ( DWORD64 )( _DEST_ ), NULL, ( DWORD64 )( _LEN_ ) )

/**
 * @brief Get the address to a function in a 64-bit loaded module
 * @param [in] ModuleHandle: The base address to the 64-bit loaded module
 * @param [in] FunctionName: The name of the function
 * @return The address of the function
*/
#define HgGetProcAddress( _MODULE_BASE_, _NAME_ ) \
X64_GETPROCADDRESS( ( DWORD64 )( _MODULE_BASE_ ), _NAME_ )

/**
 * @brief Get the base address to a 64-bit loaded module
 * @param [in] ModuleName: The name of the module
 * @return The base address of the loaded module
*/
#define HgGetModuleHandleA( _NAME_ ) \
X64_GETMODULEHANDLE( _NAME_ )

/**
 * @brief Get the imafe size of a 64-bit loaded module
 * @param [in] ModuleHandle: The base address of the loaded module
 * @return
*/
#define HgGetModuleSize( _BASE_ ) \
X64_GET_MODULE_SIZE( _BASE_ )

/**
 * @brief Obtain the 64-bit TEB structure
 * @param NONE
 * @return The 64-bit Address to the TEB
*/
#define HgGetTEB( ) \
X64_GETTEB( )

/**
 * @brief Scan for a byte pattern in a 64-bit region
 * @param [in] SearchBase: The address to start searching
 * @param [in] SearchRange: The amount in bytes to search
 * @param [in] Signature: The byte pattern
 * @param [in] SearchMask: The search mask ('x', '?', '*')
 * @param [in] MaxSubSearch: The maximum range in bytes to search when the ambiguous operator('*') is hit
 * @return The address where the byte pattern was found
*/
#define HgFindPattern( _BASE_, _RANGE_, _SIG_, _MASK_, _MAXSUB_ ) \
X64_SIG_SCAN( ( DWORD64 )( _BASE_ ), ( DWORD64 )( _RANGE_ ), ( PBYTE )( _SIG_ ), ( LPCSTR )( _MASK_ ), ( SIZE_T )( _MAXSUB_ ) )

/**
 * @brief Scan for a IDA-Style byte pattern in a 64-bit region
 * @param [in] SearchBase: The address to start searching
 * @param [in] SearchRange: The amount in bytes to search
 * @param [in] Signature: The byte pattern (Example: "48 8B ? ? ? ? ? FF * 90")
 * @param [in] MaxSubSearch: The maximum range in bytes to search when the ambiguous operator('*') is hit
 * @return The address where the byte pattern was found
*/
#define HgFindPatternA( _BASE_, _RANGE_, _SIG_, _MAXSUB_ ) \
X64_SIG_SCAN_A( ( DWORD64 )( _BASE_ ), ( DWORD64 )( _RANGE_ ), ( LPCSTR )( _SIG_ ), ( SIZE_T )( _MAXSUB_ ) )

/**
 * @brief Call VirtualProtect on a 64-bit memory address
 * @param [in] BaseAddress: The start address of the protection
 * @param [in] NumBytesToProtect: The amount in bytes to protect
 * @param [in] NewProtection: The new protection status
 * @param [out] OldProtection: The value to store the old protection status in
 * @return NTSTATUS
*/
#define HgProtectVirtualMemory( _BASE_, _RANGE_, _NEWPROT_, _OLDPROT_ ) \
X64_PROTECTVIRTUALMEMORY( ( DWORD64 )( _BASE_ ), ( DWORD64 )( _RANGE_ ), ( ULONG )( _NEWPROT_ ), ( PULONG )( _OLDPROT_ ) );

/**
 * @brief Obtain the 64-bit PEB structure
 * @param NONE
 * @return The address to the PEB structure
*/
#define HgGetPEB( ) \
X64_GETPEB( )

//
// For the 32-bit Instrumentation callback; the original EIP gets stored in ECX. Make sure this register is preserved in the handler
// and jump to it at the end of the handler, preferrably with all the other registers saved as well
//
/**
 * @brief Sets the instrumentation callback value in Wow64InformationPointers to the specified 32-bit function
 * @param [in] FunctionPointer: The pointer to the handler function
 * @return TRUE if the function succeeds
*/
#define HgSet32BitInstrumentationCallback( _FUNCTION_ ) \
WOW64_SETINSTRUMENTATIONCALLBACK( ( PVOID )( _FUNCTION_ ) )

#define GetNameFromPath( _STR_ ) \
strrchr( _STR_, '\\' ) ? ( CONST CHAR* )( strrchr( _STR_, '\\' ) + 1 ) : ( _STR_ )

typedef struct _UNICODE_STRING_64
{
	USHORT	Length;
	USHORT	MaximumLength;
	DWORD64 Buffer;
} UNICODE_STRING_64, *PUNICODE_STRING_64;

typedef struct _LIST_ENTRY_64
{
	DWORD64 Flink;                                            
	DWORD64 Blink;                                            
} LIST_ENTRY_64, *PLIST_ENTRY_64;

typedef struct _RTL_BALANCED_NODE_64
{
	DWORD64		Left;
	DWORD64		Right;
	ULONGLONG	ParentValue;
}RTL_BALANCED_NODE_64, *PRTL_BALANCED_NODE_64;

typedef struct _LDR_DATA_TABLE_ENTRY_64
{
	LIST_ENTRY_64			InLoadOrderLinks;
	LIST_ENTRY_64			InMemoryOrderLinks;
	LIST_ENTRY_64			InInitializationOrderLinks;
	DWORD64					DllBase;
	DWORD64					EntryPoint;
	ULONG					SizeOfImage;
	UNICODE_STRING_64		FullDllName;
	UNICODE_STRING_64		BaseDllName;
	ULONG					Flags;
	USHORT					ObsoleteLoadCount;                                         
	USHORT					TlsIndex;                                                  
	LIST_ENTRY_64			HashLinks;                                     
	ULONG					TimeDateStamp;                                              
	DWORD64					EntryPointActivationContext;          
	DWORD64					Lock;                                                       
	DWORD64					DdagNode;                                  
	LIST_ENTRY_64			NodeModuleLink;
	DWORD64					LoadContext;                           
	DWORD64					ParentDllBase;                                              
	DWORD64					SwitchBackContext;                                          
	RTL_BALANCED_NODE_64	BaseAddressIndexNode;                   
	RTL_BALANCED_NODE_64	MappingInfoIndexNode;                   
	ULONGLONG				OriginalBase;                                           
	LARGE_INTEGER			LoadTime;                                    
	ULONG					BaseNameHashValue;                                          
	ULONG					LoadReason;                             
	ULONG					ImplicitPathOptions;                                        
	ULONG					ReferenceCount;                                             
	ULONG					DependentLoadFlags;                                         
	UCHAR					SigningLevel;                                               
} LDR_DATA_TABLE_ENTRY_64, *PLDR_DATA_TABLE_ENTRY_64;

typedef struct _PEB_LDR_DATA_64
{
	ULONG		  Length;                                                 
	UCHAR		  Initialized;                                            
	DWORD64		  SsHandle;                                               
	LIST_ENTRY_64 InLoadOrderModuleList;									
	LIST_ENTRY_64 InMemoryOrderModuleList;									
	LIST_ENTRY_64 InInitializationOrderModuleList;							
	DWORD64		  EntryInProgress;                                        
	UCHAR		  ShutdownInProgress;                                     
	DWORD64		  ShutdownThreadId;                                       
} PEB_LDR_DATA_64, *PPEB_LDR_DATA_64;

/**
 * @brief String lengh no space
 * @param [in] String: The string to get the length for
 * @return The length of the string
*/
HEAVENSGATE_INLINE
SIZE_T
STRLEN_NS( 
	IN LPCSTR String 
	)
{
	LPCSTR Iterator = String;

	while ( *Iterator != NULL && *Iterator != '\x20' )
		Iterator++;

	return ( SIZE_T )( Iterator - String );
}

/**
 * @brief Hex representation ANSI to byte
 * @param [in] ARS: The string containing the ANSI(Example: "FF")
 * @return 
*/
HEAVENSGATE_INLINE
BYTE
__HRATOB( 
	IN LPCSTR ARS 
	)
{
	BYTE Result = NULL;

	SIZE_T ARSLen = STRLEN_NS( ARS );

	for ( SIZE_T i = NULL; i < ARSLen; i++ ) {

		CHAR Cur = ARS[ i ];

		Result += ( ( Cur >= '0' && Cur <= '9' ) ? ( Cur - '0' ) :
			( Cur >= 'a' && Cur <= 'f' ) ? ( Cur - 'a' + 0xA ) :
			( Cur >= 'A' && Cur <= 'F' ) ? ( Cur - 'A' + 0xA ) : NULL );

		Result <<= ( i == NULL && ARSLen > 1 ) ? ( 4 ) : NULL;
	}

	return Result;
}

HEAVENSGATE_NOINLINE
DWORD64
WINAPI
X64_GETTEB( 
	VOID 
	)
{
	DWORD64 RetValue = NULL;

	__asm
	{
		ENTER_X64_MODE( );

		//
		// mov eax, gs:[ 0x30 ]
		//
		db( 65 ) db( 48 ) db( 8B ) db( 04 ) db( 25 ) db( 30 ) db( 00 ) db( 00 ) db( 00 )

		push eax
		pop RetValue

		EXIT_X64_MODE( );
	}
}

HEAVENSGATE_NOINLINE
VOID
WINAPI
X64_MEMSET( 
	IN DWORD64 Destination, 
	IN DWORD64 Value, 
	IN DWORD64 Len 
	)
{
	__asm
	{
		push edi
		push esi

		ENTER_X64_MODE( );

		push Destination
		pop edi

		push Value
		pop eax

		push Len
		pop ecx

		rep stosb

		EXIT_X64_MODE( );

		pop edi
		pop esi
	}
}

HEAVENSGATE_NOINLINE
VOID
WINAPI
X64_MEMCPY( 
	IN DWORD64 Destination, 
	IN DWORD64 Source, 
	IN DWORD64 Len 
	)
{
	__asm
	{
		//
		// Save all non-volatile GPRs
		//
		push esi
		push edi

		ENTER_X64_MODE( );

		push Destination
		pop edi

		push Source
		pop esi

		push Len
		pop ecx

		rep movsb

		EXIT_X64_MODE( );

		//
		// Reset saved GPRs
		//
		pop edi
		pop esi
	}
}

HEAVENSGATE_NOINLINE
DWORD64
WINAPI
X64_GETPEB( 
	VOID 
	)
{
	DWORD64 RetValue = NULL;
	DWORD64 TEB		 = X64_GETTEB( );

	HgCopyMemory( &RetValue, TEB + 0x60, sizeof( DWORD64 ) );

	return RetValue;
}

HEAVENSGATE_NOINLINE
DWORD64
WINAPI
X64_GETMODULEHANDLE( 
	IN LPCSTR ModuleName 
	)
{
	DWORD64 Result	= NULL;
	DWORD64 PEB		= X64_GETPEB( );

	if ( PEB == NULL ) {
		return NULL;
	}

	DWORD64 LdrData = NULL;
	HgCopyMemory( &LdrData, PEB + 0x18, sizeof( DWORD64 ) );

	if ( LdrData == NULL ) {
		return NULL;
	}

	DWORD64		  HeadEntry = LdrData + FIELD_OFFSET( PEB_LDR_DATA_64, InLoadOrderModuleList );
	LIST_ENTRY_64 ListEntry;

	HgCopyMemory( &ListEntry, HeadEntry, sizeof( LIST_ENTRY_64 ) );

	if ( ListEntry.Flink == NULL ) {
		return NULL;
	}

	DWORD64 CurrentEntry = ListEntry.Flink;

	WCHAR WDllNameBuffer[ MAX_PATH + 1 ];
	CHAR  ADllNameBuffer[ MAX_PATH + 1 ];

	while ( CurrentEntry != HeadEntry )
	{
		LDR_DATA_TABLE_ENTRY_64 LdrEntry;
		HgCopyMemory( &LdrEntry, CurrentEntry - FIELD_OFFSET( LDR_DATA_TABLE_ENTRY_64, InLoadOrderLinks ), sizeof( LDR_DATA_TABLE_ENTRY_64 ) );

		RtlZeroMemory( WDllNameBuffer, sizeof( WDllNameBuffer ) );
		RtlZeroMemory( ADllNameBuffer, sizeof( ADllNameBuffer ) );

		HgCopyMemory( WDllNameBuffer, LdrEntry.BaseDllName.Buffer, LdrEntry.BaseDllName.Length );

		wcstombs( ADllNameBuffer, WDllNameBuffer, sizeof( WDllNameBuffer ) );

		if ( !strcmp( GetNameFromPath( ADllNameBuffer ), ModuleName ) ) {
			Result = LdrEntry.DllBase;
			break;
		}

		HgCopyMemory( &ListEntry, CurrentEntry, sizeof( LIST_ENTRY_64 ) );
		CurrentEntry = ListEntry.Flink;
	}

	return Result;
}

HEAVENSGATE_NOINLINE
DWORD64
WINAPI
X64_GETPROCADDRESS( 
	IN DWORD64	ModuleHandle, 
	IN LPCSTR	FunctionName 
	)
{
	IMAGE_DOS_HEADER ImageDosHeader;
	HgCopyMemory( &ImageDosHeader, ModuleHandle, sizeof( IMAGE_DOS_HEADER ) );

	if ( ImageDosHeader.e_magic != IMAGE_DOS_SIGNATURE ) {
		return NULL;
	}

	IMAGE_NT_HEADERS64 ImageNtHeaders;
	HgCopyMemory( &ImageNtHeaders, ModuleHandle + ImageDosHeader.e_lfanew, sizeof( IMAGE_NT_HEADERS64 ) );

	if ( ImageNtHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ) {
		return NULL;
	}

	DWORD  ExportVA	 = ImageNtHeaders.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].VirtualAddress;
	SIZE_T ExportLen = ImageNtHeaders.OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ].Size;

	if ( !ExportVA ) {
		return NULL;
	}

	IMAGE_EXPORT_DIRECTORY ExportDirectory;
	HgCopyMemory( &ExportDirectory, ModuleHandle + ExportVA, sizeof( IMAGE_EXPORT_DIRECTORY ) );

	CHAR lpszFunctionName[ MAX_PATH + 1 ];

	for ( SIZE_T i = NULL; i < ExportDirectory.NumberOfFunctions; i++ )
	{
		DWORD NameAddress = NULL;
		HgCopyMemory( &NameAddress, ModuleHandle + ExportDirectory.AddressOfNames + ( i * sizeof( DWORD ) ), sizeof( DWORD ) );

		if ( NameAddress == NULL ) {
			continue;
		}

		RtlZeroMemory( lpszFunctionName, sizeof( lpszFunctionName ) );
		HgCopyMemory( lpszFunctionName, ModuleHandle + NameAddress, strnlen_s( FunctionName, MAX_PATH ) );

		if ( !strcmp( lpszFunctionName, FunctionName ) )
		{
			USHORT Ordinal = NULL;
			HgCopyMemory( &Ordinal, ModuleHandle + ExportDirectory.AddressOfNameOrdinals + ( i * sizeof( USHORT ) ), sizeof( USHORT ) );

			DWORD FunctionAddress = NULL;
			HgCopyMemory( &FunctionAddress, ModuleHandle + ExportDirectory.AddressOfFunctions + ( Ordinal * sizeof( DWORD ) ), sizeof( DWORD ) );

			if ( FunctionAddress > ExportVA && FunctionAddress < ExportVA + ExportLen )
				return NULL;

			return ModuleHandle + FunctionAddress;
		}
	}

	return 0;
}

HEAVENSGATE_NOINLINE
DWORD64
WINAPI
X64_GET_MODULE_SIZE( 
	IN DWORD64 ModuleHandle 
	)
{
	IMAGE_DOS_HEADER ModuleDosHeader;
	HgCopyMemory( &ModuleDosHeader, ModuleHandle, sizeof( IMAGE_DOS_HEADER ) );

	if ( ModuleDosHeader.e_magic != IMAGE_DOS_SIGNATURE ) {
		return NULL;
	}

	IMAGE_NT_HEADERS64 ModuleNtHeaders;
	HgCopyMemory( &ModuleNtHeaders, ModuleHandle + ModuleDosHeader.e_lfanew, sizeof( IMAGE_NT_HEADERS64 ) );

	if ( ModuleNtHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ) {
		return NULL;
	}

	return ModuleNtHeaders.OptionalHeader.SizeOfImage;
}

HEAVENSGATE_NOINLINE
DWORD64
WINAPI
X64_SIG_SCAN( 
	IN DWORD64	SearchBase, 
	IN DWORD64	SearchRange, 
	IN PBYTE	Signature,
	IN LPCSTR	SearchMask,
	IN SIZE_T	MaxSubSearch
	)
{
	CONST SIZE_T SignatureLength = strnlen_s( SearchMask, 0x64 );
	CONST PBYTE	 SearchRegion	 = ( PBYTE )( malloc( SearchRange ) );

	PBYTE SearchIterator[ 2 ] = { SearchRegion, SearchRegion };

	if ( SearchRegion == NULL ) {
		return NULL;
	}

	RtlZeroMemory( SearchRegion, SearchRange );

	HgCopyMemory( SearchRegion, SearchBase, SearchRange );

	while ( SearchIterator[ 0 ] < ( SearchRegion + SearchRange ) )
	{
		BOOLEAN FullMatch = TRUE;

		for ( SIZE_T i = NULL; i < SignatureLength; i++ )
		{
			if ( SearchMask[ i ] == '*' ) 
			{
				while ( SearchIterator[ 1 ][ i + 1 ] != Signature[ i + 1 ] &&
						SearchIterator[ 1 ] - SearchIterator[ 0 ] < MaxSubSearch )
				{
					SearchIterator[ 1 ]++;
				}
			}

			if ( SearchMask[ i ] == '?' ) {
				continue;
			}

			if ( SearchMask[ i ] == 'x' && SearchIterator[ 1 ][ i ] != Signature[ i ] ) {
				FullMatch = FALSE;
				break;
			}
		}

		if ( FullMatch ) {
			free( SearchRegion );
			return SearchBase + ( DWORD64 )( SearchIterator[ 0 ] - SearchRegion );
		}

		SearchIterator[ 0 ]++;
		SearchIterator[ 1 ] = SearchIterator[ 0 ];
	}

	free( SearchRegion );
	return NULL;
}

HEAVENSGATE_NOINLINE
DWORD64
WINAPI
X64_SIG_SCAN_A( 
	IN DWORD64	SearchBase, 
	IN DWORD64	SearchRange, 
	IN LPCSTR	Signature, 
	IN SIZE_T	MaxSubSearch 
	)
{
	CONST SIZE_T SigStringLength = strnlen_s( Signature, 0x200 );

	BYTE RawSignature	[ 0x64 ];
	CHAR Mask			[ 0x64 ];

	SIZE_T RawSigLength = NULL;

	RtlZeroMemory( RawSignature, sizeof( RawSignature ) );
	RtlZeroMemory( Mask, sizeof( Mask ) );

	for ( SIZE_T i = NULL; i < SigStringLength; i++ )
	{
		if ( Signature[ i ] != '\x20' && Signature[ i ] != NULL )
		{
			BYTE Value = __HRATOB( &Signature[ i ] );

			if ( Value > 0xF || ( i + 1 < SigStringLength && Signature[ i + 1 ] != '\x20' ) ) {
				i++;
			}

			if ( Signature[ i ] == '?' || Signature[ i ] == '*' ) {
				RawSignature[ RawSigLength ] = NULL;
				Mask		[ RawSigLength ] = Signature[ i ];
			}
			else {
				RawSignature[ RawSigLength ] = Value;
				Mask		[ RawSigLength ] = 'x';
			}

			RawSigLength++;
		}
	}



	return X64_SIG_SCAN( SearchBase, SearchRange, RawSignature, Mask, MaxSubSearch );
}

HEAVENSGATE_NOINLINE
BOOLEAN
WINAPI
WOW64_SETINSTRUMENTATIONCALLBACK(
	IN PVOID FunctionPointer
)
{
	CONST DWORD64 Wow64Handle = HgGetModuleHandleA( "wow64.dll" );
	CONST SIZE_T  Wow64Size   = HgGetModuleSize( Wow64Handle );

	if ( Wow64Handle == NULL )
		return FALSE;

	DWORD64 pWow64InformationPointers = HgFindPatternA(
		Wow64Handle, Wow64Size, "48 8B 05 ? ? ? ? C7 00 00 10 00 00", NULL );

	if ( pWow64InformationPointers == NULL )
		return FALSE;

	DWORD64 Wow64InformationPointers = NULL;

	INT32 RelativeVirtual = NULL;
	HgCopyMemory( &RelativeVirtual, pWow64InformationPointers + 3, sizeof( INT32 ) );

	pWow64InformationPointers += ( RelativeVirtual + 7 );

	HgCopyMemory( &Wow64InformationPointers, pWow64InformationPointers, sizeof( DWORD64 ) );
	HgCopyMemory( Wow64InformationPointers + 8, &FunctionPointer, sizeof( PVOID ) );

	return TRUE;
}

/**
 * @brief Perform a direct 64-bit system call
 * @param [in] SyscallIndex: The sytem call ID
 * @param [in] Args: The arguments for the system call
 * @param [in] NumArgs: The number of arguments for the system call
 * @return The NTSTAUS of the system call
*/
HEAVENSGATE_NOINLINE
NTSTATUS
NTAPI
X64_SYSCALL( 
	IN DWORD	SyscallIndex, 
	IN PDWORD64 Args, 
	IN SIZE_T	NumArgs 
	)
{ 
	NTSTATUS	RetValue	= NULL;
	SIZE_T		ArgCounter	= NULL;

	//
	// rcx
	//
	DWORD64 x64_a1 = X64_CALL_GET_ARG( 
		Args, NumArgs, ArgCounter );

	//
	// rdx
	//
	DWORD64 x64_a2 = X64_CALL_GET_ARG(
		Args, NumArgs, ArgCounter );

	//
	// r8
	//
	DWORD64 x64_a3 = X64_CALL_GET_ARG(
		Args, NumArgs, ArgCounter );

	//
	// r9
	//
	DWORD64 x64_a4 = X64_CALL_GET_ARG(
		Args, NumArgs, ArgCounter );

	DWORD64	x64_stack_args		 = NULL;
	DWORD64	x64_stack_args_count = NULL;

	if ( NumArgs > 4 )
	{
		x64_stack_args_count = ( NumArgs - 4 );
		x64_stack_args		 = ( DWORD64 )( &Args[ 3 ] );
	}

	DWORD OldStack = NULL;

	__asm
	{
		//
		// Save all non-volatile GPRs
		//
		push esi
		push edi
		push ebx

		//
		// Align the stack to better suit 64-bit values
		//
		mov OldStack, esp
		and esp, 0xFFFFFFF0

		//
		// 64-bit (Long mode)
		//
		ENTER_X64_MODE( );
		{
			//
			// Set up the args for the x64 __fastcall calling convention
			//
			push x64_a1
			pop ecx

			push x64_a2
			pop edx

			push x64_a3
			db( 41 ) db( 58 ) //pop r8

			push x64_a4
			db( 41 ) db( 59 ) //pop r9
			
			//
			// Set up the loop for stack argument pushing
			//
			push x64_stack_args_count
			pop edi

			push x64_stack_args
			pop esi

			test edi, edi
			jz system_call

		push_args:
			push [ esi + 8 * edi ]
			sub edi, 1
			jnz push_args

		system_call:
			sub esp, 0x28
			
			//
			// Start the syscall
			//

			mov eax, SyscallIndex	
			db( 49 ) db( 89 ) db( CA ) //mov r10, rcx
			db( 0F ) db( 05 )		   //syscall

			//
			// Save the return value
			//
			mov RetValue, eax

			add esp, 0x28

			push x64_stack_args_count
			pop edi
			imul edi, 8

			add esp, edi
		}
		EXIT_X64_MODE( );

		mov esp, OldStack

		//
		// Reset saved GPRs
		//
		pop ebx
		pop edi
		pop esi
	}

	return RetValue;
}

/**
 * @brief Perform a direct 64-bit function call
 * @param [in] FunctionAddress: The address to the function you want to call 
 * @param [in] Args: The array containing the arguments for the function call
 * @param [in] NumArgs: The amount of arguments in the array
 * @return The return value of the function called
*/
HEAVENSGATE_NOINLINE
DWORD
WINAPI
X64_CALL( 
	IN DWORD64	FunctionAddress, 
	IN PDWORD64 Args, 
	IN SIZE_T	NumArgs 
	)
{
	DWORD		ReturnValue = NULL;
	SIZE_T		ArgCounter	= NULL;

	//
	// rcx
	//
	DWORD64 x64_a1 = X64_CALL_GET_ARG(
		Args, NumArgs, ArgCounter );

	//
	// rdx
	//
	DWORD64 x64_a2 = X64_CALL_GET_ARG(
		Args, NumArgs, ArgCounter );

	//
	// r8
	//
	DWORD64 x64_a3 = X64_CALL_GET_ARG(
		Args, NumArgs, ArgCounter );

	//
	// r9
	//
	DWORD64 x64_a4 = X64_CALL_GET_ARG(
		Args, NumArgs, ArgCounter );

	DWORD64 x64_stack_args		= NULL;
	DWORD64 x64_stack_arg_count = NULL;

	if ( NumArgs > 4 )
	{
		x64_stack_arg_count = ( NumArgs - 4 );
		x64_stack_args		= ( DWORD64 )( &Args[ 3 ] );
	}

	DWORD OldStack = NULL;

	__asm
	{
		//
		// Save non-volatile GPRs
		//
		push esi
		push edi
		push ebx

		//
		// Align the stack to better suit 64-bit values
		//
		mov OldStack, esp
		and esp, 0xFFFFFFF0

		ENTER_X64_MODE( );
		{
			//
			// Set up the __fastcall arguments
			//
			push x64_a1
			pop ecx

			push x64_a2
			pop edx

			push x64_a3
			db( 41 ) db( 58 )

			push x64_a4
			db( 41 ) db( 59 )

			//
			// Set up the loop for pushing the remaining arguments
			//
			push x64_stack_arg_count
			pop edi

			push x64_stack_args
			pop esi

			test edi, edi
			jz function_call

		push_args:
			push [ esi + 8 * edi ]
			sub edi, 1
			jnz push_args

		function_call:
			push FunctionAddress
			pop eax

			//
			// Reserve shadow space on the stack for rcx, rdx, r8 and r9 to spill
			//
			sub esp, 0x20

			call eax

			add esp, 0x20

			mov ReturnValue, eax

			push x64_stack_arg_count
			pop edi
			imul edi, 8
			
			add esp, edi
		}
		EXIT_X64_MODE( );

		mov esp, OldStack

		//
		// Reset saved GPRs
		//
		push ebx
		push edi
		push esi
	}
};

HEAVENSGATE_NOINLINE
NTSTATUS
NTAPI
X64_PROTECTVIRTUALMEMORY(
	IN	DWORD64 BaseAddress,
	IN	DWORD64 NumBytesToProtect,
	IN	ULONG	ProtectionStatus,
	OUT PULONG	OldProtectionStatus
	)
{
	DWORD64 Base	 = BaseAddress;
	DWORD64 NumBytes = NumBytesToProtect;

	DWORD64 Args[ 5 ] = {
		( DWORD64 )-1,
		( DWORD64 )&Base,
		( DWORD64 )&NumBytes,
		( DWORD64 )ProtectionStatus,
		( DWORD64 )OldProtectionStatus
	};

	return X64_SYSCALL( 0x50, Args, 5 );
}
#endif
#endif
