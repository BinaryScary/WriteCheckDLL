#include <stdio.h>
#include <stdarg.h>
#include <windows.h>
#include <Aclapi.h>
#include <AuthZ.h>
#include <strsafe.h>
#include "Header.h"

#define STRSIZE 256

// Use in C# proj: Add Existing Item 32/64.dll, (right-click on file in proj)->properties->Copy to Output Dir : Copy if newer

// Ref: https://docs.microsoft.com/en-us/windows/win32/debug/retrieving-the-last-error-code
void ErrorExit(LPTSTR lpszFunction) 
{ 
    // Retrieve the system error message for the last-error code

    LPVOID lpMsgBuf;
    LPVOID lpDisplayBuf;
    DWORD dw = GetLastError(); 

    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER | 
        FORMAT_MESSAGE_FROM_SYSTEM |
        FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        dw,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );

    // Display the error message and exit the process

    lpDisplayBuf = (LPVOID)LocalAlloc(LMEM_ZEROINIT, 
        (lstrlen((LPCTSTR)lpMsgBuf) + lstrlen((LPCTSTR)lpszFunction) + 40) * sizeof(TCHAR)); 
    StringCchPrintf((LPTSTR)lpDisplayBuf, 
        LocalSize(lpDisplayBuf) / sizeof(TCHAR),
        TEXT("%s failed with error %d: %s"), 
        lpszFunction, dw, lpMsgBuf); 
    MessageBox(NULL, (LPCTSTR)lpDisplayBuf, TEXT("Error"), MB_OK); 

    LocalFree(lpMsgBuf);
    LocalFree(lpDisplayBuf);
    ExitProcess(dw); 
}


// struct to simplify accessCheck function cuz only black magic can make it work
typedef struct accessParms {
	HANDLE hToken;
	HANDLE hImpersonatedToken;
	GENERIC_MAPPING mapping;
	PRIVILEGE_SET privileges;
	DWORD grantedAccess; 
	DWORD privilegesLength;
	DWORD genericAccessRights;
}accessParms;
accessParms* initAccessParms(SE_OBJECT_TYPE type) {
	accessParms* p = malloc(sizeof(accessParms));
	p->hToken = NULL;
	p->hImpersonatedToken = NULL;
	OpenProcessToken(GetCurrentProcess(), TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE | STANDARD_RIGHTS_READ, &(p->hToken));
	DuplicateToken(p->hToken, SecurityImpersonation, &(p->hImpersonatedToken));

	p->mapping = (GENERIC_MAPPING){ 0xFFFFFFFF };
	p->privileges = (PRIVILEGE_SET){ 0 };
	p->grantedAccess = 0;
	p->privilegesLength = sizeof( p->privileges );
	p->genericAccessRights = GENERIC_WRITE; // check for write access

	// Generic Mapping must match Security Object Type
	switch (type) {
	case SE_REGISTRY_KEY:
		// SE_REGISTRY_KEY
		(p->mapping).GenericRead = KEY_READ;
		(p->mapping).GenericWrite = KEY_WRITE;
		(p->mapping).GenericExecute = KEY_EXECUTE;
		(p->mapping).GenericAll = KEY_ALL_ACCESS;
		break;
	case SE_FILE_OBJECT:
		// SE_FIlE_OBJECT
		(p->mapping).GenericRead = FILE_GENERIC_READ;
		(p->mapping).GenericWrite = FILE_GENERIC_WRITE;
		(p->mapping).GenericExecute = FILE_GENERIC_EXECUTE;
		(p->mapping).GenericAll = FILE_ALL_ACCESS;
		break;
	default:
		// SE_FIlE_OBJECT
		(p->mapping).GenericRead = FILE_GENERIC_READ;
		(p->mapping).GenericWrite = FILE_GENERIC_WRITE;
		(p->mapping).GenericExecute = FILE_GENERIC_EXECUTE;
		(p->mapping).GenericAll = FILE_ALL_ACCESS;
		break;
	}

	MapGenericMask( &(p->genericAccessRights), &(p->mapping) );
	return p;
}
int freeAccessParms(accessParms* p) {
	CloseHandle(p->hImpersonatedToken);
	CloseHandle(p->hToken);
	free(p);
	return 0;
}

// create dir string from path, must free dir after
char* getDir(char* path) {
	char* dir = malloc(STRSIZE);
	if (dir == 0) { return NULL; }

	strcpy_s(dir, STRSIZE, path);

	char* p = strrchr(dir, '\\');
	if (p == 0) {
		free(dir);
		return NULL;
	}
	// delimit string
	*p = '\0';
	return dir;
}

// check write access on files and folders
// (Registry-Hive)Path: "CLASSES_ROOT", "CURRENT_USER", "MACHINE", and "USERS".
// type: SE_FILE_OBJECT = 1, SE_REGISTRY_KEY = 4
int pathWritableAC(char* path, SE_OBJECT_TYPE type) {
	PSECURITY_DESCRIPTOR pSD = NULL;
	PACL pDACL = NULL; 
	accessParms* p = initAccessParms(type);

	//char* dir = getDir(path);
	BOOL writable = FALSE;

	// check if dir/file is writable
	if (GetNamedSecurityInfoA(path, type, DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, NULL, NULL, &pDACL, NULL, &pSD) != ERROR_SUCCESS) {
		// cleanup pointers
		if (pSD != NULL) LocalFree((HLOCAL)pSD);
		//if (pDACL != NULL) LocalFree((HLOCAL)pDACL);
		if (p != NULL) freeAccessParms(p);

		return writable;
	}
	//printf("%d", IsValidSecurityDescriptor(pSD));

	// check if file is available to everyone, authorized users, or current user
	if (!AccessCheck(pSD, p->hImpersonatedToken, p->genericAccessRights, &(p->mapping), &(p->privileges), &(p->privilegesLength), &(p->grantedAccess), &writable)) {
		// cleanup pointers
		if (pSD != NULL) LocalFree((HLOCAL)pSD);
		//if (pDACL != NULL) LocalFree((HLOCAL)pDACL);
		if (p != NULL) freeAccessParms(p);

		ErrorExit(TEXT("AccessCheck"));
	}

	// free descriptor and dacl
	if (pSD != NULL) LocalFree((HLOCAL)pSD); 
	//if (pDACL != NULL) LocalFree((HLOCAL)pDACL);
	if (p != NULL) freeAccessParms(p);

	return writable;
}

