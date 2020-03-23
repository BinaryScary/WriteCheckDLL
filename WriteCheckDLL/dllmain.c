#include <stdio.h>
#include <stdarg.h>
#include <windows.h>
#include <Aclapi.h>
#include <AuthZ.h>
#include <strsafe.h>
#include "Header.h"

#define STRSIZE 256

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
accessParms* initAccessParms() {
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

	(p->mapping).GenericRead = FILE_GENERIC_READ;
	(p->mapping).GenericWrite = FILE_GENERIC_WRITE;
	(p->mapping).GenericExecute = FILE_GENERIC_EXECUTE;
	(p->mapping).GenericAll = FILE_ALL_ACCESS;

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
int writeCheck(char* path) {
	PSECURITY_DESCRIPTOR pSD = NULL;
	PACL pDACL = NULL; 
	accessParms* p = initAccessParms();

	//char* dir = getDir(path);
	BOOL writable = FALSE;

	// check if dir/file is writable
	if (GetNamedSecurityInfoA(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION, NULL, NULL, &pDACL, NULL, &pSD) != ERROR_SUCCESS) {
		// cleanup pointers
		if (pSD != NULL) { LocalFree((HLOCAL)pSD); }
		//if (pDACL != NULL) { LocalFree((HLOCAL)pDACL); }
		return writable;
	}
	//printf("%d", IsValidSecurityDescriptor(pSD));

	// check if file is available to everyone, authorized users, or current user
	if (!AccessCheck(pSD, p->hImpersonatedToken, p->genericAccessRights, &(p->mapping), &(p->privileges), &(p->privilegesLength), &(p->grantedAccess), &writable)) {
		ErrorExit(TEXT("AccessCheck"));
	}

	// free descriptor and dacl
	if (pSD != NULL) { LocalFree((HLOCAL)pSD); }
	//if (pDACL != NULL) { LocalFree((HLOCAL)pDACL); }

	return writable;
}
