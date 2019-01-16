#include "stdafx.h"
#include "BootEncryption.h"
#include <Winternl.h>

OSVersionEnum nCurrentOS = WIN_UNKNOWN;
int CurrentOSMajor = 0;
int CurrentOSMinor = 0;
int CurrentOSServicePack = 0;
int CurrentOSBuildNumber = 0;

typedef HRESULT (WINAPI *SHGETKNOWNFOLDERPATH) (
  _In_     REFKNOWNFOLDERID rfid,
  _In_     DWORD            dwFlags,
  _In_opt_ HANDLE           hToken,
  _Out_    PWSTR            *ppszPath
);


/*
 * Use RtlGetVersion to get Windows version because GetVersionEx is affected by application manifestation.
 */
typedef NTSTATUS (WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

static BOOL GetWindowsVersion(LPOSVERSIONINFOW lpVersionInformation)
{
	BOOL bRet = FALSE;
	RtlGetVersionPtr RtlGetVersionFn = (RtlGetVersionPtr) GetProcAddress(GetModuleHandle (L"ntdll.dll"), "RtlGetVersion");
	if (RtlGetVersionFn != NULL)
	{
		if (ERROR_SUCCESS == RtlGetVersionFn (lpVersionInformation))
			bRet = TRUE;
	}

	if (!bRet)
		bRet = GetVersionExW (lpVersionInformation);

	return bRet;
}

BOOL InitOSVersionInfo ()
{
	OSVERSIONINFOEXW os;
	os.dwOSVersionInfoSize = sizeof (OSVERSIONINFOEXW);

	if (GetWindowsVersion ((LPOSVERSIONINFOW) &os) == FALSE)
		return FALSE;

	CurrentOSMajor = os.dwMajorVersion;
	CurrentOSMinor = os.dwMinorVersion;
	CurrentOSServicePack = os.wServicePackMajor;
	CurrentOSBuildNumber = os.dwBuildNumber;

	if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 5 && CurrentOSMinor == 0)
		nCurrentOS = WIN_2000;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 5 && CurrentOSMinor == 1)
		nCurrentOS = WIN_XP;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 5 && CurrentOSMinor == 2)
	{
		if (os.wProductType == VER_NT_SERVER || os.wProductType == VER_NT_DOMAIN_CONTROLLER)
			nCurrentOS = WIN_SERVER_2003;
		else
			nCurrentOS = WIN_XP64;
	}
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 6 && CurrentOSMinor == 0)
	{
		if (os.wProductType !=  VER_NT_WORKSTATION)
			nCurrentOS = WIN_SERVER_2008;
		else
			nCurrentOS = WIN_VISTA;
	}
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 6 && CurrentOSMinor == 1)
		nCurrentOS = ((os.wProductType !=  VER_NT_WORKSTATION) ? WIN_SERVER_2008_R2 : WIN_7);
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 6 && CurrentOSMinor == 2)
		nCurrentOS = ((os.wProductType !=  VER_NT_WORKSTATION) ? WIN_SERVER_2012 : WIN_8);
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 6 && CurrentOSMinor == 3)
		nCurrentOS = ((os.wProductType !=  VER_NT_WORKSTATION) ? WIN_SERVER_2012_R2 : WIN_8_1);
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 10 && CurrentOSMinor == 0)
		nCurrentOS = ((os.wProductType !=  VER_NT_WORKSTATION) ? WIN_SERVER_2016 : WIN_10);
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_NT && CurrentOSMajor == 4)
		nCurrentOS = WIN_NT4;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS && os.dwMajorVersion == 4 && os.dwMinorVersion == 0)
		nCurrentOS = WIN_95;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS && os.dwMajorVersion == 4 && os.dwMinorVersion == 10)
		nCurrentOS = WIN_98;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS && os.dwMajorVersion == 4 && os.dwMinorVersion == 90)
		nCurrentOS = WIN_ME;
	else if (os.dwPlatformId == VER_PLATFORM_WIN32s)
		nCurrentOS = WIN_31;
	else
		nCurrentOS = WIN_UNKNOWN;

	return TRUE;
}

BOOL IsOSVersionAtLeast (OSVersionEnum reqMinOS, int reqMinServicePack)
{
	/* When updating this function, update IsOSAtLeast() in Ntdriver.c too. */

	if (CurrentOSMajor <= 0)
		return FALSE;

	int major = 0, minor = 0;

	switch (reqMinOS)
	{
	case WIN_2000:			major = 5; minor = 0; break;
	case WIN_XP:			major = 5; minor = 1; break;
	case WIN_SERVER_2003:	major = 5; minor = 2; break;
	case WIN_VISTA:			major = 6; minor = 0; break;
	case WIN_7:				major = 6; minor = 1; break;
	case WIN_8:				major = 6; minor = 2; break;
	case WIN_8_1:			major = 6; minor = 3; break;
	case WIN_10:			major = 10; minor = 0; break;

	default:
		return FALSE;
		break;
	}

	return ((CurrentOSMajor << 16 | CurrentOSMinor << 8 | CurrentOSServicePack)
		>= (major << 16 | minor << 8 | reqMinServicePack));
}


BOOL Is64BitOs ()
{
#ifdef _WIN64
	return TRUE;
#else
    static BOOL isWow64 = FALSE;
	static BOOL valid = FALSE;
	typedef BOOL (__stdcall *LPFN_ISWOW64PROCESS ) (HANDLE hProcess,PBOOL Wow64Process);
	LPFN_ISWOW64PROCESS fnIsWow64Process;

	if (valid)
		return isWow64;

	fnIsWow64Process = (LPFN_ISWOW64PROCESS) GetProcAddress (GetModuleHandle(L"kernel32"), "IsWow64Process");

    if (fnIsWow64Process != NULL)
        if (!fnIsWow64Process (GetCurrentProcess(), &isWow64))
			isWow64 = FALSE;

	valid = TRUE;
    return isWow64;
#endif
}

// Returns TRUE if the file or directory exists (both may be enclosed in quotation marks).
BOOL FileExists (const wchar_t *filePathPtr)
{
	wchar_t filePath [TC_MAX_PATH * 2 + 1];

	// Strip quotation marks (if any)
	if (filePathPtr [0] == L'"')
	{
		StringCbCopyW (filePath, sizeof(filePath), filePathPtr + 1);
	}
	else
	{
		StringCbCopyW (filePath, sizeof(filePath), filePathPtr);
	}

	// Strip quotation marks (if any)
	if (filePath [wcslen (filePath) - 1] == L'"')
		filePath [wcslen (filePath) - 1] = 0;

    return (_waccess (filePath, 0) != -1);
}

void GetInstallationPath (HWND hwndDlg, wchar_t* szInstallPath, DWORD cchSize, BOOL* pbInstallPathDetermined)
{
	HKEY hkey;
	BOOL bInstallPathDetermined = FALSE;
	wchar_t path[MAX_PATH+20];
	ITEMIDLIST *itemList;

	memset (szInstallPath, 0, cchSize * sizeof (wchar_t));

	// Determine if VeraCrypt is already installed and try to determine its "Program Files" location
	if (RegOpenKeyEx (HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\VeraCrypt", 0, KEY_READ | KEY_WOW64_32KEY, &hkey) == ERROR_SUCCESS)
	{
		/* Default 'UninstallString' registry strings written by VeraCrypt:
		------------------------------------------------------------------------------------
		5.0+	"C:\Program Files\VeraCrypt\VeraCrypt Setup.exe" /u
		*/

		wchar_t rv[MAX_PATH*4];
		DWORD size = sizeof (rv);
		if (RegQueryValueEx (hkey, L"UninstallString", 0, 0, (LPBYTE) &rv, &size) == ERROR_SUCCESS && wcsrchr (rv, L'/'))
		{
			size_t len = 0;

			// Cut and paste the location (path) where VeraCrypt is installed to InstallationPath
			if (rv[0] == L'"')
			{
				len = wcsrchr (rv, L'/') - rv - 2;
				StringCchCopyNW (szInstallPath, cchSize, rv + 1, len);
				szInstallPath [len] = 0;
				bInstallPathDetermined = TRUE;

				if (szInstallPath [wcslen (szInstallPath) - 1] != L'\\')
				{
					len = wcsrchr (szInstallPath, L'\\') - szInstallPath;
					szInstallPath [len] = 0;
				}
			}

		}
		RegCloseKey (hkey);
	}

	if (!bInstallPathDetermined)
	{
		/* VeraCrypt is not installed or it wasn't possible to determine where it is installed. */

		// Default "Program Files" path.
		SHGetSpecialFolderLocation (hwndDlg, CSIDL_PROGRAM_FILES, &itemList);
		SHGetPathFromIDList (itemList, path);

		if (Is64BitOs())
		{
			// Use a unified default installation path (registry redirection of %ProgramFiles% does not work if the installation path is user-selectable)
			wstring s = path;
			size_t p = s.find (L" (x86)");
			if (p != wstring::npos)
			{
				s = s.substr (0, p);
				if (_waccess (s.c_str(), 0) != -1)
					StringCbCopyW (path, sizeof (path), s.c_str());
			}
		}

		StringCbCatW (path, sizeof(path), L"\\VeraCrypt\\");
		StringCbCopyW (szInstallPath, cchSize, path);
	}

	// Make sure the path ends with a backslash
	if (szInstallPath [wcslen (szInstallPath) - 1] != L'\\')
	{
		StringCbCatW (szInstallPath, cchSize, L"\\");
	}

	if (pbInstallPathDetermined)
		*pbInstallPathDetermined = bInstallPathDetermined;
}

BOOL GetSetupconfigLocation (wchar_t* path, DWORD cchSize)
{
	wchar_t szShell32Path[MAX_PATH] = {0};
	HMODULE hShell32 = NULL;
	BOOL bResult = FALSE;

	path[0] = 0;

	if (GetSystemDirectory(szShell32Path, MAX_PATH))
		StringCchCatW (szShell32Path, MAX_PATH, L"\\Shell32.dll");
	else
		StringCchCopyW (szShell32Path, MAX_PATH, L"C:\\Windows\\System32\\Shell32.dll");

	hShell32 = LoadLibrary (szShell32Path);
	if (hShell32)
	{
		SHGETKNOWNFOLDERPATH SHGetKnownFolderPathFn = (SHGETKNOWNFOLDERPATH) GetProcAddress (hShell32, "SHGetKnownFolderPath");
		if (SHGetKnownFolderPathFn)
		{
			wchar_t* pszUsersPath = NULL;
			if (S_OK == SHGetKnownFolderPathFn (FOLDERID_UserProfiles, 0, NULL, &pszUsersPath))
			{
				StringCchPrintfW (path, cchSize, L"%s\\Default\\AppData\\Local\\Microsoft\\Windows\\WSUS\\", pszUsersPath);
				CoTaskMemFree (pszUsersPath);
				bResult = TRUE;
			}
		}
		FreeLibrary (hShell32);
	}

	if (!bResult && CurrentOSMajor >= 10)
	{
		StringCchPrintfW (path, cchSize, L"%c:\\Users\\Default\\AppData\\Local\\Microsoft\\Windows\\WSUS\\", szShell32Path[0]);					
		bResult = TRUE;
	}

	return bResult;
}

wchar_t *GetProgramConfigPath (wchar_t *fileName)
{
	static wchar_t path[MAX_PATH * 2] = { 0 };

	if (SUCCEEDED (SHGetFolderPath (NULL, CSIDL_COMMON_APPDATA | CSIDL_FLAG_CREATE, NULL, 0, path)))
	{
		StringCchCatW (path, (MAX_PATH * 2), L"\\VeraCrypt\\");
		CreateDirectory (path, NULL);
		StringCchCatW (path, (MAX_PATH * 2), fileName);
	}
	else
		path[0] = 0;

	return path;
}


BOOL BufferHasPattern (const unsigned char* buffer, size_t bufferLen, const void* pattern, size_t patternLen)
{
	BOOL bRet = FALSE;
	if (patternLen <= bufferLen)
	{
		size_t i;
		for (i = 0; i <= (bufferLen - patternLen); ++i)
		{
			if (memcmp (&buffer[i], pattern, patternLen) == 0)
			{
				bRet = TRUE;
				break;
			}
		}
	}

	return bRet;
}


File::File (wstring path, bool readOnly, bool create) : FileOpen (false), ReadOnly (readOnly), LastError(0)
{
	Handle = CreateFile (path.c_str(),
		readOnly ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, create ? CREATE_ALWAYS : OPEN_EXISTING,
		FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_WRITE_THROUGH, NULL);

	if (Handle != INVALID_HANDLE_VALUE)
	{
		FileOpen = true;
	}

	FilePointerPosition = 0;
	IsDevice = false;
	Path = path;
}

void File::Close ()
{
	if (Handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle (Handle);
		Handle = INVALID_HANDLE_VALUE;
	}

	FileOpen = false;
}

DWORD File::Read (byte *buffer, DWORD size)
{
	DWORD bytesRead;

	if (!FileOpen)
	{
		return -1;
	}

	if (!ReadFile (Handle, buffer, size, &bytesRead, NULL))
	{
		DWORD dwLastError = GetLastError();
		if ((dwLastError == ERROR_INVALID_PARAMETER) && IsDevice && (size % 4096))
		{					
			DWORD remainingSize = (size % 4096);
			DWORD alignedSize = size - remainingSize;
			LARGE_INTEGER offset;

			if (alignedSize)
			{
				if (ReadFile (Handle, buffer, alignedSize, &bytesRead, NULL))
				{
					if (bytesRead < alignedSize)
						return bytesRead;

					buffer += alignedSize;
					size -= alignedSize;
				}
				else
					return -1;
			}


			if (ReadFile (Handle, ReadBuffer, 4096, &bytesRead, NULL))
			{
				DWORD effectiveSize = min (bytesRead, remainingSize);					
				memcpy (buffer, ReadBuffer, effectiveSize);
				offset.QuadPart = - ((LONGLONG) bytesRead) + (LONGLONG) effectiveSize;
				if (!SetFilePointerEx (Handle, offset, NULL, FILE_CURRENT))
					return -1;
				return alignedSize + effectiveSize;
			}
			else
				return -1;
		}
		else
			return -1;
	}

	return bytesRead;
}

bool File::GetFileSize (unsigned __int64& size)
{
	if (!FileOpen)
	{
		return false;
	}

	LARGE_INTEGER lSize;
	lSize.QuadPart = 0;
	if (!GetFileSizeEx (Handle, &lSize))
		return false;
	size = (unsigned __int64) lSize.QuadPart;
	return true;
}

bool File::GetFileSize (DWORD& dwSize)
{
	unsigned __int64 size64;
	if (GetFileSize (size64))
	{
		dwSize = (DWORD) size64;
		return true;
	}
	else
		return false;
}

bool File::Write (byte *buffer, DWORD size)
{
	DWORD bytesWritten;

	if (!FileOpen)
	{
		return false;
	}

	if (!WriteFile (Handle, buffer, size, &bytesWritten, NULL))
	{
		DWORD dwLastError = GetLastError ();
		if ((ERROR_INVALID_PARAMETER == dwLastError) && IsDevice && !ReadOnly && (size % 4096))
		{
			bool bSuccess = false;						
			DWORD remainingSize = (size % 4096);
			DWORD alignedSize = size - remainingSize;
			DWORD bytesRead = 0;
			bytesWritten = 0;
			if (alignedSize)
			{
				if (WriteFile (Handle, buffer, alignedSize, &bytesWritten, NULL))
				{
					if (bytesWritten != alignedSize)
						return false;
					buffer += alignedSize;
					size -= alignedSize;
				}
				else
				{
					bytesWritten = 0;
					dwLastError = GetLastError ();
				}
			}

			if (!alignedSize || (alignedSize && bytesWritten))
			{
				LARGE_INTEGER offset;

				if (!ReadFile (Handle, ReadBuffer, 4096, &bytesRead, NULL) || (bytesRead != 4096))
					return false;
				offset.QuadPart = -4096;
				if (!SetFilePointerEx (Handle, offset, NULL, FILE_CURRENT))
					return false;

				memcpy (ReadBuffer, buffer, remainingSize);

				if (WriteFile (Handle, ReadBuffer, 4096, &bytesWritten, NULL))
				{
					if (bytesWritten != 4096)
						return false;
					bSuccess = true;
				}
				else
				{
					dwLastError = GetLastError ();
				}
			}

			if (!bSuccess)
			{
				return false;
			}
		}
		else
			return false;
	}
	else
	{
		if (bytesWritten != size)
			return false;
	}

	return true;
}

bool File::IoCtl(DWORD code, void* inBuf, DWORD inBufSize, void* outBuf, DWORD outBufSize)
{
	if (!FileOpen)
	{
		return false;
	}

	DWORD bytesReturned = 0;
	return TRUE == DeviceIoControl(Handle, code, inBuf, inBufSize, outBuf, outBufSize, &bytesReturned, NULL);
}


Device::Device (wstring path, bool readOnly)
{
	wstring effectivePath;
	FileOpen = false;

	if (path.find(L"\\\\?\\") == 0)
		effectivePath = path;
	else
		effectivePath = wstring (L"\\\\.\\") + path;

	Handle = CreateFile (effectivePath.c_str(),
		readOnly ? GENERIC_READ : GENERIC_READ | GENERIC_WRITE,
		FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
		FILE_FLAG_RANDOM_ACCESS | FILE_FLAG_WRITE_THROUGH, NULL);

	if (Handle != INVALID_HANDLE_VALUE)
	{
		FileOpen = true;
	}

	FilePointerPosition = 0;
	IsDevice = true;
	Path = path;
	ReadOnly = readOnly;
}

EfiBoot::EfiBoot() {
	ZeroMemory (&sdn, sizeof (sdn));
	ZeroMemory (&partInfo, sizeof (partInfo));
	m_bMounted = false;
	bBootVolumePathSelected = false;
}

#define SYSPARTITIONINFORMATION 0x62

typedef NTSTATUS (WINAPI *NtQuerySystemInformationFn)(
		SYSTEM_INFORMATION_CLASS SystemInformationClass,
		PVOID                    SystemInformation,
      ULONG                    SystemInformationLength,
		PULONG                   ReturnLength
);

NtQuerySystemInformationFn NtQuerySystemInformationPtr = NULL;

bool EfiBoot::SelectBootVolumeESP() {
	NTSTATUS res;
	ULONG    len;
	memset(tempBuf, 0, sizeof(tempBuf));

	// Load NtQuerySystemInformation function point
	if (!NtQuerySystemInformationPtr)
	{
		NtQuerySystemInformationPtr = (NtQuerySystemInformationFn) GetProcAddress (GetModuleHandle (L"ntdll.dll"), "NtQuerySystemInformation");
		if (!NtQuerySystemInformationPtr)
			return false;
	}

	res = NtQuerySystemInformationPtr((SYSTEM_INFORMATION_CLASS)SYSPARTITIONINFORMATION, tempBuf, sizeof(tempBuf), &len);
	if (res != S_OK)
	{
		SetLastError (res);
		return false;
	}		

	PUNICODE_STRING pStr = (PUNICODE_STRING) tempBuf;
	BootVolumePath = pStr->Buffer;

	EfiBootPartPath = L"\\\\?";
	EfiBootPartPath += &pStr->Buffer[7];

	bBootVolumePathSelected = true;

	return true;
}

bool EfiBoot::PrepareBootPartition() {
	if (!bBootVolumePathSelected) {
		if (!SelectBootVolumeESP())
			return false;
	}
	std::wstring devicePath = L"\\\\?\\GLOBALROOT";
	devicePath += BootVolumePath;
	Device  dev(devicePath.c_str(), TRUE);

	if (!dev.IsOpened())
		return false;
		
	bool bSuccess = dev.IoCtl(IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0, &sdn, sizeof(sdn))
						&& dev.IoCtl(IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &partInfo, sizeof(partInfo));
	DWORD dwLastError = GetLastError ();
	dev.Close();
	if (!bSuccess)
	{
		SetLastError (dwLastError);
		return false;
	}

	return true;
}

static const wchar_t*	EfiVarGuid = L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";

bool EfiBoot::IsEfiBoot() {
	DWORD BootOrderLen;
	BootOrderLen = GetFirmwareEnvironmentVariable(L"BootOrder", EfiVarGuid, tempBuf, sizeof(tempBuf));
	return BootOrderLen != 0;
}

bool EfiBoot::DeleteStartExec(uint16 statrtOrderNum, wchar_t* type) {
	// Check EFI
	if (!IsEfiBoot()) {
		return false;
	}
	wchar_t	varName[256];
	StringCchPrintfW(varName, ARRAYSIZE (varName), L"%s%04X", type == NULL ? L"Boot" : type, statrtOrderNum);
	SetFirmwareEnvironmentVariable(varName, EfiVarGuid, NULL, 0);

	wstring order = L"Order";
	order.insert(0, type == NULL ? L"Boot" : type);
	uint32 startOrderLen = GetFirmwareEnvironmentVariable(order.c_str(), EfiVarGuid, tempBuf, sizeof(tempBuf));
	uint32 startOrderNumPos = UINT_MAX;
	bool	startOrderUpdate = false;
	uint16*	startOrder = (uint16*)tempBuf;
	for (uint32 i = 0; i < startOrderLen / 2; i++) {
		if (startOrder[i] == statrtOrderNum) {
			startOrderNumPos = i;
			break;
		}
	}

	// delete entry if present
	if (startOrderNumPos != UINT_MAX) {
		for (uint32 i = startOrderNumPos; i < ((startOrderLen / 2) - 1); ++i) {
			startOrder[i] = startOrder[i + 1];
		}
		startOrderLen -= 2;
		startOrderUpdate = true;
	}

	if (startOrderUpdate) {
		SetFirmwareEnvironmentVariable(order.c_str(), EfiVarGuid, startOrder, startOrderLen);

		// remove ourselves from BootNext value
		uint16 bootNextValue = 0;
		wstring next = L"Next";
		next.insert(0, type == NULL ? L"Boot" : type);

		if (	(GetFirmwareEnvironmentVariable(next.c_str(), EfiVarGuid, &bootNextValue, 2) == 2)
			&&	(bootNextValue == statrtOrderNum)
			)
		{
			SetFirmwareEnvironmentVariable(next.c_str(), EfiVarGuid, startOrder, 0);
		}
	}

	return true;
}

bool EfiBoot::SetStartExec(wstring description, wstring execPath, uint16 statrtOrderNum , wchar_t* type, uint32 attr) {

	// Check EFI
	if (!IsEfiBoot()) {
		return false;
	}
		
	uint32 varSize = 56;
	varSize += ((uint32) description.length()) * 2 + 2;
	varSize += ((uint32) execPath.length()) * 2 + 2;
	byte *startVar = new byte[varSize];
	byte *pVar = startVar;

	// Attributes (1b Active, 1000b - Hidden)
	*(uint32 *)pVar = attr;
	pVar += sizeof(uint32);

	// Size Of device path + file path
	*(uint16 *)pVar = (uint16)(50 + execPath.length() * 2 + 2);
	pVar += sizeof(uint16);

	// description
	for (uint32 i = 0; i < description.length(); i++) {
		*(uint16 *)pVar = description[i];
		pVar += sizeof(uint16);
	}
	*(uint16 *)pVar = 0;
	pVar += sizeof(uint16);

	/* EFI_DEVICE_PATH_PROTOCOL (HARDDRIVE_DEVICE_PATH \ FILE_PATH \ END) */

	// Type
	*(byte *)pVar = 0x04;
	pVar += sizeof(byte);

	// SubType
	*(byte *)pVar = 0x01;
	pVar += sizeof(byte);

	// HDD dev path length
	*(uint16 *)pVar = 0x2A; // 42
	pVar += sizeof(uint16);
		
	// PartitionNumber
	*(uint32 *)pVar = (uint32)partInfo.PartitionNumber;
	pVar += sizeof(uint32);

	// PartitionStart
	*(uint64 *)pVar = partInfo.StartingOffset.QuadPart >> 9;
	pVar += sizeof(uint64);

	// PartitiontSize
	*(uint64 *)pVar = partInfo.PartitionLength.QuadPart >> 9;
	pVar += sizeof(uint64);

	// GptGuid
	memcpy(pVar, &partInfo.Gpt.PartitionId, 16);
	pVar += 16;

	// MbrType
	*(byte *)pVar = 0x02;
	pVar += sizeof(byte);

	// SigType
	*(byte *)pVar = 0x02;
	pVar += sizeof(byte);

	// Type and sub type 04 04 (file path)
	*(uint16 *)pVar = 0x0404;
	pVar += sizeof(uint16);

	// SizeOfFilePath ((CHAR16)FullPath.length + sizeof(EndOfrecord marker) )
	*(uint16 *)pVar = (uint16)(execPath.length() * 2 + 2 + sizeof(uint32));
	pVar += sizeof(uint16);

	// FilePath
	for (uint32 i = 0; i < execPath.length(); i++) {
		*(uint16 *)pVar = execPath[i];
		pVar += sizeof(uint16);
	}
	*(uint16 *)pVar = 0;
	pVar += sizeof(uint16);

	// EndOfrecord
	*(uint32 *)pVar = 0x04ff7f;
	pVar += sizeof(uint32);

	// Set variable
	wchar_t	varName[256];
	StringCchPrintfW(varName, ARRAYSIZE (varName), L"%s%04X", type == NULL ? L"Boot" : type, statrtOrderNum);
	SetFirmwareEnvironmentVariable(varName, EfiVarGuid, startVar, varSize);
	delete [] startVar;

	// Update order
	wstring order = L"Order";
	order.insert(0, type == NULL ? L"Boot" : type);

	uint32 startOrderLen = GetFirmwareEnvironmentVariable(order.c_str(), EfiVarGuid, tempBuf, sizeof(tempBuf));
	uint32 startOrderNumPos = UINT_MAX;
	bool	startOrderUpdate = false;
	uint16*	startOrder = (uint16*)tempBuf;
	for (uint32 i = 0; i < startOrderLen / 2; i++) {
		if (startOrder[i] == statrtOrderNum) {
			startOrderNumPos = i;
			break;
		}
	}

	// Create new entry if absent
	if (startOrderNumPos == UINT_MAX) {
		for (uint32 i = startOrderLen / 2; i > 0; --i) {
			startOrder[i] = startOrder[i - 1];
		}
		startOrder[0] = statrtOrderNum;
		startOrderLen += 2;
		startOrderUpdate = true;
	} else if (startOrderNumPos > 0) {
		for (uint32 i = startOrderNumPos; i > 0; --i) {
			startOrder[i] = startOrder[i - 1];
		}
		startOrder[0] = statrtOrderNum;
		startOrderUpdate = true;
	}

	if (startOrderUpdate) {
		SetFirmwareEnvironmentVariable(order.c_str(), EfiVarGuid, startOrder, startOrderLen);
	}

	// set BootNext value
	wstring next = L"Next";
	next.insert(0, type == NULL ? L"Boot" : type);

	SetFirmwareEnvironmentVariable(next.c_str(), EfiVarGuid, &statrtOrderNum, 2);

	return true;
}

bool EfiBoot::SaveFile(const wchar_t* name, byte* data, DWORD size) {
	bool bRet;
	wstring path = EfiBootPartPath;
	path += name;

	File f(path, false, true);
	bRet = f.Write(data, size);
	f.Close();
	return bRet;
}

bool EfiBoot::FileExists(const wchar_t* name) {
	wstring path = EfiBootPartPath;
	path += name;
	File f(path, true);
	bool bRet = f.IsOpened ();
	f.Close();
	return bRet;
}

bool EfiBoot::GetFileSize(const wchar_t* name, unsigned __int64& size) {
	wstring path = EfiBootPartPath;
	path += name;
	File f(path, true);
	bool bret = f.GetFileSize(size);
	f.Close();
	return bret;
}

bool EfiBoot::ReadFile(const wchar_t* name, byte* data, DWORD size) {
	wstring path = EfiBootPartPath;
	path += name;
	File f(path, true);
	bool bRet;
	if (f.Read(data, size) == (DWORD) -1)
		bRet = false;
	else
		bRet = true;
	f.Close();
	return bRet;
}

bool EfiBoot::CopyFile(const wchar_t* name, const wchar_t* targetName) {
	wstring path = EfiBootPartPath;
	path += name;
	wstring targetPath;
	if (targetName[0] == L'\\')
	{
		targetPath = EfiBootPartPath;
		targetPath += targetName;
	}
	else
		targetPath = targetName;
	if (!::CopyFileW (path.c_str(), targetPath.c_str(), FALSE))
		return false;
	else
		return true;
}

BOOL EfiBoot::RenameFile(const wchar_t* name, const wchar_t* nameNew, BOOL bForce) {
	wstring path = EfiBootPartPath;
	path += name;
	wstring pathNew = EfiBootPartPath;
	pathNew += nameNew;
	return MoveFileExW(path.c_str(), pathNew.c_str(), bForce? MOVEFILE_REPLACE_EXISTING : 0);
}

BOOL EfiBoot::DelFile(const wchar_t* name) {
	wstring path = EfiBootPartPath;
	path += name;
	return DeleteFile(path.c_str());
}


void UpdateSetupConfigFile (bool bForInstall)
{
	// starting from Windows 10 1607 (Build 14393), ReflectDrivers in Setupconfig.ini is supported
	if (IsOSVersionAtLeast (WIN_10, 0) && CurrentOSBuildNumber >= 14393)
	{
		wchar_t szInstallPath [MAX_PATH];
		wchar_t szSetupconfigLocation [MAX_PATH + 20];

		if (bForInstall)
		{
			GetInstallationPath (NULL, szInstallPath, ARRAYSIZE (szInstallPath), NULL);
			// remove ending backslash
			if (szInstallPath [wcslen (szInstallPath) - 1] == L'\\')
			{
				szInstallPath [wcslen (szInstallPath) - 1] = 0;
			}
		}
		if (GetSetupconfigLocation (szSetupconfigLocation, ARRAYSIZE (szSetupconfigLocation)))
		{
			if (bForInstall)
				::CreateDirectoryW (szSetupconfigLocation, NULL);

			StringCchCatW (szSetupconfigLocation, ARRAYSIZE (szSetupconfigLocation), L"SetupConfig.ini");

			if (bForInstall)
			{
				wstring szPathParam = L"\"";
				szPathParam += szInstallPath;
				szPathParam += L"\"";
				WritePrivateProfileStringW (L"SetupConfig", L"ReflectDrivers", szPathParam.c_str(), szSetupconfigLocation);

				szPathParam = GetProgramConfigPath (L"SetupComplete.cmd");
				FILE* scriptFile = _wfopen (szPathParam.c_str(), L"w");
				if (scriptFile)
				{
					fwprintf (scriptFile, L"\"%s\\VeraCrypt.exe\" /PostOOBE\n", szInstallPath);
					fclose (scriptFile);

					WritePrivateProfileStringW (L"SetupConfig", L"PostOOBE", szPathParam.c_str(), szSetupconfigLocation);
				}
			}
			else
			{
				if (FileExists (szSetupconfigLocation))
				{
					WritePrivateProfileStringW (L"SetupConfig", L"ReflectDrivers", NULL, szSetupconfigLocation);
					WritePrivateProfileStringW (L"SetupConfig", L"PostOOBE", NULL, szSetupconfigLocation);
				}

				wstring scriptFilePath = GetProgramConfigPath (L"SetupComplete.cmd");
				if (FileExists (scriptFilePath.c_str()))
				{
					::DeleteFileW (scriptFilePath.c_str());
				}
			}
		}
	}
}

wstring GetWindowsDirectory ()
{
	wchar_t buf[MAX_PATH] = {0};
	GetSystemDirectory (buf, ARRAYSIZE (buf));

	return wstring (buf);
}

bool CallDriver (DWORD ioctl, void *input, DWORD inputSize, void *output, DWORD outputSize)
{
	DWORD bytesReturned;
	if (!DeviceIoControl (g_hDriver, ioctl, input, inputSize, output, outputSize, &bytesReturned, NULL))
		return false;
	else
		return true;
}

BOOL ResolveSymbolicLink (const wchar_t *symLinkName, PWSTR targetName, size_t cbTargetName)
{
	BOOL bResult;
	DWORD dwResult;
	RESOLVE_SYMLINK_STRUCT resolve;

	memset (&resolve, 0, sizeof(resolve));
	StringCbCopyW (resolve.symLinkName, sizeof(resolve.symLinkName), symLinkName);

	bResult = DeviceIoControl (g_hDriver, VC_IOCTL_GET_RESOLVED_SYMLINK, &resolve,
		sizeof (resolve), &resolve, sizeof (resolve), &dwResult,
		NULL);

	StringCbCopyW (targetName, cbTargetName, resolve.targetName);

	return bResult;
}


// Returns drive letter number assigned to device (-1 if none)
int GetDiskDeviceDriveLetter (PWSTR deviceName)
{
	int i;
	WCHAR link[MAX_PATH];
	WCHAR target[MAX_PATH];
	WCHAR device[MAX_PATH];

	if (!ResolveSymbolicLink (deviceName, device, sizeof(device)))
		StringCchCopyW (device, MAX_PATH, deviceName);

	for (i = 0; i < 26; i++)
	{
		WCHAR drive[] = { (WCHAR) i + L'A', L':', 0 };

		StringCchCopyW (link, MAX_PATH, L"\\DosDevices\\");
		StringCchCatW (link, MAX_PATH, drive);

		if (	ResolveSymbolicLink (link, target, sizeof(target))
			&& (wcscmp (device, target) == 0)
			)
		{
			return i;
		}
	}

	return -1;
}

PartitionList GetDrivePartitions (int driveNumber)
{
	PartitionList partList;

	for (int partNumber = 0; partNumber < 64; ++partNumber)
	{
		wstringstream partPath;
		partPath << L"\\Device\\Harddisk" << driveNumber << L"\\Partition" << partNumber;

		DISK_PARTITION_INFO_STRUCT diskPartInfo = {0};
		StringCchCopyW (diskPartInfo.deviceName, ARRAYSIZE (diskPartInfo.deviceName), partPath.str().c_str());

		try
		{
			CallDriver (VC_IOCTL_GET_DRIVE_PARTITION_INFO, &diskPartInfo, sizeof (diskPartInfo), &diskPartInfo, sizeof (diskPartInfo));
		}
		catch (...)
		{
			continue;
		}

		if (	(diskPartInfo.IsGPT == TRUE || diskPartInfo.IsGPT == FALSE)
			&&	(diskPartInfo.IsDynamic == TRUE || diskPartInfo.IsDynamic == FALSE)
			&&	(diskPartInfo.partInfo.BootIndicator == TRUE || diskPartInfo.partInfo.BootIndicator == FALSE)
			&&	(diskPartInfo.partInfo.RecognizedPartition == TRUE || diskPartInfo.partInfo.RecognizedPartition == FALSE)
			&&	(diskPartInfo.partInfo.RewritePartition == TRUE || diskPartInfo.partInfo.RewritePartition == FALSE)
			&&	(diskPartInfo.partInfo.StartingOffset.QuadPart >= 0)
			&&	(diskPartInfo.partInfo.PartitionLength.QuadPart >= 0)
			)
		{
			Partition part;
			part.DevicePath = partPath.str();
			part.Number = partNumber;
			part.Info = diskPartInfo.partInfo;
			part.IsGPT = diskPartInfo.IsGPT;

			// Mount point
			int driveNumber = GetDiskDeviceDriveLetter ((wchar_t *) partPath.str().c_str());

			if (driveNumber >= 0)
			{
				part.MountPoint += (wchar_t) (driveNumber + L'A');
				part.MountPoint += L":";
			}

			// Volume ID
			wchar_t volumePath[TC_MAX_PATH];
			if (ResolveSymbolicLink ((wchar_t *) partPath.str().c_str(), volumePath, sizeof(volumePath)))
			{
				wchar_t volumeName[TC_MAX_PATH];
				HANDLE fh = FindFirstVolumeW (volumeName, ARRAYSIZE (volumeName));
				if (fh != INVALID_HANDLE_VALUE)
				{
					do
					{
						wstring volumeNameStr = volumeName;
						wchar_t devicePath[TC_MAX_PATH];

						if (QueryDosDeviceW (volumeNameStr.substr (4, volumeNameStr.size() - 1 - 4).c_str(), devicePath, ARRAYSIZE (devicePath)) != 0
							&& wcscmp (volumePath, devicePath) == 0)
						{
							part.VolumeNameId = volumeName;
							break;
						}

					} while (FindNextVolumeW (fh, volumeName, ARRAYSIZE (volumeName)));

					FindVolumeClose (fh);
				}
			}

			partList.push_back (part);
		}
	}

	return partList;
}

std::wstring ToUpperCase (const std::wstring &str)
{
	wstring u;
	foreach (wchar_t c, str)
	{
		u += (wchar_t) towupper (c);
	}

	return u;
}

SystemDriveConfiguration GetSystemDriveConfiguration ()
{
	static bool DriveConfigValid;
	static SystemDriveConfiguration DriveConfig;
	if (DriveConfigValid)
		return DriveConfig;

	SystemDriveConfiguration config;

	wstring winDir = GetWindowsDirectory();

	// Scan all drives
	for (int driveNumber = 0; driveNumber < 32; ++driveNumber)
	{
		bool windowsFound = false;
		bool activePartitionFound = false;
		config.ExtraBootPartitionPresent = false;
		config.SystemLoaderPresent = false;

		PartitionList partitions = GetDrivePartitions (driveNumber);
		foreach (const Partition &part, partitions)
		{
			if (!part.MountPoint.empty()
				&& (_waccess ((part.MountPoint + L"\\bootmgr").c_str(), 0) == 0 || _waccess ((part.MountPoint + L"\\ntldr").c_str(), 0) == 0))
			{
				config.SystemLoaderPresent = true;
			}
			else if (!part.VolumeNameId.empty()
				&& (_waccess ((part.VolumeNameId + L"\\bootmgr").c_str(), 0) == 0 || _waccess ((part.VolumeNameId + L"\\ntldr").c_str(), 0) == 0))
			{
				config.SystemLoaderPresent = true;
			}

			if (!windowsFound && !part.MountPoint.empty() && ToUpperCase (winDir).find (ToUpperCase (part.MountPoint)) == 0)
			{
				config.SystemPartition = part;
				windowsFound = true;
			}

			if (!activePartitionFound && part.Info.BootIndicator)
			{
				activePartitionFound = true;

				if (part.Info.PartitionLength.QuadPart > 0 && part.Info.PartitionLength.QuadPart <= VC_MAX_EXTRA_BOOT_PARTITION_SIZE)
					config.ExtraBootPartitionPresent = true;
			}
		}

		if (windowsFound)
		{
			config.DriveNumber = driveNumber;

			wstringstream ss;
			ss << L"PhysicalDrive" << driveNumber;
			config.DevicePath = ss.str();

			wstringstream kernelPath;
			kernelPath << L"\\Device\\Harddisk" << driveNumber << L"\\Partition0";
			config.DeviceKernelPath = kernelPath.str();

			config.DrivePartition = partitions.front();
			partitions.pop_front();
			config.Partitions = partitions;

			config.InitialUnallocatedSpace = 0x7fffFFFFffffFFFFull;
			config.TotalUnallocatedSpace = config.DrivePartition.Info.PartitionLength.QuadPart;

			foreach (const Partition &part, config.Partitions)
			{
				if (part.Info.StartingOffset.QuadPart < config.InitialUnallocatedSpace)
					config.InitialUnallocatedSpace = part.Info.StartingOffset.QuadPart;

				config.TotalUnallocatedSpace -= part.Info.PartitionLength.QuadPart;
			}

			DriveConfig = config;
			DriveConfigValid = true;
			return DriveConfig;
		}
	}

	SystemDriveConfiguration dummy = {0};
	dummy.DriveNumber = -1;
	return dummy;
}


bool InstallBootLoader (Device& device)
{
	SystemDriveConfiguration config = GetSystemDriveConfiguration();

	if (!config.SystemPartition.IsGPT)
		return false;

	EfiBoot EfiBootInst;

	if (!EfiBootInst.PrepareBootPartition())
		return false;

	// Save modules
	const char* g_szMsBootString = "bootmgfw.pdb";
	unsigned __int64 loaderSize = 0;
	const wchar_t * szStdEfiBootloader = Is64BitOs()? L"\\EFI\\Boot\\bootx64.efi": L"\\EFI\\Boot\\bootia32.efi";
	const wchar_t * szBackupEfiBootloader = Is64BitOs()? L"\\EFI\\Boot\\original_bootx64.vc_backup": L"\\EFI\\Boot\\original_bootia32.vc_backup";

	bool bModifiedMsBoot = true;
	EfiBootInst.GetFileSize(L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", loaderSize);

	if (EfiBootInst.FileExists (L"\\EFI\\Microsoft\\Boot\\bootmgfw_ms.vc"))
	{
		if (loaderSize > 32768)
		{
			std::vector<byte> bootLoaderBuf ((size_t) loaderSize);

			if (EfiBootInst.ReadFile(L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", &bootLoaderBuf[0], (DWORD) loaderSize))
			{
				// look for bootmgfw.efi identifiant string
				if (BufferHasPattern (bootLoaderBuf.data (), (size_t) loaderSize, g_szMsBootString, strlen (g_szMsBootString)))
				{
					bModifiedMsBoot = false;
					// replace the backup with this version
					EfiBootInst.RenameFile (L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", L"\\EFI\\Microsoft\\Boot\\bootmgfw_ms.vc", TRUE);
				}
			}
		}
	}
	else
	{						
		// DcsBoot.efi is always smaller than 32KB
		if (loaderSize > 32768)
		{
			std::vector<byte> bootLoaderBuf ((size_t) loaderSize);

			if (EfiBootInst.ReadFile(L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", &bootLoaderBuf[0], (DWORD) loaderSize))
			{
				// look for bootmgfw.efi identifiant string
				if (BufferHasPattern (bootLoaderBuf.data (), (size_t) loaderSize, g_szMsBootString, strlen (g_szMsBootString)))
					bModifiedMsBoot = false;
			}
		}

		if (!bModifiedMsBoot)
		{
			if (!EfiBootInst.RenameFile (L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi", L"\\EFI\\Microsoft\\Boot\\bootmgfw_ms.vc", TRUE))
				return false;
		}
		else
		{
			return false;
		}
	}

	// check if bootmgfw.efi has been set again to Microsoft version
	// if yes, replace it with our bootloader after it was copied to bootmgfw_ms.vc
	if (!bModifiedMsBoot)
	{
		if (!EfiBootInst.CopyFile (L"\\EFI\\VeraCrypt\\DcsBoot.efi", L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi"))
			return false;
	}

	if (EfiBootInst.FileExists (szStdEfiBootloader))
	{
		// check if standard bootloader under EFI\Boot has been set to Microsoft version
		// if yes, replace it with our bootloader
		EfiBootInst.GetFileSize(szStdEfiBootloader, loaderSize);
		if (loaderSize > 32768)
		{
			std::vector<byte> bootLoaderBuf ((size_t) loaderSize);

			if (!EfiBootInst.ReadFile(szStdEfiBootloader, &bootLoaderBuf[0], (DWORD) loaderSize))
				return false;

			// look for bootmgfw.efi identifiant string
			if (BufferHasPattern (bootLoaderBuf.data (), (size_t) loaderSize, g_szMsBootString, strlen (g_szMsBootString)))
			{
				EfiBootInst.RenameFile (szStdEfiBootloader, szBackupEfiBootloader, TRUE);
				EfiBootInst.CopyFile (L"\\EFI\\VeraCrypt\\DcsBoot.efi", szStdEfiBootloader);
			}
		}
	}
	return true;
}


bool InstallBootLoader ()
{
	Device device (GetSystemDriveConfiguration().DevicePath);
	if (device.IsOpened())
		return InstallBootLoader (device);
	else
		return false;
}