// VcFixBoot.cpp : main source file for VcFixBoot.exe
//

#include "stdafx.h"

#include "resource.h"

#include "MainDlg.h"
#include "BootEncryption.h"

CAppModule _Module;
HANDLE g_hDriver = INVALID_HANDLE_VALUE;

BOOL SetPrivilege(LPTSTR szPrivilegeName, BOOL bEnable)
{
	HANDLE hToken;
	TOKEN_PRIVILEGES tkp;
	BOOL bRet = FALSE;
	DWORD dwLastError = 0;

	if (OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken))
	{
		if (LookupPrivilegeValue(NULL, szPrivilegeName,
				&tkp.Privileges[0].Luid))
		{
			tkp.PrivilegeCount = 1;
			tkp.Privileges[0].Attributes = bEnable? SE_PRIVILEGE_ENABLED : SE_PRIVILEGE_REMOVED;
			
			bRet = AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, NULL, NULL);
			if (!bRet)
				dwLastError = GetLastError ();
		}
		else
			dwLastError = GetLastError ();

		CloseHandle(hToken);
	}
	else
		dwLastError = GetLastError ();

	SetLastError (dwLastError);

	return bRet;
}

int WINAPI _tWinMain(HINSTANCE hInstance, HINSTANCE /*hPrevInstance*/, LPTSTR /*lpstrCmdLine*/, int /*nCmdShow*/)
{
	HRESULT hRes = ::CoInitialize(NULL);
// If you are running on NT 4.0 or higher you can use the following call instead to 
// make the EXE free threaded. This means that calls come in on a random RPC thread.
//	HRESULT hRes = ::CoInitializeEx(NULL, COINIT_MULTITHREADED);
	ATLASSERT(SUCCEEDED(hRes));

	// this resolves ATL window thunking problem when Microsoft Layer for Unicode (MSLU) is used
	::DefWindowProc(NULL, 0, 0, 0L);

	AtlInitCommonControls(ICC_BAR_CLASSES);	// add flags to support other controls

	hRes = _Module.Init(NULL, hInstance);
	ATLASSERT(SUCCEEDED(hRes));

	int nRet = 0;

	InitOSVersionInfo();

    // connect to the VeraCrypt driver
    g_hDriver = CreateFileW (L"\\\\.\\VeraCrypt", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	{
		SetPrivilege(SE_SYSTEM_ENVIRONMENT_NAME, TRUE);

		CMainDlg dlgMain;
		nRet = dlgMain.DoModal();
	}

    if (g_hDriver != INVALID_HANDLE_VALUE)
    {
		CloseHandle (g_hDriver);
	}

	_Module.Term();
	::CoUninitialize();

	return nRet;
}
