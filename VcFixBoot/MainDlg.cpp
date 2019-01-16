// MainDlg.cpp : implementation of the CMainDlg class
//
/////////////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "resource.h"

#include "MainDlg.h"
#include "BootEncryption.h"

// possible state values of system encryption
typedef enum
{
    SYSENC_FULL = 0,
    SYSENC_PARTIAL = 1,
    SYSENC_NONE = 2
} eSysEncState;


// get the state of system encryption from the status returned by the driver
eSysEncState GetSystemEncryptionState (BootEncryptionStatus& status)
{
    if (status.DriveMounted || status.DriveEncrypted)
    {
	    if (!status.SetupInProgress
		    && status.ConfiguredEncryptedAreaEnd != 0
		    && status.ConfiguredEncryptedAreaEnd != -1
		    && status.ConfiguredEncryptedAreaStart == status.EncryptedAreaStart
		    && status.ConfiguredEncryptedAreaEnd == status.EncryptedAreaEnd
            )
        {
            return SYSENC_FULL;
        }
	
        if (	status.EncryptedAreaEnd < 0 
		    || status.EncryptedAreaStart < 0
		    || status.EncryptedAreaEnd <= status.EncryptedAreaStart
		    )
        {
            return SYSENC_NONE;
        }

        return SYSENC_PARTIAL;
    }
    else
        return SYSENC_NONE;
}


BOOL IsUefiBIOS ()
{
	BOOL bStatus = FALSE;
	if(!GetFirmwareEnvironmentVariable (L"", L"{00000000-0000-0000-0000-000000000000}", NULL, 0))
	{
		if (ERROR_INVALID_FUNCTION != GetLastError())
			bStatus = TRUE;
	}

	return bStatus;
}

BOOL IsSecureBootEnabled ()
{
	static const wchar_t*	EfiVarGuid = L"{8BE4DF61-93CA-11D2-AA0D-00E098032B8C}";
	ByteArray varValue ((ByteArray::size_type) 4096);
	DWORD dwLen = GetFirmwareEnvironmentVariable (L"SecureBoot", EfiVarGuid, varValue.data(), (DWORD) varValue.size());
	if ((dwLen >= 1) && (varValue[0] == 1))
	{
		return TRUE;
	}
	else
		return FALSE;
}

LRESULT CMainDlg::OnInitDialog(UINT /*uMsg*/, WPARAM /*wParam*/, LPARAM /*lParam*/, BOOL& /*bHandled*/)
{
	// center the dialog on the screen
	CenterWindow();

	// set icons
	HICON hIcon = AtlLoadIconImage(IDR_MAINFRAME, LR_DEFAULTCOLOR, ::GetSystemMetrics(SM_CXICON), ::GetSystemMetrics(SM_CYICON));
	SetIcon(hIcon, TRUE);
	HICON hIconSmall = AtlLoadIconImage(IDR_MAINFRAME, LR_DEFAULTCOLOR, ::GetSystemMetrics(SM_CXSMICON), ::GetSystemMetrics(SM_CYSMICON));
	SetIcon(hIconSmall, FALSE);

	if (g_hDriver)
	{
		SetDlgItemText (IDC_VC_INSTALLED, L"Yes");

		WCHAR szText[512];
		DWORD cbBytesReturned;
		LONG DriverVersion;
		BOOL bResult = DeviceIoControl (g_hDriver, VC_IOCTL_GET_DRIVER_VERSION, NULL, 0, &DriverVersion, sizeof (DriverVersion), &cbBytesReturned, NULL);
		if (bResult)
		{
			StringCbPrintfW (szText, sizeof (szText), L"%d.%.2x", (DriverVersion >> 8) & 0x000000FF, DriverVersion & 0x000000FF);			
		}
		else
		{
			StringCbPrintfW (szText, sizeof (szText), L"Error 0x%.8X", GetLastError());
		}
		SetDlgItemText (IDC_VC_VERSION, szText);

		bool bSysEncrypted;
		BootEncryptionStatus status;
        if (DeviceIoControl (g_hDriver, VC_IOCTL_GET_BOOT_ENCRYPTION_STATUS, NULL, 0, &status, sizeof (status), &cbBytesReturned, NULL))
        {
			bSysEncrypted = (status.DriveMounted || status.DriveEncrypted);
			if (bSysEncrypted)
			{
				eSysEncState state = GetSystemEncryptionState (status);
				StringCbPrintfW (szText, sizeof (szText), L"Yes (%s)", 
					(state == SYSENC_NONE)? TEXT("None") : (state == SYSENC_PARTIAL)? TEXT("Partial") : TEXT("Full"));
			}
			else
				StringCbCopyW (szText, sizeof(szText), L"No");
		}
		else
		{
			StringCbPrintfW (szText, sizeof (szText), L"Error 0x%.8X", GetLastError());
		}
		SetDlgItemText (IDC_VC_SYSENC, szText);

		BOOL bIsGPT = FALSE;
		if (IsUefiBIOS ())
		{
			bIsGPT = TRUE;
			SetDlgItemText (IDC_VC_BOOT_MODE, L"UEFI");
			if (IsSecureBootEnabled())
				SetDlgItemText (IDC_VC_SECURE_BOOT, L"Enabled");
			else
				SetDlgItemText (IDC_VC_SECURE_BOOT, L"Disabled");
		}
		else
		{
			SetDlgItemText (IDC_VC_BOOT_MODE, L"Legacy MBR");
			SetDlgItemText (IDC_VC_SECURE_BOOT, L"No");
		}

		if (bSysEncrypted)
		{
			unsigned short bootVersion = 0;
		    if (DeviceIoControl (g_hDriver, VC_IOCTL_GET_BOOT_LOADER_VERSION, NULL, 0, &bootVersion, sizeof (bootVersion), &cbBytesReturned, NULL))
			{
				StringCbPrintfW (szText, sizeof (szText), L"%d.%.2x", (bootVersion >> 8) & 0x00FF, bootVersion & 0x00FF);			
			}
			else
			{
				StringCbPrintfW (szText, sizeof (szText), L"Error 0x%.8X", GetLastError());
			}
			SetDlgItemText (IDC_VC_BOOTLOADER_VERSION, szText);
		}

		if (bSysEncrypted && bIsGPT)
			GetDlgItem(IDC_ANALYZE).EnableWindow (TRUE);
	}

	return TRUE;
}

LRESULT CMainDlg::OnCancel(WORD /*wNotifyCode*/, WORD wID, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
	EndDialog(wID);
	return 0;
}


LRESULT CMainDlg::OnBnClickedAnalyze(WORD /*wNotifyCode*/, WORD /*wID*/, HWND /*hWndCtl*/, BOOL& /*bHandled*/)
{
	CWaitCursor busy;
	UpdateSetupConfigFile (true);
	
	if (InstallBootLoader ())
		MessageBox (L"EFI BootLoader configuration updated correctly", L"Success", MB_ICONINFORMATION);
	else
		MessageBox (L"An error occured while updating EFI BootLoader configuration", L"Error", MB_ICONERROR);

	return 0;
}


LRESULT CMainDlg::OnNMClickSyslink1(int /*idCtrl*/, LPNMHDR pNMHDR, BOOL& /*bHandled*/)
{
	ShellExecute (m_hWnd, L"open", L"https://www.veracrypt.fr", NULL, NULL, SW_SHOW);

	return 0;
}
