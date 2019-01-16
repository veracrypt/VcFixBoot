#pragma once

#include "defs.h"

typedef enum
{
	// IMPORTANT: If you add a new item here, update IsOSVersionAtLeast().

	WIN_UNKNOWN = 0,
	WIN_31,
	WIN_95,
	WIN_98,
	WIN_ME,
	WIN_NT3,
	WIN_NT4,
	WIN_2000,
	WIN_XP,
	WIN_XP64,
	WIN_SERVER_2003,
	WIN_VISTA,
	WIN_SERVER_2008,
	WIN_7,
	WIN_SERVER_2008_R2,
	WIN_8,
	WIN_SERVER_2012,
	WIN_8_1,
	WIN_SERVER_2012_R2,
	WIN_10,
	WIN_SERVER_2016
} OSVersionEnum;

BOOL InitOSVersionInfo ();
BOOL IsOSVersionAtLeast (OSVersionEnum reqMinOS, int reqMinServicePack);
void UpdateSetupConfigFile (bool bForInstall);
bool CallDriver (DWORD ioctl, void *input, DWORD inputSize, void *output, DWORD outputSize);
bool InstallBootLoader ();

class File
{
public:
	File () : FileOpen (false), ReadOnly (false), FilePointerPosition(0), Handle(INVALID_HANDLE_VALUE), IsDevice(false), LastError(0) { }
	File (wstring path,bool readOnly = false, bool create = false);
	virtual ~File () { Close(); }

	bool IsOpened () const { return FileOpen;}
	void Close ();
	DWORD Read (byte *buffer, DWORD size);
	bool Write (byte *buffer, DWORD size);
	bool GetFileSize (unsigned __int64& size);
	bool GetFileSize (DWORD& dwSize);
    bool IoCtl(DWORD code, void* inBuf, DWORD inBufSize, void* outBuf, DWORD outBufSize);

protected:
	bool FileOpen;
	bool ReadOnly;
	uint64 FilePointerPosition;
	HANDLE Handle;
	bool IsDevice;
	wstring Path;
	DWORD LastError;
	BYTE ReadBuffer[4096];
};


class Device : public File
{
public:
	Device (wstring path,bool readOnly = false);
	virtual ~Device () {}
};


class Buffer
{
public:
	Buffer (size_t size) : DataSize (size)
	{
		DataPtr = new byte[size];
		if (!DataPtr)
			throw bad_alloc();
	}

	~Buffer () { delete[] DataPtr; }
	byte *Ptr () const { return DataPtr; }
	size_t Size () const { return DataSize; }
	void Resize (size_t newSize)
	{ 
		if (newSize > DataSize)
		{
			byte *tmp = new byte[newSize];
			if (!tmp)
				throw bad_alloc();
			memcpy (tmp, DataPtr, DataSize);
			delete [] DataPtr;			
			DataPtr = tmp;
		}
		DataSize = newSize;
	}

protected:
	byte *DataPtr;
	size_t DataSize;
};


class EfiBoot {
public:
	EfiBoot();

	bool PrepareBootPartition();
	bool IsEfiBoot();

	bool DeleteStartExec(uint16 statrtOrderNum = 0xDC5B, wchar_t* type = NULL);
	bool SetStartExec(wstring description, wstring execPath, uint16 statrtOrderNum = 0xDC5B, wchar_t* type = NULL, uint32 attr = 1);
	bool SaveFile(const wchar_t* name, byte* data, DWORD size);
	bool GetFileSize(const wchar_t* name, unsigned __int64& size);
	bool ReadFile(const wchar_t* name, byte* data, DWORD size);
	bool CopyFile(const wchar_t* name, const wchar_t* targetName);
	bool FileExists(const wchar_t* name);

	BOOL RenameFile(const wchar_t* name, const wchar_t* nameNew, BOOL bForce);
	BOOL DelFile(const wchar_t* name);
	bool SelectBootVolumeESP();
	PSTORAGE_DEVICE_NUMBER GetStorageDeviceNumber () { return &sdn;}

protected:
	bool m_bMounted;
	std::wstring	EfiBootPartPath;
	STORAGE_DEVICE_NUMBER sdn;
	PARTITION_INFORMATION_EX partInfo;
	WCHAR     tempBuf[1024];
	bool  bBootVolumePathSelected;
	std::wstring BootVolumePath;
};


	struct Partition
	{
		wstring DevicePath;
		PARTITION_INFORMATION Info;
		wstring MountPoint;
		size_t Number;
		BOOL IsGPT;
		wstring VolumeNameId;
	};

	typedef list <Partition> PartitionList;

#pragma pack (push)
#pragma pack(1)

	struct PartitionEntryMBR
	{
		byte BootIndicator;

		byte StartHead;
		byte StartCylSector;
		byte StartCylinder;

		byte Type;

		byte EndHead;
		byte EndSector;
		byte EndCylinder;

		uint32 StartLBA;
		uint32 SectorCountLBA;
	};

	struct MBR
	{
		byte Code[446];
		PartitionEntryMBR Partitions[4];
		uint16 Signature;
	};

#pragma pack (pop)

struct SystemDriveConfiguration
{
	wstring DeviceKernelPath;
	wstring DevicePath;
	int DriveNumber;
	Partition DrivePartition;
	bool ExtraBootPartitionPresent;
	int64 InitialUnallocatedSpace;
	PartitionList Partitions;
	Partition SystemPartition;
	int64 TotalUnallocatedSpace;
	bool SystemLoaderPresent;
};
