/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is 
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is 
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses' 
 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2016 IDRIX
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#pragma once

#include <Windows.h>
#include <stdio.h>
#include <tchar.h>

typedef unsigned char byte;
typedef __int8 int8;
typedef __int16 int16;
typedef __int32 int32;
typedef __int64 int64;
typedef unsigned __int8 byte;
typedef unsigned __int16 uint16;
typedef unsigned __int32 uint32;
typedef unsigned __int64 uint64;

#define TC_MAX_PATH MAX_PATH
#define VC_MAX_EXTRA_BOOT_PARTITION_SIZE (512UL * 1024UL * 1024UL)

#if defined(_WIN32) && !defined(_UEFI)
#define burn(mem,size) do { volatile char *burnm = (volatile char *)(mem); size_t burnc = size; RtlSecureZeroMemory (mem, size); while (burnc--) *burnm++ = 0; } while (0)
#else
#define burn(mem,size) do { volatile char *burnm = (volatile char *)(mem); int burnc = size; while (burnc--) *burnm++ = 0; } while (0)
#endif


#define VC_IOCTL(CODE) (CTL_CODE (FILE_DEVICE_UNKNOWN, 0x800 + (CODE), METHOD_BUFFERED, FILE_ANY_ACCESS))

#define VC_IOCTL_GET_DRIVER_VERSION						VC_IOCTL (1)
#define VC_IOCTL_GET_BOOT_LOADER_VERSION				VC_IOCTL (2)
#define VC_IOCTL_GET_MOUNTED_VOLUMES					VC_IOCTL (6)
#define VC_IOCTL_GET_VOLUME_PROPERTIES					VC_IOCTL (7)
#define VC_IOCTL_GET_DRIVE_PARTITION_INFO				VC_IOCTL (14)
#define VC_IOCTL_GET_RESOLVED_SYMLINK					VC_IOCTL (17)
#define VC_IOCTL_GET_BOOT_ENCRYPTION_STATUS				VC_IOCTL (18)
#define VC_IOCTL_GET_BOOT_DRIVE_VOLUME_PROPERTIES		VC_IOCTL (22)
#define VC_IOCTL_EMERGENCY_SYSENC_CLEAR_KEYS			VC_IOCTL (41)

#define VOLUME_ID_SIZE	32

#pragma pack (push)
#pragma pack(1)

typedef struct
{
	unsigned __int32 ulMountedDrives;	/* Bitfield of all mounted drive letters */
	wchar_t wszVolume[26][260];	/* Volume names of mounted volumes */
	wchar_t wszLabel[26][33];	/* Labels of mounted volumes */
	wchar_t volumeID[26][VOLUME_ID_SIZE];	/* IDs of mounted volumes */
	unsigned __int64 diskLength[26];
	int ea[26];
	int volumeType[26];	/* Volume type (e.g. PROP_VOL_TYPE_OUTER, PROP_VOL_TYPE_OUTER_VOL_WRITE_PREVENTED, etc.) */
	BOOL truecryptMode[26];
} MOUNT_LIST_STRUCT;

typedef enum
{
	SetupNone = 0,
	SetupEncryption,
	SetupDecryption
} BootEncryptionSetupMode;


typedef struct
{
	BOOL DeviceFilterActive;

	unsigned short BootLoaderVersion;

	BOOL DriveMounted;
	BOOL VolumeHeaderPresent;
	BOOL DriveEncrypted;

	LARGE_INTEGER BootDriveLength;

	__int64 ConfiguredEncryptedAreaStart;
	__int64 ConfiguredEncryptedAreaEnd;
	__int64 EncryptedAreaStart;
	__int64 EncryptedAreaEnd;

	unsigned int VolumeHeaderSaltCrc32;

	BOOL SetupInProgress;
	BootEncryptionSetupMode SetupMode;
	BOOL TransformWaitingForIdle;

	unsigned int HibernationPreventionCount;

	BOOL HiddenSystem;
	__int64 HiddenSystemPartitionStart;

	// Number of times the filter driver answered that an unencrypted volume
	// is read-only (or mounted an outer/normal TrueCrypt volume as read only)
	unsigned int HiddenSysLeakProtectionCount;

} BootEncryptionStatus;

typedef struct
{
	int driveNo;
	int uniqueId;
	wchar_t wszVolume[260];
	unsigned __int64 diskLength;
	int ea;
	int mode;
	int pkcs5;
	int pkcs5Iterations;
	BOOL hiddenVolume;
	BOOL readOnly;
	BOOL removable;
	BOOL partitionInInactiveSysEncScope;
	unsigned __int32 volumeHeaderFlags;
	unsigned __int64 totalBytesRead;
	unsigned __int64 totalBytesWritten;
	int hiddenVolProtection;
	int volFormatVersion;
	int volumePim;
	wchar_t wszLabel[33];
	BOOL bDriverSetLabel;
	unsigned char volumeID[VOLUME_ID_SIZE];
	BOOL mountDisabled;
} VOLUME_PROPERTIES_STRUCT;

#pragma pack (pop)

typedef struct
{
	WCHAR symLinkName[TC_MAX_PATH];
	WCHAR targetName[TC_MAX_PATH];
} RESOLVE_SYMLINK_STRUCT;

typedef struct
{
	WCHAR deviceName[TC_MAX_PATH];
	PARTITION_INFORMATION partInfo;
	BOOL IsGPT;
	BOOL IsDynamic;
}
DISK_PARTITION_INFO_STRUCT;

typedef struct
{
	WCHAR deviceName[TC_MAX_PATH];
	DISK_GEOMETRY diskGeometry;
}
DISK_GEOMETRY_STRUCT;

typedef struct
{
	WCHAR deviceName[TC_MAX_PATH];
	DISK_GEOMETRY diskGeometry;
	LARGE_INTEGER DiskSize;
}
DISK_GEOMETRY_EX_STRUCT;

typedef struct
{
	WCHAR DeviceName[TC_MAX_PATH];
	LARGE_INTEGER RealDriveSize;
	BOOL TimeOut;
} ProbeRealDriveSizeRequest;

/* Volume types */
enum
{
	TC_VOLUME_TYPE_NORMAL = 0,
	TC_VOLUME_TYPE_HIDDEN,
	TC_VOLUME_TYPE_COUNT
};

typedef struct
{
	wchar_t wszFileName[TC_MAX_PATH];		// Volume to be "open tested"
	BOOL bDetectTCBootLoader;			// Whether the driver is to determine if the first sector contains a portion of the TrueCrypt Boot Loader
	BOOL TCBootLoaderDetected;
	BOOL DetectFilesystem;
	BOOL FilesystemDetected;
	BOOL bComputeVolumeIDs;
	unsigned char volumeIDs[TC_VOLUME_TYPE_COUNT][VOLUME_ID_SIZE];
	BOOL VolumeIDComputed[TC_VOLUME_TYPE_COUNT];
} OPEN_TEST_STRUCT;


class ForEach
{
public:
	struct Container
	{
		Container () : InnerContinue (true), InnerEndCondition (false) { }
		virtual ~Container () { }

		void Continue () const { InnerContinue = true; }
		bool InnerIsNotEnd () const { return InnerEndCondition = !InnerEndCondition; }
		virtual bool IsNotEnd () const = 0;
		virtual void Next () const = 0;

		mutable bool InnerContinue;
		mutable bool InnerEndCondition;
	};

protected:
	template <class T>
	struct ContainerForward : Container
	{
		ContainerForward (const T &container)
			: ContainerCopy (container), EndIterator (ContainerCopy.end()), Iterator (ContainerCopy.begin()) { }

		virtual bool IsNotEnd () const { bool r = InnerContinue && Iterator != EndIterator; InnerContinue = false; return r; }
		virtual void Next () const { ++Iterator; }

		const T ContainerCopy;	// Support for temporary objects
		typename T::const_iterator EndIterator;
		mutable typename T::const_iterator Iterator;

	private:
		ContainerForward &operator= (const ContainerForward &);
	};

	template <class T>
	struct ContainerReverse : Container
	{
		ContainerReverse (const T &container)
			: ContainerCopy (container), EndIterator (ContainerCopy.rend()), Iterator (ContainerCopy.rbegin()) { }

		virtual bool IsNotEnd () const { bool r = InnerContinue && Iterator != EndIterator; InnerContinue = false; return r; }
		virtual void Next () const { ++Iterator; }

		const T ContainerCopy;
		typename T::const_reverse_iterator EndIterator;
		mutable typename T::const_reverse_iterator Iterator;

	private:
		ContainerReverse &operator= (const ContainerReverse &);
	};

public:
	template <class T>
	static ContainerForward <T> GetContainerForward (const T &container)
	{
		return ContainerForward <T> (container);
	}

	template <class T>
	static ContainerReverse <T> GetContainerReverse (const T &container)
	{
		return ContainerReverse <T> (container);
	}

protected:
	template <class T>
	struct TypeWrapper { };

public:
	template <class T>
	static TypeWrapper <T> ToTypeWrapper (const T &x) { return TypeWrapper <T> (); }

	struct TypeWrapperDummy
	{
		template <class T>
		operator TypeWrapper <T> () const { return TypeWrapper <T> (); }
	};

	template <class T>
	static const ContainerForward <T> &GetContainerForward (const Container &forEachContainer, const TypeWrapper <T> &)
	{
		return static_cast <const ContainerForward <T> &> (forEachContainer);
	}

	template <class T>
	static const ContainerReverse <T> &GetContainerReverse (const Container &forEachContainer, const TypeWrapper <T> &)
	{
		return static_cast <const ContainerReverse <T> &> (forEachContainer);
	}
};


#define FOREACH_TEMPLATE(dereference,listType,variable,listInstance) \
	for (const ForEach::Container &forEachContainer = ForEach::GetContainer##listType (listInstance); forEachContainer.IsNotEnd(); forEachContainer.Next()) \
		for (variable = dereference(ForEach::GetContainer##listType (forEachContainer, (true ? ForEach::TypeWrapperDummy() : ForEach::ToTypeWrapper (listInstance))).Iterator); forEachContainer.InnerIsNotEnd(); forEachContainer.Continue())

#define foreach(variable,listInstance) FOREACH_TEMPLATE(*, Forward, variable, listInstance)
#define foreach_ref(variable,listInstance) FOREACH_TEMPLATE(**, Forward, variable, listInstance)
#define foreach_reverse(variable,listInstance) FOREACH_TEMPLATE(*, Reverse, variable, listInstance)
#define foreach_reverse_ref(variable,listInstance) FOREACH_TEMPLATE(**, Reverse, variable, listInstance)
