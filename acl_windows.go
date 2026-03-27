package osfs

import (
	"io/fs"
	"path/filepath"
	"unsafe"

	"github.com/hectane/go-acl/api"
	"golang.org/x/sys/windows"
)

/*
	Reference ipmlementation: https://github.com/hectane/go-acl/pull/14/files#diff-90e19fbd99f32256c4dd032b519057915afd93349a9ad8cb0c67aaeebafdeb67

*/

var (
	advapi32                       = windows.MustLoadDLL("advapi32.dll")
	procGetEffectiveRightsFromAclW = advapi32.MustFindProc("GetEffectiveRightsFromAclW")
	procGetExplicitEntriesFromAclW = advapi32.MustFindProc("GetExplicitEntriesFromAclW")
)

const (
	// access mask constants from https://docs.microsoft.com/en-us/windows/desktop/wmisdk/file-and-directory-access-rights-constants
	// the x/sys/windows package defines some but not all of these constants
	FILE_READ_DATA = windows.FILE_LIST_DIRECTORY // for a directory, the ability to list contents
	// the windows package only has this by the "LIST_DIRECTORY" name
	FILE_WRITE_DATA       = 0x02                     // for a directory, the ability to add a file
	FILE_APPEND_DATA      = windows.FILE_APPEND_DATA // for a directory, the ability to add a subdirectory
	FILE_READ_EA          = 0x08
	FILE_WRITE_EA         = 0x10
	FILE_EXECUTE          = 0x20 // for a directory, the ability to traverse
	FILE_READ_ATTRIBUTES  = 0x80
	FILE_WRITE_ATTRIBUTES = windows.FILE_WRITE_ATTRIBUTES
	DELETE                = 0x10000
	SYNCHRONIZE           = windows.SYNCHRONIZE

	// these correspond to the GENERIC permissions from https://docs.microsoft.com/en-us/windows/desktop/FileIO/file-security-and-access-rights
	// except that PERM_WRITE has DELETE added to it because otherwise it would be impossible to delete or rename a file.

	PERM_READ uint32 = 0 |
		FILE_READ_ATTRIBUTES |
		FILE_READ_DATA |
		FILE_READ_EA |
		windows.STANDARD_RIGHTS_READ |
		SYNCHRONIZE

	PERM_WRITE uint32 = 0 |
		FILE_APPEND_DATA |
		FILE_WRITE_ATTRIBUTES |
		FILE_WRITE_DATA |
		FILE_WRITE_EA |
		windows.STANDARD_RIGHTS_WRITE |
		SYNCHRONIZE

	PERM_EXECUTE uint32 = 0 |
		FILE_EXECUTE |
		FILE_READ_ATTRIBUTES |
		windows.STANDARD_RIGHTS_EXECUTE |
		SYNCHRONIZE

	// https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
	SID_NAME_CREATOR_OWNER = "S-1-3-0"
	SID_NAME_CREATOR_GROUP = "S-1-3-1"
	SID_NAME_EVERYONE      = "S-1-1-0"
)

// apply the provided access control entries to a file. If the replace
// parameter is true, existing entries will be overwritten. If the inherit
// parameter is true, the file will inherit ACEs from its parent.
func apply(name string, replace, inherit bool, entries ...api.ExplicitAccess) (err error) {
	var oldAcl windows.Handle
	if !replace {
		var secDesc windows.Handle
		defer func() {
			if secDesc != 0 {
				_, e := windows.LocalFree(secDesc)
				if e != nil {
					panic(e)
				}
			}
		}()
		err = api.GetNamedSecurityInfo(
			name,
			api.SE_FILE_OBJECT,
			api.DACL_SECURITY_INFORMATION,
			nil,
			nil,
			&oldAcl,
			nil,
			&secDesc,
		)
		if err != nil {
			return err
		}

	}
	var acl windows.Handle
	if err := api.SetEntriesInAcl(
		entries,
		oldAcl,
		&acl,
	); err != nil {
		return err
	}
	defer windows.LocalFree((windows.Handle)(unsafe.Pointer(acl)))
	var secInfo uint32
	if !inherit {
		secInfo = api.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		secInfo = api.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	return api.SetNamedSecurityInfo(
		name,
		api.SE_FILE_OBJECT,
		api.DACL_SECURITY_INFORMATION|secInfo,
		nil,
		nil,
		acl,
		0,
	)
}

func getEffectiveRightsFromAcl(oldAcl windows.Handle, sid *windows.SID) (uint32, error) {
	trustee := api.Trustee{
		TrusteeForm: api.TRUSTEE_IS_SID,
		Name:        (*uint16)(unsafe.Pointer(sid)),
	}

	var rights uint32

	ret, _, err := procGetEffectiveRightsFromAclW.Call(
		uintptr(oldAcl),
		uintptr(unsafe.Pointer(&trustee)),
		uintptr(unsafe.Pointer(&rights)),
	)
	if ret != 0 {
		return 0, err
	}
	return rights, nil
}

func getExplicitEntriesFromAcl(oldAcl windows.Handle) ([]api.ExplicitAccess, error) {
	var (
		count uint32
		list  uintptr
	)

	/* TODO: seems like I ought to be able to something like this:
		 var entries *[]ExplicitAccess
		 ret, _, err := procGetExplicitEntriesFromAclW.Call(
			 ...,
			 uintptr(unsafe.Pointer(&entries)),
		 )
	   but I couldn't figure out how to make it work.  I tried a whole
	   bunch of different combinations but I only ever managed to get an empty list
	*/
	ret, _, err := procGetExplicitEntriesFromAclW.Call(
		uintptr(oldAcl),
		uintptr(unsafe.Pointer(&count)),
		uintptr(unsafe.Pointer(&list)),
	)

	if ret != 0 {
		return nil, err
	}

	defer windows.LocalFree(windows.Handle(unsafe.Pointer(list)))

	const explicitAccessSize = unsafe.Sizeof(api.ExplicitAccess{})
	getEntryAtOffset := func(list uintptr, offset uint32) api.ExplicitAccess {
		return *(*api.ExplicitAccess)(unsafe.Pointer(list + explicitAccessSize*uintptr(offset)))
	}

	output := make([]api.ExplicitAccess, count)
	for i := uint32(0); i < count; i++ {
		output[i] = getEntryAtOffset(list, i)
	}

	return output, nil
}

func getEffectiveRightsForSidName(oldAcl windows.Handle, sidName string) (uint32, error) {
	sid, err := windows.StringToSid(sidName)
	if err != nil {
		return 0, err
	}

	return getEffectiveRightsFromAcl(oldAcl, sid)
}

func getAccessModeForRights(rights uint32) uint32 {
	var ret uint32

	if rights&PERM_READ == PERM_READ {
		ret |= 04
	}
	if rights&PERM_WRITE == PERM_WRITE {
		ret |= 02
	}
	if rights&PERM_EXECUTE == PERM_EXECUTE {
		ret |= 01
	}

	return ret
}

func getExplicitAccessMode(name string) (fs.FileMode, error) {
	var (
		oldAcl  windows.Handle
		secDesc windows.Handle

		owner *windows.SID
		group *windows.SID
	)

	path, err := filepath.Abs(name)
	if err != nil {
		return fs.FileMode(0), err
	}

	err = api.GetNamedSecurityInfo(
		path,
		api.SE_FILE_OBJECT,
		api.DACL_SECURITY_INFORMATION|
			api.OWNER_SECURITY_INFORMATION|
			api.GROUP_SECURITY_INFORMATION,
		&owner,
		&group,
		&oldAcl,
		nil,
		&secDesc,
	)
	if err != nil {
		return fs.FileMode(0), err
	}
	defer windows.LocalFree(secDesc)

	ownerName := owner.String()
	groupName := group.String()

	entries, err := getExplicitEntriesFromAcl(oldAcl)
	if err != nil {
		return fs.FileMode(0), err
	}

	var mode uint32
	if len(entries) > 0 {
		for _, item := range entries {
			if item.AccessMode == api.GRANT_ACCESS && item.Trustee.TrusteeForm == api.TRUSTEE_IS_SID {
				trustee := (*windows.SID)(unsafe.Pointer(item.Trustee.Name))

				switch trustee.String() {
				case ownerName:
					mode |= (getAccessModeForRights(item.AccessPermissions) << 6)
				case groupName:
					mode |= (getAccessModeForRights(item.AccessPermissions) << 3)
				case SID_NAME_EVERYONE:
					mode |= getAccessModeForRights(item.AccessPermissions)
				}
			}
		}
	}

	return fs.FileMode(mode), nil
}

func getEffectiveAccessMode(name string) (fs.FileMode, error) {
	// get the file's current ACL
	var (
		oldAcl  windows.Handle
		secDesc windows.Handle

		owner *windows.SID
		group *windows.SID
	)

	path, err := filepath.Abs(name)
	if err != nil {
		return fs.FileMode(0), err
	}

	err = api.GetNamedSecurityInfo(
		path,
		api.SE_FILE_OBJECT,
		api.DACL_SECURITY_INFORMATION|
			api.OWNER_SECURITY_INFORMATION|
			api.GROUP_SECURITY_INFORMATION,
		&owner,
		&group,
		&oldAcl,
		nil,
		&secDesc,
	)
	if err != nil {
		return fs.FileMode(0), err
	}
	defer windows.LocalFree(secDesc)

	ownerRights, err := getEffectiveRightsFromAcl(oldAcl, owner)
	if err != nil {
		return fs.FileMode(0), err
	}

	groupRights, err := getEffectiveRightsFromAcl(oldAcl, group)
	if err != nil {
		return fs.FileMode(0), err
	}

	everyoneRights, err := getEffectiveRightsForSidName(oldAcl, SID_NAME_EVERYONE)
	if err != nil {
		return fs.FileMode(0), err
	}

	mode := fs.FileMode(
		getAccessModeForRights(ownerRights)<<6 |
			getAccessModeForRights(groupRights)<<3 |
			getAccessModeForRights(everyoneRights)<<0)

	return mode, nil
}
