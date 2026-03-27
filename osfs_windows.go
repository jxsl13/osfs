package osfs

import (
	"errors"
	"io/fs"
	"os"
	"syscall"

	"github.com/hectane/go-acl"
	"github.com/hectane/go-acl/api"
	"github.com/jxsl13/osfs/fsi"
	"golang.org/x/sys/windows"
)

func (ofs *OsFs) lstat(name string) (fs.FileInfo, error) {

	fi, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}

	fm, err := getEffectiveAccessMode(name)
	if err != nil {
		return nil, err
	}
	return newWinInfo(fi, fm), nil
}

func (ofs *OsFs) openFile(name string, flag int, perm fs.FileMode) (fsi.File, error) {

	f, err := os.OpenFile(name, flag, perm)
	if f == nil {
		// while this looks strange, we need to return a bare nil (of type nil) not
		// a nil value of type *os.File or nil won't be nil
		return nil, err
	}

	// TODO: can we change the file permissions while the file is open?
	if perm != 0 {
		err = ofs.chmod(name, perm)
		if err != nil {
			_ = f.Close()
			return nil, err
		}

	}

	return newOsFile(ofs, f), err
}

func (ofs *OsFs) mkdir(name string, perm fs.FileMode) error {
	err := os.Mkdir(name, perm)
	if err != nil {
		return err
	}
	err = acl.Chmod(name, perm)
	if err != nil {
		return err
	}
	return nil
}

func (ofs *OsFs) mkdirAll(path string, perm fs.FileMode) error {
	dir, err := ofs.stat(path)
	if err == nil {
		if dir.IsDir() {
			return nil
		}
		return &fs.PathError{Op: "mkdir", Path: path, Err: syscall.ENOTDIR}
	}

	return iterateNotExistingDirTree(ofs, path, func(subdir string, _ fs.FileInfo) error {
		return ofs.mkdir(subdir, perm)
	})
}

func (ofs *OsFs) chmod(name string, fileMode fs.FileMode) error {
	// https://support.microsoft.com/en-us/help/243330/well-known-security-identifiers-in-windows-operating-systems
	creatorOwnerSID, err := windows.StringToSid(SID_NAME_CREATOR_OWNER)
	if err != nil {
		return err
	}
	creatorGroupSID, err := windows.StringToSid(SID_NAME_CREATOR_GROUP)
	if err != nil {
		return err
	}
	everyoneSID, err := windows.StringToSid(SID_NAME_EVERYONE)
	if err != nil {
		return err
	}

	mode := uint32(fileMode)
	return apply(
		name,
		true,
		false,
		acl.GrantSid(((mode&0700)<<23)|((mode&0200)<<9)|windows.SYNCHRONIZE, creatorOwnerSID),
		acl.GrantSid(((mode&0070)<<26)|((mode&0020)<<12)|windows.SYNCHRONIZE, creatorGroupSID),
		acl.GrantSid(((mode&0007)<<29)|((mode&0002)<<15)|windows.SYNCHRONIZE, everyoneSID),
	)
}

func (ofs *OsFs) chown(name string, uid, gid string) (err error) {
	name, _, err = ofs.followSymlinks(name)
	if err != nil {
		return err
	}

	return ofs.lchown(name, uid, gid)
}

func (ofs *OsFs) lchown(name string, uid, gid string) (err error) {
	usid, err := windows.StringToSid(uid)
	if err != nil {
		return err
	}
	gsid, err := windows.StringToSid(gid)
	if err != nil {
		return err
	}

	// some docs/examples tell that "SeTakeOwnershipPrivilege" should be used
	// but it seems with that not all SIDs work for setting owner
	// (well known groups did work for me, individual users didn't)
	err = enablePrivilege("SeRestorePrivilege")
	if err != nil {
		return err
	}
	defer func() {
		e := disablePrivilege("SeRestorePrivilege")
		if e != nil {
			err = errors.Join(err)
		}
	}()

	err = api.SetNamedSecurityInfo(
		name,
		api.SE_FILE_OBJECT,
		api.OWNER_SECURITY_INFORMATION|api.GROUP_SECURITY_INFORMATION,
		usid,
		gsid,
		0,
		0,
	)
	if err != nil {
		return err
	}
	return nil
}

func (ofs *OsFs) own(name string) (uid, gid string, err error) {
	name, _, err = ofs.followSymlinks(name)
	if err != nil {
		return "", "", err
	}
	return ofs.lown(name)
}

func (ofs *OsFs) lown(name string) (uid, gid string, err error) {
	var (
		secDesc windows.Handle
		owner   *windows.SID
		group   *windows.SID
	)
	err = api.GetNamedSecurityInfo(
		name,
		api.SE_FILE_OBJECT,
		api.OWNER_SECURITY_INFORMATION|api.GROUP_SECURITY_INFORMATION,
		&owner,
		&group,
		nil,
		nil,
		&secDesc,
	)
	if err != nil {
		return "", "", err
	}
	defer windows.LocalFree(secDesc)
	return owner.String(), group.String(), nil
}
