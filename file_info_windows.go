package osfs

import (
	"io/fs"
	"time"
)

var _ fs.FileInfo = (*winInfo)(nil)

type winInfo struct {
	fi      fs.FileInfo
	aclMode fs.FileMode
}

// newWinInfo creates a file info wrapper for windows.
// The wrapper uses acl permissions for its mode permission bits
func newWinInfo(fi fs.FileInfo, aclMode fs.FileMode) *winInfo {
	return &winInfo{
		fi:      fi,
		aclMode: aclMode,
	}
}

func (i *winInfo) Name() string {
	return i.fi.Name()
}

func (i *winInfo) Size() int64 {
	return i.fi.Size()
}

func (i *winInfo) Mode() fs.FileMode {
	const invPermMask = ^fs.ModePerm
	return (i.fi.Mode() & invPermMask) | (i.aclMode & fs.ModePerm)
}

func (i *winInfo) ModTime() time.Time {
	return i.fi.ModTime()
}

func (i *winInfo) IsDir() bool {
	return i.Mode().IsDir()
}

func (i *winInfo) Sys() any {
	return i.fi.Sys()
}
