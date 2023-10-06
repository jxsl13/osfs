package osfs

import (
	"io/fs"
	"os"
	"syscall"

	"github.com/jxsl13/osfs/fsi"
)

// used for mkdirAll
func iterateNotExistingDirTree(f fsi.Fs, path string, visitor func(subdir string, fi fs.FileInfo) error) (err error) {

	dir, err := f.Stat(path)
	if err == nil {
		if dir.IsDir() {
			return nil
		}
		return &fs.PathError{Op: "stat", Path: path, Err: syscall.ENOTDIR}
	}

	i := len(path)
	for i > 0 && os.IsPathSeparator(path[i-1]) { // Skip trailing path separator.
		i--
	}

	j := i
	for j > 0 && !os.IsPathSeparator(path[j-1]) { // Scan backward over element.
		j--
	}

	if j > 1 {
		// Create parent.
		err = iterateNotExistingDirTree(f, path[:j-1], visitor)
		if err != nil {
			return err
		}
	}

	// Parent now exists; invoke visitor and use its result.
	err = visitor(path, dir)
	if err != nil {
		return err
	}
	return nil
}
