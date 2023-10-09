package osfs

import (
	"io/fs"
	"testing"

	"github.com/jxsl13/osfs/testutils"
	"github.com/stretchr/testify/require"
)

func TestIterateNonExistingDirTree(t *testing.T) {
	root := testutils.FilePath("testdata")
	ofs := New()

	err := iterateNotExistingDirTree(ofs, root, func(subdir string, fi fs.FileInfo) error {
		testutils.MustNotExist(t, ofs, subdir)
		return nil
	})
	require.NoError(t, err)
}
