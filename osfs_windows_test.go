package osfs_test

import (
	"testing"

	"github.com/jxsl13/osfs/testutils"
	"github.com/stretchr/testify/require"
)

func TestChownVirtualAccount(t *testing.T) {
	defer func() {
		err := fs.RemoveAll(root)
		require.NoError(t, err)
	}()

	testutils.MkdirAll(t, fs, root, 0755)

}
