package osfs_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jxsl13/osfs"
	"github.com/jxsl13/osfs/testutils"
	"github.com/stretchr/testify/require"
)

var (
	root = testutils.FilePath("testdata")
	fs   = osfs.New()
)

func TestMain(m *testing.M) {
	rc := m.Run()
	os.Exit(rc)
}

func initTestDataDir(t *testing.T) (closer func()) {
	err := fs.MkdirAll(root, 0755)
	require.NoError(t, err)
	return func() {
		testutils.RemoveAll(t, fs, root)
	}
}

func TestCreate(t *testing.T) {
	close := initTestDataDir(t)
	defer close()

	name := filepath.Join(root, "test01.txt")
	testutils.CreateFile(t, fs, name, testutils.StackTraceString())
}

func TestChmod(t *testing.T) {
	close := initTestDataDir(t)
	defer close()

	name := filepath.Join(root, "test02.txt")
	testutils.CreateFile(t, fs, name, testutils.StackTraceString())

	testutils.Chmod(t, fs, name, 0755)
}

func TestOsFs(t *testing.T) {
	close := initTestDataDir(t)
	defer close()
}
