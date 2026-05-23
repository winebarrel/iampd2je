//go:build !windows

package iampd2j_test

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/winebarrel/iampd2j"
)

func TestConvert_InPlacePreservesFileMode(t *testing.T) {
	dir := setupDir(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

resource "test" "x" {
  v = data.aws_iam_policy_document.p.json
}
`,
	})
	path := filepath.Join(dir, "main.tf")
	require.NoError(t, os.Chmod(path, 0o600))

	c := iampd2j.NewConverter(dir)
	c.Err = io.Discard
	require.NoError(t, c.Run(true))

	info, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}

func TestConvert_UnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read 0o000 files")
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "main.tf")
	require.NoError(t, os.WriteFile(p, []byte(`resource "x" "y" {}`), 0o644))
	require.NoError(t, os.Chmod(p, 0o000))
	t.Cleanup(func() { _ = os.Chmod(p, 0o644) })

	c := iampd2j.NewConverter(dir)
	c.Out = io.Discard
	c.Err = io.Discard
	err := c.Run(false)
	require.Error(t, err)
}
