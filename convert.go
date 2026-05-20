package iampd2j

import (
	"errors"
	"fmt"
	"io"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclwrite"
)

func Convert(src []byte, filename string, out io.Writer) error {
	f, diags := hclwrite.ParseConfig(src, filename, hcl.Pos{Line: 1, Column: 1})
	if diags.HasErrors() {
		return errors.Join(diags.Errs()...)
	}

	for _, block := range f.Body().Blocks() {
		// TODO:
		// メモ: ブロック処理切り出す・orderedmapつかう
		fmt.Println(block)
	}

	return nil
}
