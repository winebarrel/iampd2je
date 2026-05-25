package iampd2j_test

import (
	"bytes"
	"errors"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/winebarrel/iampd2j"
)

// setupDir writes the given files to a fresh temp directory and returns its path.
func setupDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644))
	}
	return dir
}

// run executes Converter.Run in non-in-place mode and returns its captured streams.
func run(t *testing.T, files map[string]string) (out, errOut string, err error) {
	t.Helper()
	dir := setupDir(t, files)
	var outBuf, errBuf bytes.Buffer
	c := iampd2j.NewConverter(dir)
	c.Out = &outBuf
	c.Err = &errBuf
	err = c.Run(false)
	return outBuf.String(), errBuf.String(), err
}

func TestConvert_Golden(t *testing.T) {
	inSrc, err := os.ReadFile(filepath.Join("testdata", "sample.tf"))
	require.NoError(t, err)
	wantBytes, err := os.ReadFile(filepath.Join("testdata", "sample.golden.tf"))
	require.NoError(t, err)

	dir := t.TempDir()
	p := filepath.Join(dir, "sample.tf")
	require.NoError(t, os.WriteFile(p, inSrc, 0o644))

	var errOut bytes.Buffer
	c := iampd2j.NewConverter(dir)
	c.Err = &errOut
	require.NoError(t, c.Run(true))

	got, err := os.ReadFile(p)
	require.NoError(t, err)
	assert.Equal(t, string(wantBytes), string(got))
	assert.Empty(t, errOut.String())
}

func TestConvert_StdoutHasFileHeader(t *testing.T) {
	out, _, err := run(t, map[string]string{
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
	require.NoError(t, err)
	assert.Contains(t, out, "### ")
	assert.Contains(t, out, "main.tf ###")
	assert.Contains(t, out, "jsonencode({")
}

func TestConvert_DataBlockRemovedAndRefReplaced(t *testing.T) {
	out, _, err := run(t, map[string]string{
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
	require.NoError(t, err)
	assert.NotContains(t, out, `data "aws_iam_policy_document"`)
	assert.NotContains(t, out, "data.aws_iam_policy_document.p.json")
	assert.Contains(t, out, "jsonencode({")
}

func TestConvert_RefAcrossFiles(t *testing.T) {
	out, _, err := run(t, map[string]string{
		"policies.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}
`,
		"main.tf": `resource "test" "x" {
  v = data.aws_iam_policy_document.p.json
}
`,
	})
	require.NoError(t, err)
	assert.Contains(t, out, "main.tf ###")
	assert.Contains(t, out, "policies.tf ###")
	assert.Contains(t, out, "jsonencode({")
}

func TestConvert_OtherDataBlocksUntouched(t *testing.T) {
	out, _, err := run(t, map[string]string{
		"main.tf": `resource "aws_s3_bucket" "ignored" {
  bucket = "x"
}

data "aws_caller_identity" "ignored" {}

data "aws_iam_policy_document" "p" {
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
	require.NoError(t, err)
	assert.Contains(t, out, `resource "aws_s3_bucket" "ignored"`)
	assert.Contains(t, out, `data "aws_caller_identity" "ignored"`)
	assert.Regexp(t, `Version\s*=\s*"2012-10-17"`, out)
	assert.Regexp(t, `Effect\s*=\s*"Allow"`, out)
}

func TestConvert_PrincipalsMergeSameType(t *testing.T) {
	out, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::111:role/a"]
    }
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::222:role/b", "arn:aws:iam::222:role/c"]
    }
  }
}

resource "test" "x" {
  v = data.aws_iam_policy_document.p.json
}
`,
	})
	require.NoError(t, err)
	assert.Contains(t, out,
		`AWS = ["arn:aws:iam::111:role/a", "arn:aws:iam::222:role/b", "arn:aws:iam::222:role/c"]`)
	assert.NotContains(t, out, "concat(")
}

func TestConvert_PrincipalsMergeNonLiteralFails(t *testing.T) {
	_, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = var.role_arns
    }
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::222:role/b"]
    }
  }
}
`,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list literals")
}

func TestConvert_PrincipalsMergeForExprFails(t *testing.T) {
	_, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = [for r in var.roles : r.arn]
    }
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::222:role/b"]
    }
  }
}
`,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list literals")
}

func TestConvert_PrincipalTypeDynamicKey(t *testing.T) {
	out, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = var.principal_type
      identifiers = ["arn:aws:iam::111:role/a"]
    }
  }
}

resource "test" "x" {
  v = data.aws_iam_policy_document.p.json
}
`,
	})
	require.NoError(t, err)
	assert.Contains(t, out, `(var.principal_type) = "arn:aws:iam::111:role/a"`)
}

func TestConvert_PrincipalTypeMixedLiteralAndDynamic(t *testing.T) {
	out, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::111:role/a"]
    }
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::222:role/b"]
    }
    principals {
      type        = var.extra_type
      identifiers = ["arn:aws:iam::333:role/c"]
    }
  }
}

resource "test" "x" {
  v = data.aws_iam_policy_document.p.json
}
`,
	})
	require.NoError(t, err)
	assert.Regexp(t,
		`AWS\s*=\s*\["arn:aws:iam::111:role/a", "arn:aws:iam::222:role/b"\]`, out)
	assert.Contains(t, out, `(var.extra_type) = "arn:aws:iam::333:role/c"`)
}

func TestConvert_ConditionTestAndVariableDynamicKey(t *testing.T) {
	out, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
    condition {
      test     = var.cond_test
      variable = var.cond_var
      values   = ["x"]
    }
  }
}

resource "test" "x" {
  v = data.aws_iam_policy_document.p.json
}
`,
	})
	require.NoError(t, err)
	assert.Contains(t, out, "(var.cond_test) = {")
	assert.Contains(t, out, `(var.cond_var) = "x"`)
}

func TestConvert_EmptyStatementListEmitted(t *testing.T) {
	out, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  policy_id = "empty"
}

resource "test" "x" {
  v = data.aws_iam_policy_document.p.json
}
`,
	})
	require.NoError(t, err)
	assert.Regexp(t, `Statement\s*=\s*\[\s*\]`, out)
}

func TestConvert_ErrorIncludesFilenameAndPolicyName(t *testing.T) {
	_, _, err := run(t, map[string]string{
		"policies.tf": `data "aws_iam_policy_document" "broken" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = var.first
    }
    principals {
      type        = "AWS"
      identifiers = var.second
    }
  }
}
`,
	})
	require.Error(t, err)
	msg := err.Error()
	assert.Contains(t, msg, "policies.tf")
	assert.Contains(t, msg, "broken")
}

func TestConvert_NotPrincipalsAndNotResources(t *testing.T) {
	out, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    effect        = "Deny"
    actions       = ["s3:*"]
    not_resources = ["arn:aws:s3:::safe/*"]
    not_principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::111:role/admin"]
    }
  }
}

resource "test" "x" {
  v = data.aws_iam_policy_document.p.json
}
`,
	})
	require.NoError(t, err)
	assert.Regexp(t, `Effect\s*=\s*"Deny"`, out)
	assert.Contains(t, out, "NotResource")
	assert.Contains(t, out, "NotPrincipal")
}

func TestConvert_VersionAndPolicyIdOverride(t *testing.T) {
	out, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  version   = "2008-10-17"
  policy_id = "custom-id"
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
	require.NoError(t, err)
	assert.Regexp(t, `Version\s*=\s*"2008-10-17"`, out)
	assert.Regexp(t, `Id\s*=\s*"custom-id"`, out)
}

func TestConvert_NoPolicyDocumentBlocks_NoOp(t *testing.T) {
	out, errOut, err := run(t, map[string]string{
		"main.tf": `resource "aws_s3_bucket" "x" { bucket = "y" }`,
	})
	require.NoError(t, err)
	assert.Empty(t, out)
	assert.Empty(t, errOut)
}

func TestConvert_ParseError(t *testing.T) {
	_, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {`, // unterminated
	})
	require.Error(t, err)
}

func TestConvert_SourcePolicyDocumentsWarnsAndKeepsBlock(t *testing.T) {
	src := `data "aws_iam_policy_document" "merged_policy" {
  source_policy_documents = [data.aws_iam_policy_document.base.json]
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

resource "test" "x" {
  v = data.aws_iam_policy_document.merged_policy.json
}
`
	dir := setupDir(t, map[string]string{"policies.tf": src})
	var outBuf, errBuf bytes.Buffer
	c := iampd2j.NewConverter(dir)
	c.Out = &outBuf
	c.Err = &errBuf
	require.NoError(t, c.Run(true))

	assert.Contains(t, errBuf.String(), "source_policy_documents")
	assert.Contains(t, errBuf.String(), "merge manually")
	assert.Contains(t, errBuf.String(), "policies.tf")
	assert.Contains(t, errBuf.String(), "merged_policy")
	// the data block and reference are kept on disk
	body, err := os.ReadFile(filepath.Join(dir, "policies.tf"))
	require.NoError(t, err)
	got := string(body)
	assert.Contains(t, got, `data "aws_iam_policy_document" "merged_policy"`)
	assert.Contains(t, got, "data.aws_iam_policy_document.merged_policy.json")
	assert.NotContains(t, got, "jsonencode({")
}

func TestConvert_OverridePolicyDocumentsWarnsAndKeepsBlock(t *testing.T) {
	src := `data "aws_iam_policy_document" "overridden_policy" {
  override_policy_documents = [data.aws_iam_policy_document.base.json]
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

resource "test" "x" {
  v = data.aws_iam_policy_document.overridden_policy.json
}
`
	dir := setupDir(t, map[string]string{"policies.tf": src})
	var errBuf bytes.Buffer
	c := iampd2j.NewConverter(dir)
	c.Err = &errBuf
	require.NoError(t, c.Run(true))

	assert.Contains(t, errBuf.String(), "override_policy_documents")
	assert.Contains(t, errBuf.String(), "policies.tf")
	assert.Contains(t, errBuf.String(), "overridden_policy")
	body, err := os.ReadFile(filepath.Join(dir, "policies.tf"))
	require.NoError(t, err)
	got := string(body)
	assert.Contains(t, got, `data "aws_iam_policy_document" "overridden_policy"`)
	assert.NotContains(t, got, "jsonencode({")
}

func TestConvert_BareRefKeepsBlock(t *testing.T) {
	// A bare data.aws_iam_policy_document.p reference (no .json) is a
	// legitimate Terraform pattern (e.g. depends_on). The block must be
	// kept so the reference still resolves.
	src := `data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

resource "test" "x" {
  depends_on = [data.aws_iam_policy_document.p]
}
`
	dir := setupDir(t, map[string]string{"main.tf": src})
	c := iampd2j.NewConverter(dir)
	c.Err = io.Discard
	require.NoError(t, c.Run(true))

	body, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	require.NoError(t, err)
	got := string(body)
	assert.Contains(t, got, `data "aws_iam_policy_document" "p"`)
	assert.Contains(t, got, "depends_on = [data.aws_iam_policy_document.p]")
	assert.NotContains(t, got, "jsonencode({")
}

func TestConvert_BareRefAndJSONRef(t *testing.T) {
	// Combined: an external .json ref still gets inlined, but the bare ref
	// elsewhere keeps the data block in place so the bare ref still works.
	src := `data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

resource "a" "x" { v = data.aws_iam_policy_document.p.json }

resource "b" "x" {
  depends_on = [data.aws_iam_policy_document.p]
}
`
	dir := setupDir(t, map[string]string{"main.tf": src})
	c := iampd2j.NewConverter(dir)
	c.Err = io.Discard
	require.NoError(t, c.Run(true))

	body, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	require.NoError(t, err)
	got := string(body)
	assert.Contains(t, got, `data "aws_iam_policy_document" "p"`)
	assert.Contains(t, got, "jsonencode({")
	assert.Contains(t, got, "depends_on = [data.aws_iam_policy_document.p]")
}

func TestConvert_MixedJSONAndMinifiedRef(t *testing.T) {
	// When both .json and .minified_json refer to the same policy, the .json
	// site is still replaced with jsonencode but the data block stays so that
	// the .minified_json site keeps resolving.
	src := `data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

resource "a" "x" { v = data.aws_iam_policy_document.p.json }
resource "b" "x" { v = data.aws_iam_policy_document.p.minified_json }
`
	dir := setupDir(t, map[string]string{"main.tf": src})
	var errBuf bytes.Buffer
	c := iampd2j.NewConverter(dir)
	c.Err = &errBuf
	require.NoError(t, c.Run(true))

	body, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	require.NoError(t, err)
	got := string(body)
	assert.Contains(t, errBuf.String(), "minified_json")
	assert.Contains(t, got, `data "aws_iam_policy_document" "p"`)
	assert.Contains(t, got, "jsonencode({")
	assert.Contains(t, got, "data.aws_iam_policy_document.p.minified_json")
	assert.NotContains(t, got, "data.aws_iam_policy_document.p.json\n")
}

func TestConvert_SourcePolicyDocumentsChainedJSONKeepsBoth(t *testing.T) {
	// merged is non-convertible (source_policy_documents). Its body contains
	// data.base.json, so base must be kept even though base is convertible
	// and only otherwise referenced via .json.
	src := `data "aws_iam_policy_document" "base" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "merged" {
  source_policy_documents = [data.aws_iam_policy_document.base.json]
  statement {
    actions   = ["s3:PutObject"]
    resources = ["*"]
  }
}

resource "r" "x" { v = data.aws_iam_policy_document.merged.json }
`
	dir := setupDir(t, map[string]string{"main.tf": src})
	c := iampd2j.NewConverter(dir)
	c.Err = io.Discard
	require.NoError(t, c.Run(true))

	body, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	require.NoError(t, err)
	got := string(body)
	assert.Contains(t, got, `data "aws_iam_policy_document" "base"`)
	assert.Contains(t, got, `data "aws_iam_policy_document" "merged"`)
	assert.Contains(t, got, "data.aws_iam_policy_document.base.json")
	assert.Contains(t, got, "data.aws_iam_policy_document.merged.json")
}

func TestConvert_SourcePolicyDocumentsChainedMinifiedKeepsBoth(t *testing.T) {
	src := `data "aws_iam_policy_document" "base" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "merged" {
  source_policy_documents = [data.aws_iam_policy_document.base.minified_json]
  statement {
    actions   = ["s3:PutObject"]
    resources = ["*"]
  }
}

resource "r" "x" { v = data.aws_iam_policy_document.merged.json }
`
	dir := setupDir(t, map[string]string{"main.tf": src})
	c := iampd2j.NewConverter(dir)
	c.Err = io.Discard
	require.NoError(t, c.Run(true))

	body, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	require.NoError(t, err)
	got := string(body)
	assert.Contains(t, got, `data "aws_iam_policy_document" "base"`)
	assert.Contains(t, got, `data "aws_iam_policy_document" "merged"`)
}

func TestConvert_RemovableXReferencesYKeepsY(t *testing.T) {
	// X is convertible and gets removed; its statement.resources references
	// data.Y.json which ends up spliced at the external .json reference site.
	// Y must therefore be kept.
	src := `data "aws_iam_policy_document" "y" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "x" {
  statement {
    actions   = ["s3:PutObject"]
    resources = [data.aws_iam_policy_document.y.json]
  }
}

resource "r" "x" { v = data.aws_iam_policy_document.x.json }
`
	dir := setupDir(t, map[string]string{"main.tf": src})
	c := iampd2j.NewConverter(dir)
	c.Err = io.Discard
	require.NoError(t, c.Run(true))

	body, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	require.NoError(t, err)
	got := string(body)
	// x is removed (no surviving non-.json refs to x outside the policy doc)
	assert.NotContains(t, got, `data "aws_iam_policy_document" "x"`)
	// y is kept because the spliced jsonencode for x still references y.json
	assert.Contains(t, got, `data "aws_iam_policy_document" "y"`)
	// the spliced jsonencode appears at the external ref site
	assert.Contains(t, got, "jsonencode({")
	assert.Contains(t, got, "data.aws_iam_policy_document.y.json")
}

func TestConvert_NonJSONRefWarnsAndKeepsBlock(t *testing.T) {
	src := `data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

resource "test" "x" {
  v = data.aws_iam_policy_document.p.minified_json
}
`
	dir := setupDir(t, map[string]string{"main.tf": src})
	var errBuf bytes.Buffer
	c := iampd2j.NewConverter(dir)
	c.Err = &errBuf
	require.NoError(t, c.Run(true))

	assert.Contains(t, errBuf.String(), "minified_json")
	body, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	require.NoError(t, err)
	got := string(body)
	assert.Contains(t, got, `data "aws_iam_policy_document" "p"`)
	assert.Contains(t, got, "data.aws_iam_policy_document.p.minified_json")
	assert.NotContains(t, got, "jsonencode({")
}

func TestConvert_NoReferencesStillRemovesBlock(t *testing.T) {
	// A dead policy with no references is still removed once it is
	// successfully convertible.
	out, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}
`,
	})
	require.NoError(t, err)
	assert.NotContains(t, out, `data "aws_iam_policy_document" "p"`)
}

func TestConvert_DuplicatePolicyNameFails(t *testing.T) {
	_, _, err := run(t, map[string]string{
		"a.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}
`,
		"b.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:PutObject"]
    resources = ["*"]
  }
}
`,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate")
}

func TestConvert_ConditionVariableWithDollarSign(t *testing.T) {
	out, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:foo$bar"
      values   = ["x"]
    }
  }
}

resource "test" "x" {
  v = data.aws_iam_policy_document.p.json
}
`,
	})
	require.NoError(t, err)
	assert.Contains(t, out, `"aws:foo$bar" = "x"`)
}

func TestConvert_PrincipalBlockMissingFields(t *testing.T) {
	_, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "AWS"
    }
  }
}
`,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type and identifiers")
}

func TestConvert_ConditionMergeSameTestAndVariable(t *testing.T) {
	out, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:username"
      values   = ["alice"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:username"
      values   = ["bob", "carol"]
    }
  }
}

resource "test" "x" {
  v = data.aws_iam_policy_document.p.json
}
`,
	})
	require.NoError(t, err)
	assert.Contains(t, out, `"aws:username" = ["alice", "bob", "carol"]`)
	assert.Equal(t, 1, strings.Count(out, `"aws:username"`),
		"duplicate variable keys must be merged into one")
}

func TestConvert_ConditionMergeNonLiteralFails(t *testing.T) {
	_, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:username"
      values   = var.users
    }
    condition {
      test     = "StringEquals"
      variable = "aws:username"
      values   = ["bob"]
    }
  }
}
`,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list literals")
}

func TestConvert_ConditionBlockMissingFields(t *testing.T) {
	_, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
    condition {
      test = "StringEquals"
    }
  }
}
`,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "test, variable, and values")
}

func TestNewConverter_Defaults(t *testing.T) {
	c := iampd2j.NewConverter("/tmp")
	require.NotNil(t, c)
	assert.NotNil(t, c.Out)
	assert.NotNil(t, c.Err)
	assert.Equal(t, "/tmp", c.Dir)
}

func TestConvert_ZeroValueConverterDefaults(t *testing.T) {
	// Confirm that a zero-value Converter still works (initializes defaults).
	dir := setupDir(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {`, // parse error → exits before any writes
	})
	c := &iampd2j.Converter{Dir: dir}
	err := c.Run(false)
	require.Error(t, err)
	assert.Same(t, os.Stdout, c.Out)
	assert.Same(t, os.Stderr, c.Err)
}

func TestConvert_NonStatementBlockSkipped(t *testing.T) {
	dir := setupDir(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  unknown_block {
    foo = "bar"
  }
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
	var outBuf bytes.Buffer
	c := iampd2j.NewConverter(dir)
	c.Out = &outBuf
	c.Err = io.Discard
	require.NoError(t, c.Run(false))
	got := outBuf.String()
	assert.NotContains(t, got, "unknown_block")
	assert.Regexp(t, `Action\s*=\s*"s3:GetObject"`, got)
}

func TestConvert_NotPrincipalsMergeNonLiteralFails(t *testing.T) {
	_, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    effect  = "Deny"
    actions = ["s3:*"]
    not_principals {
      type        = "AWS"
      identifiers = var.first
    }
    not_principals {
      type        = "AWS"
      identifiers = var.second
    }
  }
}
`,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not_principals.identifiers")
}

func TestConvert_EmptyStringKeyIsQuoted(t *testing.T) {
	out, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = ""
      identifiers = ["arn:aws:iam::111:role/a"]
    }
  }
}

resource "test" "x" {
  v = data.aws_iam_policy_document.p.json
}
`,
	})
	require.NoError(t, err)
	assert.Contains(t, out, `"" = "arn:aws:iam::111:role/a"`)
}

func TestConvert_NonIdentifierKeyIsQuoted(t *testing.T) {
	out, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "1Custom"
      identifiers = ["arn:aws:iam::111:role/a"]
    }
  }
}

resource "test" "x" {
  v = data.aws_iam_policy_document.p.json
}
`,
	})
	require.NoError(t, err)
	assert.Contains(t, out, `"1Custom" = "arn:aws:iam::111:role/a"`)
}

func TestConvert_VerboseLogsTouchedFiles(t *testing.T) {
	// Verbose=true exercises the log.Printf branches we otherwise skip; run
	// it through and make sure nothing panics. We capture log output to keep
	// the test output clean.
	var logBuf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logBuf)
	t.Cleanup(func() { log.SetOutput(prev) })

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
	c := iampd2j.NewConverter(dir)
	c.Err = io.Discard
	c.Verbose = true
	require.NoError(t, c.Run(true))
	logged := logBuf.String()
	assert.Contains(t, logged, "inline data.aws_iam_policy_document.p.json")
	assert.Contains(t, logged, "remove data.aws_iam_policy_document.p")
	assert.Contains(t, logged, "rewrote")
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("boom") }

func TestConvert_WriteErrorPropagates(t *testing.T) {
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
	c := iampd2j.NewConverter(dir)
	c.Out = failWriter{}
	c.Err = io.Discard
	err := c.Run(false)
	require.Error(t, err)
}

func TestConvert_WarnsForNonJSONInsidePolicyDoc(t *testing.T) {
	// A non-`.json` accessor inside another policy doc body must still
	// produce the unsupported-accessor warning. The reference also keeps
	// the target's block in place.
	src := `data "aws_iam_policy_document" "outer" {
  statement {
    actions   = ["s3:GetObject"]
    resources = [data.aws_iam_policy_document.inner.minified_json]
  }
}

data "aws_iam_policy_document" "inner" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

resource "r" "x" { v = data.aws_iam_policy_document.outer.json }
`
	dir := setupDir(t, map[string]string{"main.tf": src})
	var errBuf bytes.Buffer
	c := iampd2j.NewConverter(dir)
	c.Err = &errBuf
	require.NoError(t, c.Run(true))
	assert.Contains(t, errBuf.String(), "minified_json")
	assert.Contains(t, errBuf.String(), "is not supported")

	body, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	require.NoError(t, err)
	got := string(body)
	assert.Contains(t, got, `data "aws_iam_policy_document" "inner"`)
}

func TestConvert_WarnsForNonJSONEvenWhenAlreadyKept(t *testing.T) {
	// outer's body references inner.json from inside, which silently sets
	// inner.keepBlock=true (via the inPolicyDoc branch). An external
	// `.minified_json` ref to inner must still produce the warning,
	// independent of scan order.
	src := `data "aws_iam_policy_document" "outer" {
  statement {
    actions   = ["s3:GetObject"]
    resources = [data.aws_iam_policy_document.inner.json]
  }
}

data "aws_iam_policy_document" "inner" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

resource "r" "x" { v = data.aws_iam_policy_document.inner.minified_json }
resource "r" "y" { v = data.aws_iam_policy_document.outer.json }
`
	dir := setupDir(t, map[string]string{"main.tf": src})
	var errBuf bytes.Buffer
	c := iampd2j.NewConverter(dir)
	c.Err = &errBuf
	require.NoError(t, c.Run(true))
	assert.Contains(t, errBuf.String(), "minified_json")
	assert.Contains(t, errBuf.String(), "is not supported")
}

func TestConvert_NonJSONWarningEmittedOnce(t *testing.T) {
	src := `data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

resource "a" "x" { v = data.aws_iam_policy_document.p.minified_json }
resource "b" "x" { v = data.aws_iam_policy_document.p.minified_json }
resource "c" "x" { v = data.aws_iam_policy_document.p.override_json }
`
	dir := setupDir(t, map[string]string{"main.tf": src})
	var errBuf bytes.Buffer
	c := iampd2j.NewConverter(dir)
	c.Err = &errBuf
	require.NoError(t, c.Run(true))
	// Even with multiple unsupported accessors, the warning is emitted at
	// most once per policy.
	assert.Equal(t, 1, strings.Count(errBuf.String(), "is not supported"))
}

func TestConvert_EmptyDirDefaultsToCWD(t *testing.T) {
	dir := setupDir(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

resource "test" "x" { v = data.aws_iam_policy_document.p.json }
`,
	})
	t.Chdir(dir)

	c := &iampd2j.Converter{} // zero-value, no Dir
	c.Err = io.Discard
	require.NoError(t, c.Run(true))
	assert.Equal(t, ".", c.Dir)

	body, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	require.NoError(t, err)
	assert.Contains(t, string(body), "jsonencode({")
}

func TestConvert_MissingDirReturnsError(t *testing.T) {
	c := iampd2j.NewConverter(filepath.Join(t.TempDir(), "does-not-exist"))
	c.Err = io.Discard
	c.Out = io.Discard
	err := c.Run(false)
	require.Error(t, err)
}

func TestConvert_DirIsAFileReturnsError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "not-a-dir")
	require.NoError(t, os.WriteFile(p, []byte("hi"), 0o644))
	c := iampd2j.NewConverter(p)
	c.Err = io.Discard
	c.Out = io.Discard
	err := c.Run(false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a directory")
}

func TestConvert_RunIsReusable(t *testing.T) {
	// Reuse the same Converter for two independent directories. State from
	// the first run must not leak into the second.
	dir1 := setupDir(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

resource "test" "x" { v = data.aws_iam_policy_document.p.json }
`,
	})
	dir2 := setupDir(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:PutObject"]
    resources = ["*"]
  }
}

resource "test" "y" { v = data.aws_iam_policy_document.p.json }
`,
	})

	c := iampd2j.NewConverter(dir1)
	c.Err = io.Discard
	c.Out = io.Discard
	require.NoError(t, c.Run(true))

	c.Dir = dir2
	require.NoError(t, c.Run(true), "second Run must not see policies from the first run as duplicates")

	body, err := os.ReadFile(filepath.Join(dir2, "main.tf"))
	require.NoError(t, err)
	got := string(body)
	assert.Contains(t, got, "s3:PutObject")
	assert.NotContains(t, got, `data "aws_iam_policy_document"`)
}

func TestConvert_InPlaceWritesFiles(t *testing.T) {
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
	c := iampd2j.NewConverter(dir)
	c.Err = io.Discard
	require.NoError(t, c.Run(true))
	body, err := os.ReadFile(filepath.Join(dir, "main.tf"))
	require.NoError(t, err)
	got := string(body)
	assert.NotContains(t, got, `data "aws_iam_policy_document"`)
	assert.Contains(t, got, "jsonencode({")
}

func TestConvert_SingletonTupleUnwrappedAcrossFields(t *testing.T) {
	// aws_iam_policy_document renders single-element lists as scalars in the
	// resulting JSON. The conversion mirrors that for actions, resources,
	// principal identifiers, and condition values when they're tuple literals.
	out, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions       = ["s3:GetObject"]
    not_actions   = ["s3:DeleteObject"]
    resources     = ["arn:aws:s3:::b/*"]
    not_resources = ["arn:aws:s3:::other/*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::111:role/a"]
    }
    not_principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:username"
      values   = ["alice"]
    }
  }
}

resource "test" "x" {
  v = data.aws_iam_policy_document.p.json
}
`,
	})
	require.NoError(t, err)
	assert.Regexp(t, `Action\s*=\s*"s3:GetObject"`, out)
	assert.Regexp(t, `NotAction\s*=\s*"s3:DeleteObject"`, out)
	assert.Regexp(t, `Resource\s*=\s*"arn:aws:s3:::b/\*"`, out)
	assert.Regexp(t, `NotResource\s*=\s*"arn:aws:s3:::other/\*"`, out)
	assert.Regexp(t, `AWS\s*=\s*"arn:aws:iam::111:role/a"`, out)
	assert.Regexp(t, `Service\s*=\s*"s3\.amazonaws\.com"`, out)
	assert.Contains(t, out, `"aws:username" = "alice"`)
}

func TestConvert_MultiElementTupleNotUnwrapped(t *testing.T) {
	// Two or more elements stay as a list — only single-element tuple
	// literals are unwrapped.
	out, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = ["*"]
  }
}

resource "test" "x" {
  v = data.aws_iam_policy_document.p.json
}
`,
	})
	require.NoError(t, err)
	assert.Regexp(t, `Action\s*=\s*\["s3:GetObject", "s3:ListBucket"\]`, out)
	assert.Regexp(t, `Resource\s*=\s*"\*"`, out)
}

func TestConvert_NonLiteralExpressionsNotUnwrapped(t *testing.T) {
	// References, function calls, and for-expressions can't be evaluated
	// statically — we can't know their length, so leave them as written.
	out, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions   = var.actions
    resources = concat(["a"], var.extra)
    condition {
      test     = "StringEquals"
      variable = "aws:username"
      values   = [for u in var.users : u.name]
    }
  }
}

resource "test" "x" {
  v = data.aws_iam_policy_document.p.json
}
`,
	})
	require.NoError(t, err)
	assert.Regexp(t, `Action\s*=\s*var\.actions`, out)
	assert.Regexp(t, `Resource\s*=\s*concat\(\["a"\], var\.extra\)`, out)
	assert.Contains(t, out, `"aws:username" = [for u in var.users : u.name]`)
}

func TestConvert_EmptyTupleNotUnwrapped(t *testing.T) {
	// An empty list isn't a single-element tuple, so it stays `[]`. (This is
	// a weird input that real configs wouldn't write, but the unwrap rule
	// should be conservative.)
	out, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions   = []
    resources = ["*"]
  }
}

resource "test" "x" {
  v = data.aws_iam_policy_document.p.json
}
`,
	})
	require.NoError(t, err)
	assert.Regexp(t, `Action\s*=\s*\[\]`, out)
}

func TestConvert_MergedDownToOneElementIsUnwrapped(t *testing.T) {
	// Multiple principals blocks of the same type get merged. If the merged
	// result is exactly one identifier, unwrap it to a scalar.
	out, _, err := run(t, map[string]string{
		"main.tf": `data "aws_iam_policy_document" "p" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::111:role/a"]
    }
    principals {
      type        = "AWS"
      identifiers = []
    }
  }
}

resource "test" "x" {
  v = data.aws_iam_policy_document.p.json
}
`,
	})
	require.NoError(t, err)
	assert.Regexp(t, `AWS\s*=\s*"arn:aws:iam::111:role/a"`, out)
}
