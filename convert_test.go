package iampd2j_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/winebarrel/iampd2j"
)

func TestConvert_Golden(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("testdata", "sample.tf"))
	require.NoError(t, err)
	want, err := os.ReadFile(filepath.Join("testdata", "sample.golden.tf"))
	require.NoError(t, err)

	var out, errOut bytes.Buffer
	c := &iampd2j.Converter{Out: &out, Err: &errOut}
	require.NoError(t, c.Convert(src, "sample.tf"))

	assert.Equal(t, string(want), out.String())
	assert.Empty(t, errOut.String())
}

func TestConvert_DefaultsAndSkipsOtherBlocks(t *testing.T) {
	src := []byte(`
resource "aws_s3_bucket" "ignored" {
  bucket = "x"
}

data "aws_caller_identity" "ignored" {}

data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}
`)
	var out bytes.Buffer
	c := &iampd2j.Converter{Out: &out}
	require.NoError(t, c.Convert(src, "in.tf"))

	got := out.String()
	assert.Contains(t, got, "# p")
	assert.Regexp(t, `Version\s*=\s*"2012-10-17"`, got)
	assert.Regexp(t, `Effect\s*=\s*"Allow"`, got)
	assert.NotContains(t, got, "aws_s3_bucket")
	assert.NotContains(t, got, "aws_caller_identity")
}

func TestConvert_PrincipalsMergeSameType(t *testing.T) {
	src := []byte(`
data "aws_iam_policy_document" "p" {
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
`)
	var out bytes.Buffer
	c := &iampd2j.Converter{Out: &out}
	require.NoError(t, c.Convert(src, "in.tf"))
	got := out.String()
	assert.Contains(t, got,
		`AWS = ["arn:aws:iam::111:role/a", "arn:aws:iam::222:role/b", "arn:aws:iam::222:role/c"]`)
	assert.NotContains(t, got, "concat(")
}

func TestConvert_PrincipalsMergeNonLiteralFails(t *testing.T) {
	src := []byte(`
data "aws_iam_policy_document" "p" {
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
`)
	var out bytes.Buffer
	c := &iampd2j.Converter{Out: &out}
	err := c.Convert(src, "in.tf")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list literals")
}

func TestConvert_PrincipalsMergeForExprFails(t *testing.T) {
	src := []byte(`
data "aws_iam_policy_document" "p" {
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
`)
	var out bytes.Buffer
	c := &iampd2j.Converter{Out: &out}
	err := c.Convert(src, "in.tf")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list literals")
}

func TestConvert_NotPrincipalsAndNotResources(t *testing.T) {
	src := []byte(`
data "aws_iam_policy_document" "p" {
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
`)
	var out bytes.Buffer
	c := &iampd2j.Converter{Out: &out}
	require.NoError(t, c.Convert(src, "in.tf"))
	got := out.String()
	assert.Regexp(t, `Effect\s*=\s*"Deny"`, got)
	assert.Contains(t, got, "NotResource")
	assert.Contains(t, got, "NotPrincipal")
}

func TestConvert_VersionAndPolicyIdOverride(t *testing.T) {
	src := []byte(`
data "aws_iam_policy_document" "p" {
  version   = "2008-10-17"
  policy_id = "custom-id"
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}
`)
	var out bytes.Buffer
	c := &iampd2j.Converter{Out: &out}
	require.NoError(t, c.Convert(src, "in.tf"))
	got := out.String()
	assert.Regexp(t, `Version\s*=\s*"2008-10-17"`, got)
	assert.Regexp(t, `Id\s*=\s*"custom-id"`, got)
}

func TestConvert_NoPolicyDocumentBlocks(t *testing.T) {
	src := []byte(`resource "aws_s3_bucket" "x" { bucket = "y" }`)
	var out bytes.Buffer
	c := &iampd2j.Converter{Out: &out}
	err := c.Convert(src, "in.tf")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no aws_iam_policy_document blocks")
	assert.Empty(t, out.String())
}

func TestConvert_ParseError(t *testing.T) {
	src := []byte(`data "aws_iam_policy_document" "p" {`) // unterminated
	var out bytes.Buffer
	c := &iampd2j.Converter{Out: &out}
	err := c.Convert(src, "in.tf")
	require.Error(t, err)
}

func TestConvert_SourcePolicyDocumentsWarns(t *testing.T) {
	src := []byte(`
data "aws_iam_policy_document" "p" {
  source_policy_documents = [data.aws_iam_policy_document.base.json]
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}
`)
	var out, errOut bytes.Buffer
	c := &iampd2j.Converter{Out: &out, Err: &errOut}
	require.NoError(t, c.Convert(src, "in.tf"))
	assert.Contains(t, errOut.String(), "source_policy_documents")
	assert.Contains(t, errOut.String(), "merge manually")
}

func TestConvert_OverridePolicyDocumentsWarns(t *testing.T) {
	src := []byte(`
data "aws_iam_policy_document" "p" {
  override_policy_documents = [data.aws_iam_policy_document.base.json]
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}
`)
	var out, errOut bytes.Buffer
	c := &iampd2j.Converter{Out: &out, Err: &errOut}
	require.NoError(t, c.Convert(src, "in.tf"))
	assert.Contains(t, errOut.String(), "override_policy_documents")
}

func TestConvert_PrincipalBlockMissingFields(t *testing.T) {
	src := []byte(`
data "aws_iam_policy_document" "p" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type = "AWS"
    }
  }
}
`)
	var out bytes.Buffer
	c := &iampd2j.Converter{Out: &out}
	err := c.Convert(src, "in.tf")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "type and identifiers")
}

func TestConvert_ConditionMergeSameTestAndVariable(t *testing.T) {
	src := []byte(`
data "aws_iam_policy_document" "p" {
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
`)
	var out bytes.Buffer
	c := &iampd2j.Converter{Out: &out}
	require.NoError(t, c.Convert(src, "in.tf"))
	got := out.String()
	assert.Contains(t, got, `"aws:username" = ["alice", "bob", "carol"]`)
	assert.Equal(t, 1, strings.Count(got, `"aws:username"`),
		"duplicate variable keys must be merged into one")
}

func TestConvert_ConditionMergeNonLiteralFails(t *testing.T) {
	src := []byte(`
data "aws_iam_policy_document" "p" {
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
`)
	var out bytes.Buffer
	c := &iampd2j.Converter{Out: &out}
	err := c.Convert(src, "in.tf")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list literals")
}

func TestConvert_ConditionBlockMissingFields(t *testing.T) {
	src := []byte(`
data "aws_iam_policy_document" "p" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
    condition {
      test = "StringEquals"
    }
  }
}
`)
	var out bytes.Buffer
	c := &iampd2j.Converter{Out: &out}
	err := c.Convert(src, "in.tf")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "test, variable, and values")
}

func TestNewConverter_Defaults(t *testing.T) {
	c := iampd2j.NewConverter()
	require.NotNil(t, c)
	assert.NotNil(t, c.Out)
	assert.NotNil(t, c.Err)
}
