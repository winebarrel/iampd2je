# iampd2j

[![CI](https://github.com/winebarrel/iampd2j/actions/workflows/ci.yml/badge.svg)](https://github.com/winebarrel/iampd2j/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/winebarrel/iampd2j/branch/main/graph/badge.svg)](https://codecov.io/gh/winebarrel/iampd2j)
[![AI Generated](https://img.shields.io/badge/AI%20Generated-Claude-orange?logo=anthropic)](https://claude.ai/claude-code)

`iampd2j` rewrites Terraform `data "aws_iam_policy_document" "<name>"` blocks as equivalent `jsonencode({ ... })` expressions, so the policy can be embedded inline (for example, in an `aws_iam_role_policy.policy` argument) without keeping the separate data source around.

## Installation

```
brew install winebarrel/iampd2j/iampd2j
```

## Usage

```
Usage: iampd2j [<files> ...] [flags]

Convert aws_iam_policy_document data sources to jsonencode() expressions.

Arguments:
  [<files> ...]    Terraform files to convert. Reads from stdin if no files are
                   given or "-" is passed.

Flags:
  -h, --help       Show help.
      --version
```

The converted policies are written to stdout. Each block is preceded by a `# <name>` comment so it can be located and pasted into the right place by hand. With no file arguments (or with `-`) the tool reads HCL from stdin, so it can be used as a filter (e.g. `cat policies.tf | iampd2j`).

## Example

```hcl
# policies.tf
data "aws_iam_policy_document" "bucket_read" {
  statement {
    sid     = "AllowReads"
    actions = ["s3:GetObject", "s3:ListBucket"]
    resources = [
      aws_s3_bucket.example.arn,
      "${aws_s3_bucket.example.arn}/*",
    ]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/example"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:username"
      values   = ["alice"]
    }
  }
}
```

```sh
iampd2j policies.tf
```

```hcl
# bucket_read
jsonencode({
  Version = "2012-10-17"
  Statement = [
    {
      Sid    = "AllowReads"
      Effect = "Allow"
      Action = ["s3:GetObject", "s3:ListBucket"]
      Resource = [
        aws_s3_bucket.example.arn,
        "${aws_s3_bucket.example.arn}/*",
      ]
      Principal = {
        AWS = ["arn:aws:iam::123456789012:role/example"]
      }
      Condition = {
        StringEquals = {
          "aws:username" = ["alice"]
        }
      }
    }
  ]
})
```

Notes:

- `version` defaults to `"2012-10-17"` and `effect` defaults to `"Allow"` when omitted in the data source, matching Terraform's defaults.
- Multiple `principals` blocks with the same `type` are merged into a single flat list. The same merging applies to `condition` blocks that share `test` + `variable`. List-literal `identifiers` / `values` only — references (e.g. `var.x`) make merging fail with an error rather than emit a `concat()`.
- Non-literal `principals.type`, `condition.test`, and `condition.variable` are spliced as HCL dynamic keys (`(var.x) = ...`), so configs that pass variables through these fields still convert cleanly.
- `source_policy_documents` and `override_policy_documents` are not converted; a warning is printed to stderr and the surrounding policy is still emitted so the merge can be re-done by hand.
- Blocks other than `data "aws_iam_policy_document"` in the input file are ignored.
