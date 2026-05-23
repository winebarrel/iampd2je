# iampd2j

[![CI](https://github.com/winebarrel/iampd2j/actions/workflows/ci.yml/badge.svg)](https://github.com/winebarrel/iampd2j/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/winebarrel/iampd2j/branch/main/graph/badge.svg)](https://codecov.io/gh/winebarrel/iampd2j)
[![AI Generated](https://img.shields.io/badge/AI%20Generated-Claude-orange?logo=anthropic)](https://claude.ai/claude-code)

`iampd2j` inlines Terraform `data "aws_iam_policy_document" "<name>"` blocks as `jsonencode({ ... })` expressions. Wherever the policy is referenced via `data.aws_iam_policy_document.<name>.json` across the `*.tf` files in a directory, the reference is replaced with the equivalent `jsonencode(...)` and the original data block is removed.

## Installation

```
brew install winebarrel/iampd2j/iampd2j
```

## Usage

```
Usage: iampd2j [<dir>] [flags]

Inline aws_iam_policy_document data sources as jsonencode() expressions.

Arguments:
  [<dir>]    Directory containing *.tf files (default: ".").

Flags:
  -h, --help        Show help.
  -i, --in-place    Write changes back to files instead of stdout.
  -v, --verbose     Verbose logging.
      --version
```

By default each rewritten file is printed to stdout preceded by a `### <path> ###` header. Pass `-i` / `--in-place` to rewrite the files on disk.

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

resource "aws_iam_role_policy" "bucket_read" {
  role   = aws_iam_role.example.id
  policy = data.aws_iam_policy_document.bucket_read.json
}
```

```sh
iampd2j -i .
```

```hcl
# policies.tf (rewritten)
resource "aws_iam_role_policy" "bucket_read" {
  role = aws_iam_role.example.id
  policy = jsonencode({
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
}
```

Notes:

- `version` defaults to `"2012-10-17"` and `effect` defaults to `"Allow"` when omitted in the data source, matching Terraform's defaults.
- Multiple `principals` blocks with the same `type` are merged into a single flat list. The same merging applies to `condition` blocks that share `test` + `variable`. List-literal `identifiers` / `values` only — references (e.g. `var.x`) make merging fail with an error rather than emit a `concat()`.
- Non-literal `principals.type`, `condition.test`, and `condition.variable` are spliced as HCL dynamic keys (`(var.x) = ...`), so configs that pass variables through these fields still convert cleanly.
- Only `data.aws_iam_policy_document.<name>.json` references are rewritten. If a policy is also referenced via something else (`.minified_json`, `.override_json`, etc.), the `.json` sites are still inlined but the data block is kept so the other accessors keep resolving (a stderr warning calls this out).
- `source_policy_documents` and `override_policy_documents` are not supported; the surrounding data block is left in place with a stderr warning so the merge can be re-done by hand. Any policy referenced (with any attribute) from inside another policy doc body is also kept, since its references either survive in the kept outer body or via the spliced tokens at the outer's reference sites.
- After rewriting, run `terraform fmt` to align attribute padding if you care about that.
