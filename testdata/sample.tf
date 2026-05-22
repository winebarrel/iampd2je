data "aws_iam_policy_document" "simple" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "full" {
  policy_id = "example"

  statement {
    sid     = "AllowReads"
    effect  = "Allow"
    actions = ["s3:GetObject", "s3:ListBucket"]
    resources = [
      aws_s3_bucket.example.arn,
      "${aws_s3_bucket.example.arn}/*",
    ]

    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::123456789012:role/example"]
    }

    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:username"
      values   = ["alice"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:userid"
      values   = ["AIDAEXAMPLE"]
    }

    condition {
      test     = "DateGreaterThan"
      variable = "aws:CurrentTime"
      values   = ["2025-01-01T00:00:00Z"]
    }
  }

  statement {
    sid       = "DenyDeletes"
    effect    = "Deny"
    not_actions = ["s3:DeleteObject"]
    resources = ["*"]
  }
}
