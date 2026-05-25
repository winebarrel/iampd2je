resource "aws_iam_role_policy" "simple" {
  role = "example"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy" "full" {
  role = "example"
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "example"
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
          AWS     = "arn:aws:iam::123456789012:role/example"
          Service = "s3.amazonaws.com"
        }
        Condition = {
          StringEquals = {
            "aws:username" = "alice"
            "aws:userid"   = "AIDAEXAMPLE"
          }
          DateGreaterThan = {
            "aws:CurrentTime" = "2025-01-01T00:00:00Z"
          }
        }
      },
      {
        Sid       = "DenyDeletes"
        Effect    = "Deny"
        NotAction = "s3:DeleteObject"
        Resource  = "*"
      }
    ]
  })
}
