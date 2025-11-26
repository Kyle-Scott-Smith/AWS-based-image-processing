# S3 Buckets for image storage
resource "aws_s3_bucket" "original_images" {
  bucket = "n11957948-original-images"
  
  tags = {
    Name        = "OriginalImages"
    Environment = "Assessment2"
    Owner       = "n11957948"
  }
}

resource "aws_s3_bucket" "processed_images" {
  bucket = "n11957948-processed-images"
  
  tags = {
    Name        = "ProcessedImages"
    Environment = "Assessment2"
    Owner       = "n11957948"
  }
}

# DynamoDB Table for metadata
resource "aws_dynamodb_table" "image_metadata" {
  name           = "ImageMetadata"
  billing_mode   = "PAY_PER_REQUEST"
  hash_key       = "image_id"

  attribute {
    name = "image_id"
    type = "S"
  }

  attribute {
    name = "user_id"
    type = "S"
  }

  global_secondary_index {
    name               = "UserIndex"
    hash_key           = "user_id"
    projection_type    = "ALL"
    read_capacity      = 5
    write_capacity     = 5
  }

  tags = {
    Name        = "ImageMetadata"
    Environment = "Assessment2"
    Owner       = "n11957948"
  }
}

# IAM Role for EC2 instance
resource "aws_iam_role" "ec2_s3_dynamodb_role" {
  name = "EC2S3DynamoDBRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "EC2S3DynamoDBRole"
    Environment = "Assessment2"
    Owner       = "n11957948"
  }
}

# IAM Policy for S3 access
resource "aws_iam_policy" "s3_access_policy" {
  name        = "S3AccessPolicy"
  description = "Policy for S3 bucket access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:ListBucket"
        ]
        Effect = "Allow"
        Resource = [
          "${aws_s3_bucket.original_images.arn}",
          "${aws_s3_bucket.original_images.arn}/*",
          "${aws_s3_bucket.processed_images.arn}",
          "${aws_s3_bucket.processed_images.arn}/*"
        ]
      }
    ]
  })
}

# IAM Policy for DynamoDB access
resource "aws_iam_policy" "dynamodb_access_policy" {
  name        = "DynamoDBAccessPolicy"
  description = "Policy for DynamoDB table access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan"
        ]
        Effect = "Allow"
        Resource = [
          "${aws_dynamodb_table.image_metadata.arn}",
          "${aws_dynamodb_table.image_metadata.arn}/index/*"
        ]
      }
    ]
  })
}

# Attach policies to the role
resource "aws_iam_role_policy_attachment" "s3_access" {
  role       = aws_iam_role.ec2_s3_dynamodb_role.name
  policy_arn = aws_iam_policy.s3_access_policy.arn
}

resource "aws_iam_role_policy_attachment" "dynamodb_access" {
  role       = aws_iam_role.ec2_s3_dynamodb_role.name
  policy_arn = aws_iam_policy.dynamodb_access_policy.arn
}

resource "aws_iam_role_policy_attachment" "secrets_access" {
  role       = aws_iam_role.ec2_s3_dynamodb_role.name
  policy_arn = "arn:aws:iam::aws:policy/SecretsManagerReadWrite"
}

# Instance profile for EC2
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "EC2S3DynamoDBInstanceProfile"
  role = aws_iam_role.ec2_s3_dynamodb_role.name
}

output "s3_original_bucket" {
  value = aws_s3_bucket.original_images.bucket
}

output "s3_processed_bucket" {
  value = aws_s3_bucket.processed_images.bucket
}

output "dynamodb_table" {
  value = aws_dynamodb_table.image_metadata.name
}

