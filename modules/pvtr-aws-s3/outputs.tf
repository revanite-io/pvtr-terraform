output "bucket_arn" {
  description = "ARN of the main S3 bucket (for plugin config)"
  value       = aws_s3_bucket.this.arn
}

output "bucket_name" {
  description = "Name of the main S3 bucket"
  value       = aws_s3_bucket.this.id
}

output "log_bucket_name" {
  description = "Name of the access log bucket"
  value       = aws_s3_bucket.log_bucket.id
}

output "kms_key_arn" {
  description = "ARN of the KMS key used for encryption"
  value       = aws_kms_key.this.arn
}

output "cloudtrail_name" {
  description = "Name of the CloudTrail trail"
  value       = aws_cloudtrail.this.name
}

output "cloudwatch_log_group_name" {
  description = "Name of the CloudWatch log group for CloudTrail"
  value       = aws_cloudwatch_log_group.cloudtrail.name
}
