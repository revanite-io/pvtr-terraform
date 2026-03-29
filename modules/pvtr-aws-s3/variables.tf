variable "bucket_name" {
  description = "S3 bucket name. If empty, auto-generated."
  type        = string
  default     = ""

  validation {
    condition     = var.bucket_name == "" || can(regex("^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$", var.bucket_name))
    error_message = "Bucket name must be 3-63 characters, lowercase alphanumeric, hyphens, or periods."
  }
}

variable "allowed_ips" {
  description = "List of IP addresses or CIDR ranges allowed to access the bucket"
  type        = list(string)
  default     = []
}

variable "object_lock_mode" {
  description = "Object Lock retention mode (COMPLIANCE or GOVERNANCE). COMPLIANCE cannot be overridden."
  type        = string
  default     = "COMPLIANCE"

  validation {
    condition     = contains(["COMPLIANCE", "GOVERNANCE"], var.object_lock_mode)
    error_message = "object_lock_mode must be one of: COMPLIANCE, GOVERNANCE."
  }
}

variable "object_lock_retention_days" {
  description = "Default Object Lock retention period in days"
  type        = number
  default     = 1
}

variable "kms_key_rotation_enabled" {
  description = "Enable automatic annual rotation of the KMS key"
  type        = bool
  default     = true
}

variable "log_retention_days" {
  description = "Number of days to retain objects in the access log bucket"
  type        = number
  default     = 90
}

variable "cloudtrail_retention_days" {
  description = "Number of days to retain CloudWatch logs for CloudTrail"
  type        = number
  default     = 30
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}
