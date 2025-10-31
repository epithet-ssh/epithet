variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "us-west-2"
}

variable "project_name" {
  description = "Project name used in resource naming"
  type        = string
  default     = "epithet"
}

variable "ca_key_algorithm" {
  description = "CA private key algorithm (ed25519 or rsa)"
  type        = string
  default     = "ed25519"

  validation {
    condition     = contains(["ed25519", "rsa"], var.ca_key_algorithm)
    error_message = "ca_key_algorithm must be either 'ed25519' or 'rsa'"
  }
}

variable "ca_key_bits" {
  description = "CA private key size in bits (256 for ed25519, 4096 for rsa)"
  type        = number
  default     = 256

  validation {
    condition     = var.ca_key_bits == 256 || var.ca_key_bits == 4096
    error_message = "ca_key_bits must be 256 (ed25519) or 4096 (rsa)"
  }
}

variable "lambda_memory_mb" {
  description = "Lambda function memory allocation in MB"
  type        = number
  default     = 256
}

variable "lambda_timeout_sec" {
  description = "Lambda function timeout in seconds"
  type        = number
  default     = 30
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention period in days"
  type        = number
  default     = 7
}
