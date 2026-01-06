# ===== Terraform Backend =====
# Uses partial configuration - bucket provided at init time
#
# Local usage:
#   terraform init -backend-config="bucket=error-debugger-terraform-state-<ACCOUNT_ID>"
#
# Or create backend.hcl with:
#   bucket = "error-debugger-terraform-state-<ACCOUNT_ID>"
# Then run:
#   terraform init -backend-config=backend.hcl

terraform {
  backend "s3" {
    # bucket is provided via -backend-config at init time
    key            = "error-debugger/terraform.tfstate"
    region         = "us-east-1"
    dynamodb_table = "error-debugger-terraform-locks"
    encrypt        = true
  }
}
