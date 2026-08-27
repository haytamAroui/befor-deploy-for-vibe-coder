data "aws_caller_identity" "current" {}

resource "aws_s3_bucket" "ambiguous" {
  bucket = "before-deploy-calibration-ambiguous"
  tags = {
    account = data.aws_caller_identity.current.account_id
  }
}
