# trivy:ignore:AVD-AWS-0089
resource "aws_s3_bucket" "without_logging" {
  bucket = "before-deploy-calibration-suppression"
}
