resource "aws_s3_bucket" "data" {
  bucket = "fixture-public-bucket"
}

resource "aws_s3_bucket_acl" "data" {
  bucket = aws_s3_bucket.data.id
  acl    = "public-read-write"
}

resource "aws_security_group" "ssh" {
  name = "open-ssh"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "azurerm_storage_account" "data" {
  name                      = "fixturestorage"
  resource_group_name       = "rg"
  location                  = "westeurope"
  account_tier              = "Standard"
  account_replication_type  = "LRS"
  https_traffic_only_enabled = false
  min_tls_version           = "TLS1_0"
}
