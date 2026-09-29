provider "aws" {
  region                      = "us-east-1"
  access_key                  = "x"
  secret_key                  = "x"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
  skip_metadata_api_check     = true
}
resource "aws_security_group" "db" {
  name = "db"
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_iam_role_policy" "p" {
  name = "p"
  role = "r"
  policy = jsonencode({ Version = "2012-10-17", Statement = [{ Effect = "Allow", Action = "s3:*", Resource = "*" }] })
}
resource "aws_db_instance" "main" {
  identifier          = "main"
  engine              = "postgres"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  username            = "app"
  password            = "notreal123"
  publicly_accessible = true
  storage_encrypted   = false
  skip_final_snapshot = true
}
