resource "aws_vpc" "main" {
  cidr_block = "10.50.0.0/16"
}

resource "aws_subnet" "automatic" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.50.1.0/24"
}
