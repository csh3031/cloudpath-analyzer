resource "aws_vpc" "main" {
  cidr_block = "10.40.0.0/16"
}

resource "aws_subnet" "automatic" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.40.1.0/24"
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_default_route_table" "main" {
  default_route_table_id = aws_vpc.main.default_route_table_id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
}
