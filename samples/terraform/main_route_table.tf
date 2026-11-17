resource "aws_vpc" "main" {
  cidr_block = "10.30.0.0/16"
}

resource "aws_subnet" "automatic" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.30.1.0/24"
}

resource "aws_subnet" "explicit" {
  vpc_id     = aws_vpc.main.id
  cidr_block = "10.30.2.0/24"
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
}

resource "aws_route_table" "main" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }
}

resource "aws_route_table" "isolated" {
  vpc_id = aws_vpc.main.id
}

resource "aws_main_route_table_association" "main" {
  vpc_id         = aws_vpc.main.id
  route_table_id = aws_route_table.main.id
}

resource "aws_route_table_association" "explicit" {
  subnet_id      = aws_subnet.explicit.id
  route_table_id = aws_route_table.isolated.id
}
