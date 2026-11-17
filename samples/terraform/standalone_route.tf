resource "aws_vpc" "standalone" {
  cidr_block = "10.20.0.0/16"
}

resource "aws_subnet" "standalone" {
  vpc_id     = aws_vpc.standalone.id
  cidr_block = "10.20.1.0/24"
}

resource "aws_internet_gateway" "standalone" {
  vpc_id = aws_vpc.standalone.id
}

resource "aws_route_table" "standalone" {
  vpc_id = aws_vpc.standalone.id
}

resource "aws_route" "internet" {
  route_table_id         = aws_route_table.standalone.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.standalone.id
}

resource "aws_route_table_association" "standalone" {
  subnet_id      = aws_subnet.standalone.id
  route_table_id = aws_route_table.standalone.id
}
