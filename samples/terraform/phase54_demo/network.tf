# Offline analysis sample. No deployment intended.
resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}
resource "aws_subnet" "a" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.1.0/24"
}
resource "aws_subnet" "b" {
  vpc_id = aws_vpc.main.id
  cidr_block = "10.0.2.0/24"
}
resource "aws_route_table" "main" {
  vpc_id = aws_vpc.main.id
}
resource "aws_route_table_association" "a" {
  subnet_id = aws_subnet.a.id
  route_table_id = aws_route_table.main.id
}
resource "aws_route_table_association" "b" {
  subnet_id = aws_subnet.b.id
  route_table_id = aws_route_table.main.id
}
