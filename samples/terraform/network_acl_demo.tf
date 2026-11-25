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
resource "aws_network_acl" "a" {
  vpc_id = aws_vpc.main.id
  subnet_ids = [aws_subnet.a.id]
  egress {
    rule_no = 100
    protocol = "tcp"
    action = "allow"
    cidr_block = "10.0.2.0/24"
    from_port = 0
    to_port = 65535
  }
}
resource "aws_network_acl" "b" {
  vpc_id = aws_vpc.main.id
}
resource "aws_network_acl_association" "b" {
  subnet_id = aws_subnet.b.id
  network_acl_id = aws_network_acl.b.id
}
resource "aws_network_acl_rule" "allow_https" {
  network_acl_id = aws_network_acl.b.id
  rule_number = 100
  egress = false
  protocol = "tcp"
  rule_action = "allow"
  cidr_block = "10.0.1.0/24"
  from_port = 443
  to_port = 443
}
resource "aws_security_group" "a" {
  vpc_id = aws_vpc.main.id
  egress {
    protocol = "-1"
    from_port = 0
    to_port = 0
    cidr_blocks = ["10.0.0.0/16"]
  }
}
resource "aws_security_group" "b" {
  vpc_id = aws_vpc.main.id
  ingress {
    protocol = "tcp"
    from_port = 0
    to_port = 65535
    cidr_blocks = ["10.0.1.0/24"]
  }
}
resource "aws_instance" "a" {
  ami = "ami-example-not-deployable"
  instance_type = "t3.micro"
  subnet_id = aws_subnet.a.id
  private_ip = "10.0.1.10"
  vpc_security_group_ids = [aws_security_group.a.id]
}
resource "aws_instance" "b" {
  ami = "ami-example-not-deployable"
  instance_type = "t3.micro"
  subnet_id = aws_subnet.b.id
  private_ip = "10.0.2.20"
  vpc_security_group_ids = [aws_security_group.b.id]
}
