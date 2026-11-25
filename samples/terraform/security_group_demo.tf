# Offline example only; no deployment is required.
resource "aws_vpc" "sg_demo" {
  cidr_block = "10.20.0.0/16"
}
resource "aws_subnet" "sg_demo" {
  vpc_id = aws_vpc.sg_demo.id
  cidr_block = "10.20.1.0/24"
}
resource "aws_route_table" "sg_demo" {
  vpc_id = aws_vpc.sg_demo.id
}
resource "aws_route_table_association" "sg_demo" {
  subnet_id = aws_subnet.sg_demo.id
  route_table_id = aws_route_table.sg_demo.id
}
resource "aws_security_group" "web" {
  vpc_id = aws_vpc.sg_demo.id
  egress {
    protocol = "-1"
    from_port = 0
    to_port = 0
    cidr_blocks = ["10.20.0.0/16"]
  }
}
resource "aws_security_group" "db" {
  vpc_id = aws_vpc.sg_demo.id
}
resource "aws_vpc_security_group_ingress_rule" "mysql" {
  security_group_id = aws_security_group.db.id
  referenced_security_group_id = aws_security_group.web.id
  ip_protocol = "tcp"
  from_port = 3306
  to_port = 3306
}
resource "aws_instance" "web" {
  ami = "ami-example-not-deployable"
  instance_type = "t3.micro"
  subnet_id = aws_subnet.sg_demo.id
  private_ip = "10.20.1.10"
  vpc_security_group_ids = [aws_security_group.web.id]
}
resource "aws_instance" "db" {
  ami = "ami-example-not-deployable"
  instance_type = "t3.micro"
  subnet_id = aws_subnet.sg_demo.id
  private_ip = "10.20.1.20"
  vpc_security_group_ids = [aws_security_group.db.id]
}
