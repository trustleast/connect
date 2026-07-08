# outputs.tf
output "vpc_id" {
  value = aws_vpc.this.id
}

output "vpc_ipv6_cidr_block" {
  value = aws_vpc.this.ipv6_cidr_block
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "public_subnet_ids_by_az" {
  value = { for s in aws_subnet.public : s.availability_zone => s.id }
}

output "public_subnet_ipv6_cidrs" {
  value = aws_subnet.public[*].ipv6_cidr_block
}
