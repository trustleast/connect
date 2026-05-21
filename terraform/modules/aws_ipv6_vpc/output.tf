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

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "public_subnet_ipv6_cidrs" {
  value = aws_subnet.public[*].ipv6_cidr_block
}

output "private_subnet_ipv6_cidrs" {
  value = aws_subnet.private[*].ipv6_cidr_block
}
