import hcl2

from backend.models.infrastructure import InfrastructureResource

RESOURCE_CATEGORIES = {
    "aws_vpc": ("network", "vpc"),
    "aws_subnet": ("network", "subnet"),
    "aws_internet_gateway": ("network", "internet_gateway"),
    "aws_route_table": ("network", "route_table"),
    "aws_main_route_table_association": ("network", "main_route_table_association"),
    "aws_default_route_table": ("network", "default_route_table"),
    "aws_route": ("network", "route"),
    "aws_nat_gateway": ("network", "nat_gateway"),
    "aws_security_group": ("security", "security_group"),
    "aws_network_acl": ("security", "network_acl"),
    "aws_default_network_acl": ("security", "default_network_acl"),
    "aws_network_interface": ("network", "network_interface"),
    "aws_instance": ("compute", "instance"),
    "aws_route_table_association": ("network", "route_table_association")
}


def clean_value(value):
    """
    HCL 파서에서 반환한 문자열의 불필요한 따옴표 제거.
    참조 표현식은 그대로 유지한다.
    """
    if isinstance(value, str):
        if len(value) >= 2 and value[0] == value[-1] == '"':
            return value[1:-1]
        return value

    if isinstance(value, list):
        return [clean_value(item) for item in value]

    if isinstance(value, dict):
        return {
            key: clean_value(item)
            for key, item in value.items()
            if key != "__is_block__"
        }

    return value


def parse_terraform(file_path):
    """
    Terraform HCL 파일을 공통 인프라 모델로 변환한다.
    """

    with open(file_path, "r", encoding="utf-8") as file:
        terraform_data = hcl2.load(file)

    resources = []

    resource_blocks = terraform_data.get("resource", [])

    for resource_block in resource_blocks:
        for resource_type, instances in resource_block.items():

            resource_type = clean_value(resource_type)

            for resource_name, attributes in instances.items():

                resource_name = clean_value(resource_name)

                category, normalized_type = RESOURCE_CATEGORIES.get(
                    resource_type,
                    ("unknown", resource_type)
                )

                resource = InfrastructureResource(
                    id=f"{resource_type}.{resource_name}",
                    provider=resource_type.split("_")[0],
                    type=category,
                    resource_type=normalized_type,
                    name=resource_name,
                    attributes=clean_value(attributes)
                )

                resources.append(resource)

    return resources

