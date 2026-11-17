
from backend.iac.terraform_parser import parse_terraform
from backend.analyzer.routing_analyzer import analyze_route


def test_public_subnet_internet_route():
    resources = parse_terraform("samples/terraform/main.tf")

    result = analyze_route(
        resources,
        "aws_subnet.public",
        "8.8.8.8"
    )

    assert result["status"] == "ROUTE_FOUND"
    assert result["matched_cidr"] == "0.0.0.0/0"
    assert result["next_hop"] == "aws_internet_gateway.main"


def test_private_subnet_no_internet_route():
    resources = parse_terraform("samples/terraform/main.tf")

    result = analyze_route(
        resources,
        "aws_subnet.private",
        "8.8.8.8"
    )

    assert result["status"] == "NO_ROUTE"


def test_private_subnet_local_route():
    resources = parse_terraform("samples/terraform/main.tf")

    result = analyze_route(
        resources,
        "aws_subnet.private",
        "10.0.1.10"
    )

    assert result["status"] == "ROUTE_FOUND"
    assert result["matched_cidr"] == "10.0.0.0/16"
    assert result["next_hop"] == "local"



def test_standalone_aws_route():
    resources = parse_terraform(
        "samples/terraform/standalone_route.tf"
    )

    # 독립적인 aws_route 리소스가 인식되는지 확인
    assert any(
        resource.id == "aws_route.internet"
        and resource.resource_type == "route"
        for resource in resources
    )

    result = analyze_route(
        resources,
        "aws_subnet.standalone",
        "8.8.8.8"
    )

    assert result["status"] == "ROUTE_FOUND"
    assert result["matched_cidr"] == "0.0.0.0/0"
    assert result["next_hop"] == "aws_internet_gateway.standalone"


def test_main_route_table_fallback():
    resources = parse_terraform(
        "samples/terraform/main_route_table.tf"
    )

    result = analyze_route(
        resources, "aws_subnet.automatic", "8.8.8.8"
    )

    assert result["status"] == "ROUTE_FOUND"
    assert result["route_table"] == "aws_route_table.main"
    assert result["next_hop"] == "aws_internet_gateway.main"


def test_explicit_route_table_takes_priority():
    resources = parse_terraform(
        "samples/terraform/main_route_table.tf"
    )

    result = analyze_route(
        resources, "aws_subnet.explicit", "8.8.8.8"
    )

    assert result["status"] == "NO_ROUTE"
    assert result["route_table"] == "aws_route_table.isolated"


def test_managed_default_route_table():
    resources = parse_terraform(
        "samples/terraform/default_route_table.tf"
    )

    result = analyze_route(
        resources, "aws_subnet.automatic", "8.8.8.8"
    )

    assert result["status"] == "ROUTE_FOUND"
    assert result["route_table"] == "aws_default_route_table.main"
    assert result["next_hop"] == "aws_internet_gateway.main"


def test_implicit_main_route_table_local():
    resources = parse_terraform(
        "samples/terraform/implicit_main_route_table.tf"
    )

    result = analyze_route(
        resources, "aws_subnet.automatic", "10.50.2.10"
    )

    assert result["status"] == "ROUTE_FOUND"
    assert result["matched_cidr"] == "10.50.0.0/16"
    assert result["next_hop"] == "local"


def test_implicit_main_route_table_no_internet():
    resources = parse_terraform(
        "samples/terraform/implicit_main_route_table.tf"
    )

    result = analyze_route(
        resources, "aws_subnet.automatic", "8.8.8.8"
    )

    assert result["status"] == "NO_ROUTE"
