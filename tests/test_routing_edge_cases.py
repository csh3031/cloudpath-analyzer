from copy import deepcopy

import pytest

from backend.iac.terraform_parser import parse_terraform
from backend.analyzer.routing_analyzer import analyze_route


SAMPLE = "samples/terraform/main.tf"


def load_resources():
    return parse_terraform(SAMPLE)


def find_resource(resources, resource_id):
    return next(resource for resource in resources if resource.id == resource_id)


def public_route(resources):
    table = find_resource(resources, "aws_route_table.public")
    return table.attributes["route"][0]


@pytest.mark.parametrize("destination", ["not-an-ip", "2001:db8::1"])
def test_invalid_or_unsupported_destination_is_unknown(destination):
    result = analyze_route(load_resources(), "aws_subnet.public", destination)
    assert result["status"] == "UNKNOWN"
    assert result["reason"]


def test_missing_subnet_is_unknown():
    result = analyze_route(load_resources(), "aws_subnet.missing", "8.8.8.8")
    assert result["status"] == "UNKNOWN"
    assert "Subnet" in result["reason"]


def test_missing_vpc_reference_is_unknown():
    resources = load_resources()
    find_resource(resources, "aws_subnet.public").attributes["vpc_id"] = (
        "${aws_vpc.missing.id}"
    )
    result = analyze_route(resources, "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "UNKNOWN"
    assert "VPC" in result["reason"]


def test_missing_route_table_is_unknown():
    resources = [
        resource for resource in load_resources()
        if resource.id != "aws_route_table.public"
    ]
    result = analyze_route(resources, "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "UNKNOWN"
    assert "Route Table" in result["reason"]


def test_duplicate_subnet_association_is_unknown():
    resources = load_resources()
    association = find_resource(resources, "aws_route_table_association.public")
    duplicate = deepcopy(association)
    duplicate.id = "aws_route_table_association.duplicate"
    resources.append(duplicate)
    result = analyze_route(resources, "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "UNKNOWN"
    assert "중복" in result["reason"]


def test_invalid_route_cidr_is_unknown():
    resources = load_resources()
    public_route(resources)["cidr_block"] = "invalid-cidr"
    result = analyze_route(resources, "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "UNKNOWN"
    assert "CIDR" in result["reason"]


def test_duplicate_matching_routes_are_unknown():
    resources = load_resources()
    table = find_resource(resources, "aws_route_table.public")
    table.attributes["route"].append(deepcopy(public_route(resources)))
    result = analyze_route(resources, "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "UNKNOWN"
    assert "중복" in result["reason"]


def test_longest_prefix_match_selects_more_specific_route():
    resources = load_resources()
    table = find_resource(resources, "aws_route_table.public")
    table.attributes["route"].append({
        "cidr_block": "8.8.8.0/24",
        "gateway_id": "${aws_internet_gateway.main.id}",
    })
    result = analyze_route(resources, "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "ROUTE_FOUND"
    assert result["matched_cidr"] == "8.8.8.0/24"


def test_route_without_target_is_unknown():
    resources = load_resources()
    public_route(resources).pop("gateway_id")
    result = analyze_route(resources, "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "UNKNOWN"
    assert "Target" in result["reason"]


def test_missing_next_hop_resource_is_unknown():
    resources = load_resources()
    public_route(resources)["gateway_id"] = "${aws_internet_gateway.missing.id}"
    result = analyze_route(resources, "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "UNKNOWN"
    assert "리소스" in result["reason"]


def test_unsupported_prefix_list_is_unknown_not_no_route():
    resources = load_resources()
    table = find_resource(resources, "aws_route_table.public")
    table.attributes["route"].append({
        "destination_prefix_list_id": "pl-example",
        "gateway_id": "${aws_internet_gateway.main.id}",
    })
    result = analyze_route(resources, "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "UNKNOWN"
    assert "Prefix List" in result["reason"]


def test_route_found_has_diagnostic_evidence():
    result = analyze_route(load_resources(), "aws_subnet.public", "8.8.8.8")
    assert result["status"] == "ROUTE_FOUND"
    assert result["evidence"]
    checks = [item["check"] for item in result["evidence"]]
    assert "route_table_selection" in checks
    assert "longest_prefix_match" in checks
    assert "next_hop" in checks
