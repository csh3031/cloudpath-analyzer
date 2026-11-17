from backend.iac.terraform_parser import parse_terraform
from backend.analyzer.topology_analyzer import analyze_topology


def test_network_topology():
    resources = parse_terraform("samples/terraform/main.tf")
    topology = analyze_topology(resources)

    assert len(topology["nodes"]) == 8

    edges = topology["edges"]

    assert {
        "source": "aws_vpc.main",
        "target": "aws_subnet.public",
        "relation": "contains"
    } in edges

    assert {
        "source": "aws_vpc.main",
        "target": "aws_subnet.private",
        "relation": "contains"
    } in edges

    assert {
        "source": "aws_route_table.public",
        "target": "aws_internet_gateway.main",
        "relation": "routes_to"
    } in edges

    assert {
        "source": "aws_route_table.public",
        "target": "aws_subnet.public",
        "relation": "associated_with"
    } in edges

    assert {
        "source": "aws_route_table.private",
        "target": "aws_subnet.private",
        "relation": "associated_with"
    } in edges

