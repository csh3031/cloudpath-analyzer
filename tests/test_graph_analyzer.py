"""Phase 2-5: 참조 그래프 / 네트워크 구성 그래프 분리 검증."""

import json

from backend.analyzer.graph_analyzer import analyze_graphs
from backend.analyzer.network_graph_analyzer import analyze_network_graph
from backend.analyzer.reference_graph_analyzer import analyze_reference_graph
from backend.models.infrastructure import InfrastructureResource


def r(resource_id, resource_type, **attributes):
    return InfrastructureResource(
        id=resource_id,
        provider="aws",
        type="network",
        resource_type=resource_type,
        name=resource_id.split(".")[-1],
        attributes=attributes,
    )


def example():
    return [
        r("aws_vpc.main", "vpc", cidr_block="10.0.0.0/16"),
        r("aws_subnet.public", "subnet", vpc_id="${aws_vpc.main.id}", cidr_block="10.0.1.0/24"),
        r("aws_internet_gateway.igw", "internet_gateway", vpc_id="${aws_vpc.main.id}"),
        r("aws_route_table.public", "route_table", vpc_id="${aws_vpc.main.id}",
          route=[{"cidr_block": "0.0.0.0/0", "gateway_id": "${aws_internet_gateway.igw.id}"}]),
        r("aws_route_table_association.public", "route_table_association",
          subnet_id="${aws_subnet.public.id}", route_table_id="${aws_route_table.public.id}"),
    ]


def edge(graph, source, target, relation):
    return next(
        (e for e in graph["edges"] if e["source"] == source and e["target"] == target and e["relation"] == relation),
        None,
    )


def test_reference_graph_direction_and_path():
    graph = analyze_reference_graph(example())
    link = edge(graph, "aws_subnet.public", "aws_vpc.main", "references")
    assert link is not None
    assert link["attribute_paths"] == ["vpc_id"]
    assert link["packet_traversable"] is False


def test_reference_graph_nested_and_repeated_reference_deduplicated():
    resources = example() + [
        r("aws_security_group.web", "security_group", vpc_id="${aws_vpc.main.id}",
          ingress=[{"from": "${aws_subnet.public.id}", "to": "${aws_subnet.public.id}"}])
    ]
    graph = analyze_reference_graph(resources)
    link = edge(graph, "aws_security_group.web", "aws_subnet.public", "references")
    assert link["attribute_paths"] == ["ingress[0].from", "ingress[0].to"]
    assert len([e for e in graph["edges"] if e["source"] == "aws_security_group.web" and e["target"] == "aws_subnet.public"]) == 1


def test_reference_graph_unresolved_not_invented_as_node():
    resources = example() + [r("aws_instance.web", "instance", subnet_id="${aws_subnet.missing.id}")]
    graph = analyze_reference_graph(resources)
    assert not any(n["id"] == "aws_subnet.missing" for n in graph["nodes"])
    assert not any(e["target"] == "aws_subnet.missing" for e in graph["edges"])
    assert any(i["code"] == "UNRESOLVED_RESOURCE_REFERENCE" and i["target"] == "aws_subnet.missing" for i in graph["issues"])


def test_reference_graph_variables_are_not_fake_resource_nodes():
    resources = example() + [r("aws_instance.web", "instance", subnet_id="${var.subnet_id}")]
    graph = analyze_reference_graph(resources)
    assert any(item["expression_root"] == "var.subnet_id" for item in graph["external_inputs"])
    assert not any(n["id"] == "var.subnet_id" for n in graph["nodes"])


def test_network_graph_is_not_a_terraform_dependency_graph():
    graph = analyze_network_graph(example())
    assert edge(graph, "aws_vpc.main", "aws_subnet.public", "contains")
    assert edge(graph, "aws_subnet.public", "aws_route_table.public", "uses_route_table")
    assert not any(e["relation"] == "references" for e in graph["edges"])
    assert not any(e["packet_traversable"] for e in graph["edges"])
    assert graph["metadata"]["packet_path_available"] is False
    assert not any(e["source"] == "aws_route_table.public" and e["target"] == "aws_internet_gateway.igw" for e in graph["edges"])


def test_network_graph_route_rules_are_data_not_hops():
    graph = analyze_network_graph(example())
    assert len(graph["route_rules"]) == 1
    rule = graph["route_rules"][0]
    assert rule["status"] == "RESOLVED"
    assert rule["target"] == "aws_internet_gateway.igw"
    assert rule["packet_traversable"] is False


def test_network_graph_standalone_route_rule():
    resources = example()
    resources[3].attributes["route"] = []
    resources.append(r("aws_route.internet", "route",
                       route_table_id="${aws_route_table.public.id}",
                       destination_cidr_block="0.0.0.0/0",
                       gateway_id="${aws_internet_gateway.igw.id}"))
    graph = analyze_network_graph(resources)
    assert graph["route_rules"][0]["source"] == "aws_route.internet"
    assert graph["route_rules"][0]["status"] == "RESOLVED"
    assert not any(n["id"] == "aws_route.internet" for n in graph["nodes"])


def test_implicit_main_is_explicitly_synthetic_and_never_a_packet_hop():
    resources = [
        r("aws_vpc.main", "vpc", cidr_block="10.0.0.0/16"),
        r("aws_subnet.public", "subnet", vpc_id="${aws_vpc.main.id}", cidr_block="10.0.1.0/24"),
    ]
    graph = analyze_network_graph(resources)
    synthetic = next(n for n in graph["nodes"] if n["id"] == "implicit_main:aws_vpc.main")
    assert synthetic["synthetic"] is True
    link = edge(graph, "aws_subnet.public", "implicit_main:aws_vpc.main", "uses_route_table")
    assert link["selection"] == "implicit_main"
    assert link["packet_traversable"] is False


def test_managed_default_route_table_is_selected():
    resources = [
        r("aws_vpc.main", "vpc", cidr_block="10.0.0.0/16"),
        r("aws_subnet.public", "subnet", vpc_id="${aws_vpc.main.id}"),
        r("aws_default_route_table.main", "default_route_table",
          default_route_table_id="${aws_vpc.main.default_route_table_id}"),
    ]
    graph = analyze_network_graph(resources)
    link = edge(graph, "aws_subnet.public", "aws_default_route_table.main", "uses_route_table")
    assert link["selection"] == "managed_default"
    assert not any(n["synthetic"] for n in graph["nodes"])


def test_main_route_override_selected_without_explicit():
    resources = example()
    resources = [r for r in resources if r.resource_type != "route_table_association"]
    resources.append(r("aws_main_route_table_association.main", "main_route_table_association",
                       vpc_id="${aws_vpc.main.id}", route_table_id="${aws_route_table.public.id}"))
    graph = analyze_network_graph(resources)
    assert edge(graph, "aws_subnet.public", "aws_route_table.public", "uses_route_table")["selection"] == "main_override"


def test_conflicting_associations_are_unknown_not_arbitrarily_chosen():
    resources = example() + [
        r("aws_route_table_association.duplicate", "route_table_association",
          subnet_id="${aws_subnet.public.id}", route_table_id="${aws_route_table.public.id}")
    ]
    graph = analyze_network_graph(resources)
    assert not any(e["relation"] == "uses_route_table" for e in graph["edges"])
    assert any(issue["code"] == "UNRESOLVED_ROUTE_TABLE_SELECTION" for issue in graph["issues"])


def test_cross_vpc_association_rejected():
    resources = example() + [r("aws_vpc.other", "vpc", cidr_block="10.2.0.0/16")]
    resources[3].attributes["vpc_id"] = "${aws_vpc.other.id}"
    graph = analyze_network_graph(resources)
    assert not any(e["relation"] == "uses_route_table" for e in graph["edges"])
    assert any(i["code"] == "CROSS_VPC_ROUTE_TABLE" for i in graph["issues"])


def test_security_group_is_policy_attachment_not_packet_hop():
    resources = example() + [
        r("aws_security_group.web", "security_group", vpc_id="${aws_vpc.main.id}"),
        r("aws_instance.web", "instance", subnet_id="${aws_subnet.public.id}",
          vpc_security_group_ids=["${aws_security_group.web.id}"]),
    ]
    graph = analyze_network_graph(resources)
    assert edge(graph, "aws_subnet.public", "aws_instance.web", "contains")
    link = edge(graph, "aws_security_group.web", "aws_instance.web", "applies_to")
    assert link["kind"] == "policy_attachment"
    assert link["packet_traversable"] is False


def test_unresolved_route_target_is_reported_not_visualized():
    resources = example()
    resources[3].attributes["route"][0]["gateway_id"] = "${aws_internet_gateway.missing.id}"
    graph = analyze_network_graph(resources)
    assert graph["route_rules"][0]["status"] == "UNKNOWN"
    assert any(i["code"] == "UNRESOLVED_ROUTE_RULE" for i in graph["issues"])
    assert not any(n["id"] == "aws_internet_gateway.missing" for n in graph["nodes"])


def test_unresolved_parent_is_not_attached_to_fake_vpc():
    graph = analyze_network_graph([r("aws_subnet.lonely", "subnet", vpc_id="${var.vpc_id}")])
    assert not graph["edges"]
    assert any(i["code"] == "UNRESOLVED_PARENT_REFERENCE" for i in graph["issues"])


def test_combined_graphs_json_serializable_and_separate():
    graphs = analyze_graphs(example())
    assert set(graphs) == {"reference_graph", "network_graph"}
    assert json.loads(json.dumps(graphs, ensure_ascii=False))["network_graph"]["graph_type"] == "network_configuration_topology"
    assert graphs["reference_graph"]["graph_type"] == "resource_reference"
