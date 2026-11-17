import re


REFERENCE_PATTERN = re.compile(
    r"\$\{([a-zA-Z_][\w-]*\.[a-zA-Z_][\w-]*)\.[^}]+\}"
)


def extract_references(value):
    references = set()

    if isinstance(value, str):
        references.update(REFERENCE_PATTERN.findall(value))

    elif isinstance(value, list):
        for item in value:
            references.update(extract_references(item))

    elif isinstance(value, dict):
        for item in value.values():
            references.update(extract_references(item))

    return references


def get_reference(value):
    if not isinstance(value, str):
        return None

    match = REFERENCE_PATTERN.fullmatch(value)
    return match.group(1) if match else None


def analyze_topology(resources):
    nodes = []
    edges = []
    edge_keys = set()

    resource_ids = {resource.id for resource in resources}

    def add_edge(source, target, relation):
        if source not in resource_ids or target not in resource_ids:
            return

        key = (source, target, relation)

        if key not in edge_keys:
            edges.append({
                "source": source,
                "target": target,
                "relation": relation
            })
            edge_keys.add(key)

    for resource in resources:
        nodes.append({
            "id": resource.id,
            "provider": resource.provider,
            "type": resource.resource_type,
            "name": resource.name
        })

        attributes = resource.attributes
        handled_references = set()

        # 1. VPC 포함 관계
        if resource.resource_type in {
            "subnet",
            "internet_gateway",
            "route_table"
        }:
            vpc = get_reference(attributes.get("vpc_id"))

            if vpc:
                add_edge(vpc, resource.id, "contains")
                handled_references.add(vpc)

        # 2. Route Table Association
        if resource.resource_type == "route_table_association":
            subnet = get_reference(attributes.get("subnet_id"))
            route_table = get_reference(
                attributes.get("route_table_id")
            )

            if subnet and route_table:
                add_edge(
                    route_table,
                    subnet,
                    "associated_with"
                )
                handled_references.update({
                    subnet,
                    route_table
                })

        # 3. Route Table의 Gateway 경로
        if resource.resource_type == "route_table":
            for route in attributes.get("route", []):
                gateway = get_reference(route.get("gateway_id"))

                if gateway:
                    add_edge(
                        resource.id,
                        gateway,
                        "routes_to"
                    )
                    handled_references.add(gateway)

        # 4. 아직 처리하지 않은 일반 참조
        references = extract_references(attributes)

        for reference in sorted(references):
            if reference not in handled_references:
                add_edge(
                    resource.id,
                    reference,
                    "references"
                )

    return {
        "nodes": nodes,
        "edges": edges
    }

