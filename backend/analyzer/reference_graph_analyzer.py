"""Terraform 리소스 참조 그래프 — 네트워크 패킷 경로와 독립적.

Phase 2-5: HCL 파서가 반환한 리소스 모델을 사용한다. 변수·모듈을
확장하지 않으므로 해당 값은 별도 미해결 입력으로 남긴다.
"""

import re
from collections import defaultdict
from typing import Any, Sequence


# Python-hcl2가 반환하는 '${aws_subnet.public.id}' 및
# '${aws_instance.web}' 형태를 인식한다. 복합 Terraform 표현식의
# 완전한 해석기는 아니므로 이를 배포 가능성 판정에 사용하지 않는다.
TEMPLATE_REFERENCE = re.compile(
    r"\$\{\s*([A-Za-z_][\w-]*\.[A-Za-z_][\w-]*)(?=\.|\s*\})[^}]*\}"
)
EXTERNAL_ROOTS = {"var", "local", "module", "data", "path", "terraform"}


def _walk(value: Any, path: str = ""):
    if isinstance(value, str):
        for match in TEMPLATE_REFERENCE.finditer(value):
            yield match.group(1), path
    elif isinstance(value, list):
        for i, item in enumerate(value):
            yield from _walk(item, f"{path}[{i}]")
    elif isinstance(value, dict):
        for key, item in value.items():
            child_path = f"{path}.{key}" if path else str(key)
            yield from _walk(item, child_path)


def analyze_reference_graph(resources: Sequence[Any]) -> dict:
    """리소스 A가 리소스 B를 참조한다는 사실만 기록한다.

    반환 edges는 source(참조하는 측) -> target(참조받는 측)이며,
    packet_traversable=False이다. 리소스가 없으면 노드를 만들지 않는다.
    """
    by_id = {resource.id: resource for resource in resources}
    nodes = [
        {
            "id": res.id,
            "provider": res.provider,
            "resource_type": res.resource_type,
            "name": res.name,
            "synthetic": False,
        }
        for res in sorted(by_id.values(), key=lambda r: r.id)
    ]
    paths_by_edge: dict[tuple[str, str], set[str]] = defaultdict(set)
    issues: list[dict] = []
    external_inputs: set[tuple[str, str, str]] = set()

    if len(by_id) != len(resources):
        issues.append({
            "status": "UNKNOWN",
            "code": "DUPLICATE_RESOURCE_ID",
            "reason": "동일 리소스 ID가 여러 번 선언되어 참조 해석이 불명확합니다.",
        })

    seen_missing: set[tuple[str, str, str]] = set()
    for resource in sorted(resources, key=lambda r: r.id):
        for target, attr_path in _walk(resource.attributes):
            root = target.split(".", 1)[0]
            if root in EXTERNAL_ROOTS:
                external_inputs.add((resource.id, target, attr_path))
            elif target in by_id:
                paths_by_edge[(resource.id, target)].add(attr_path)
            else:
                key = (resource.id, target, attr_path)
                if key not in seen_missing:
                    seen_missing.add(key)
                    issues.append({
                        "status": "UNKNOWN",
                        "code": "UNRESOLVED_RESOURCE_REFERENCE",
                        "source": resource.id,
                        "target": target,
                        "attribute_path": attr_path,
                        "reason": "참조한 리소스가 입력 모델에 없습니다.",
                    })

    edges = [
        {
            "source": source,
            "target": target,
            "relation": "references",
            "kind": "resource_dependency",
            "attribute_paths": sorted(paths),
            "packet_traversable": False,
        }
        for (source, target), paths in sorted(paths_by_edge.items())
    ]
    return {
        "graph_type": "resource_reference",
        "nodes": nodes,
        "edges": edges,
        "external_inputs": [
            {"resource": res, "expression_root": expr, "attribute_path": path}
            for res, expr, path in sorted(external_inputs)
        ],
        "issues": issues,
        "metadata": {"packet_path_available": False},
    }
