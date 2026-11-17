"""Phase 2-5 정규화된 두 종류의 그래프를 제공하는 진입점."""

from backend.analyzer.network_graph_analyzer import analyze_network_graph
from backend.analyzer.reference_graph_analyzer import analyze_reference_graph


def analyze_graphs(resources):
    """Terraform 참조 관계와 AWS 네트워크 구성 관계를 각각 반환한다."""
    return {
        "reference_graph": analyze_reference_graph(resources),
        "network_graph": analyze_network_graph(resources),
    }
