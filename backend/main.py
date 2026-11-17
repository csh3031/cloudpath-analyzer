
import json
from dataclasses import asdict

from backend.iac.terraform_parser import parse_terraform
from backend.analyzer.topology_analyzer import analyze_topology
from backend.analyzer.routing_analyzer import analyze_route


def main():
    file_path = "samples/terraform/main.tf"

    # 1. Terraform 분석
    resources = parse_terraform(file_path)

    # 2. 공통 인프라 모델 변환
    normalized_resources = [
        asdict(resource) for resource in resources
    ]

    # 3. 토폴로지 분석
    topology = analyze_topology(resources)

    # 4. 라우팅 분석
    routing_results = [
        analyze_route(
            resources,
            "aws_subnet.public",
            "8.8.8.8"
        ),
        analyze_route(
            resources,
            "aws_subnet.private",
            "8.8.8.8"
        ),
        analyze_route(
            resources,
            "aws_subnet.private",
            "10.0.1.10"
        )
    ]

    # 5. 최종 결과 구성
    result = {
        "project": "CloudPath Analyzer",
        "resource_count": len(normalized_resources),
        "resources": normalized_resources,
        "topology": topology,
        "routing": routing_results
    }

    # 6. JSON 출력
    print(json.dumps(result, indent=4, ensure_ascii=False))


if __name__ == "__main__":
    main()

