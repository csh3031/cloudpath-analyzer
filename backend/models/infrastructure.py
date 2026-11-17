from dataclasses import dataclass, field
from typing import Any


@dataclass
class InfrastructureResource:
    id: str
    provider: str
    type: str
    resource_type: str
    name: str
    attributes: dict[str, Any] = field(default_factory=dict)

