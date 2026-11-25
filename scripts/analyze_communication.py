"""Offline initial communication diagnostic; no cloud API calls."""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from backend.iac.terraform_parser import parse_terraform
from backend.iac.input_identity import input_identity
from backend.models.diagnostics import CommunicationScenario
from backend.analyzer.communication_analyzer import analyze_communication
from backend.analyzer.security_group_analyzer import SECURITY_GROUP_CHECK
from backend.analyzer.network_acl_analyzer import NETWORK_ACL_CHECK


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--terraform', action='append', required=True, help='HCL file; repeat for multiple root files')
    p.add_argument('--source-subnet', required=True)
    p.add_argument('--source-resource')
    p.add_argument('--source-ip')
    p.add_argument('--destination-resource')
    p.add_argument('--destination-ip', required=True)
    p.add_argument('--protocol', choices=['tcp','udp'], default='tcp')
    p.add_argument('--source-port', type=int)
    p.add_argument('--trace-session', action='store_true', help='Analyze bounded bidirectional session')
    p.add_argument('--assume-tracked-response', action='store_true', help='Assume valid tracked SG reply')
    p.add_argument('--destination-port', type=int, required=True)
    p.add_argument('--complete-config', action='store_true', help='Assert all SG rules and attachments are represented')
    p.add_argument('--assume-direct-private', action='store_true', help='Assert direct same-VPC private traffic without middlebox')
    p.add_argument('--complete-nacl-config', action='store_true', help='Assert ACL rules and associations are complete')
    p.add_argument('--assume-unmodified-default-nacl', action='store_true', help='Assume unmanaged default IPv4 ACL is unchanged')
    p.add_argument('--trace-forwarding', action='store_true', help='Analyze static forwarding candidate')
    p.add_argument('--complete-routing-config', action='store_true', help='Assert route inventory is complete')
    p.add_argument('--output', type=Path)
    a = p.parse_args()
    if not 0 <= a.destination_port <= 65535:
        p.error('destination port must be 0..65535')
    if a.source_port is not None and not 1 <= a.source_port <= 65535:
        p.error('source port must be 1..65535')
    identity = input_identity(a.terraform)
    resources = [r for path in a.terraform for r in parse_terraform(path)]
    if input_identity(a.terraform) != identity:
        p.error('Terraform inputs changed while reading')
    if len({r.id for r in resources}) != len(resources):
        p.error('duplicate Terraform resource addresses')
    scenario = CommunicationScenario(source_subnet=a.source_subnet, source_resource=a.source_resource,
        source_ip=a.source_ip, destination_resource=a.destination_resource, destination_ip=a.destination_ip,
        protocol=a.protocol, destination_port=a.destination_port, complete_config=a.complete_config,
        assume_direct_private=a.assume_direct_private, complete_nacl_config=a.complete_nacl_config,
        assume_unmodified_default_nacl=a.assume_unmodified_default_nacl, source_port=a.source_port)
    if a.trace_session:
        from backend.analyzer.session_analyzer import analyze_session
        result = analyze_session(resources, scenario, complete_routing_config=a.complete_routing_config,
                                 assume_tracked_response=a.assume_tracked_response)
    else:
        result = analyze_communication(resources, scenario, [SECURITY_GROUP_CHECK, NETWORK_ACL_CHECK], trace=a.trace_forwarding, complete_routing_config=a.complete_routing_config)
    result['input_identity'] = identity
    result['analysis_type'] = 'STATIC_IAC_PREDICTION'
    raw = json.dumps(result, ensure_ascii=False, indent=2)
    if a.output:
        a.output.parent.mkdir(parents=True, exist_ok=True)
        a.output.write_text(raw+'\n', encoding='utf-8')
    print(raw)

if __name__ == '__main__':
    main()
