"""
NDL IR Converter
Transforms Parsed NDL Specifications into fully expanded Intermediate Representation.
Handles IP allocation, count expansion, and reference resolution.
"""

import sys
import ipaddress
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from ndl_parser import NDLParser, SpecNetwork, SpecService

# ============================================================================
# Intermediate Representation (IR) Classes
# These differ from Spec classes because they represent CONCRETE instances
# ============================================================================

@dataclass
class IRServiceInstance:
    name: str           # e.g., "web-server-1"
    base_name: str      # e.g., "web-server"
    image: str
    network: str
    ip: str             # Allocated IP
    ports: List[str]
    env: Dict[str, str]
    volumes: List[str] = field(default_factory=list)

@dataclass
class IREnvironment:
    networks: Dict[str, SpecNetwork] = field(default_factory=dict)
    services: List[IRServiceInstance] = field(default_factory=list)
    # Add rules, volumes, etc. as needed

# ============================================================================
# Converter Logic
# ============================================================================

class NDLConverter:
    def __init__(self):
        self.ir = IREnvironment()
        self._ip_allocations = {} # map: network_name -> set(used_ips)

    def convert(self, filename: str) -> Optional[IREnvironment]:
        # 1. Use the Parser to get the clean specification
        parser = NDLParser()
        spec, errors, warnings = parser.parse(filename)

        if errors:
            print("\n!!! Parsing Errors Found !!!")
            for e in errors:
                print(f"[{e.file_name}:{e.line_number}] {e.message}")
            return None

        # 2. Build IR: Networks
        print(f"Converting {len(spec.networks)} networks...")
        for net in spec.networks:
            self.ir.networks[net.name] = net
            # Initialize IP tracking (reserve gateway)
            try:
                network_obj = ipaddress.ip_network(net.subnet, strict=False)
                gateway_ip = net.gateway if net.gateway else str(network_obj.network_address + 1)
                self._ip_allocations[net.name] = {gateway_ip}
            except Exception as e:
                print(f"Error initializing network {net.name}: {e}")

        # 3. Build IR: Expand Services & Allocate IPs
        print(f"Expanding {len(spec.services)} service definitions...")
        for svc_spec in spec.services:
            self._expand_service(svc_spec)

        return self.ir

    def _expand_service(self, spec: SpecService):
        """
        Takes a Service Specification (which might have count=3)
        and creates 3 concrete IRServiceInstances with unique IPs.
        """
        net_def = self.ir.networks.get(spec.network)
        if not net_def:
            # logic error (should have been caught by parser validation)
            return

        network_obj = ipaddress.ip_network(net_def.subnet, strict=False)
        
        for i in range(1, spec.count + 1):
            # Generate Instance Name
            instance_name = spec.name if spec.count == 1 else f"{spec.name}-{i}"
            
            # Allocate Next Available IP
            ip_addr = self._get_next_free_ip(spec.network, network_obj)
            
            if not ip_addr:
                print(f"ERROR: IP Exhaustion in network {spec.network}")
                continue

            # Create Instance
            instance = IRServiceInstance(
                name=instance_name,
                base_name=spec.name,
                image=spec.image,
                network=spec.network,
                ip=ip_addr,
                ports=spec.ports,
                env=spec.env
            )
            self.ir.services.append(instance)

    def _get_next_free_ip(self, net_name: str, net_obj) -> Optional[str]:
        used = self._ip_allocations[net_name]
        
        # Simple linear search (efficient enough for N < 1000)
        # Skip .0 (network) and .1 (gateway usually)
        for ip in net_obj.hosts():
            ip_str = str(ip)
            if ip_str not in used:
                used.add(ip_str)
                return ip_str
        return None

# ============================================================================
# Main Execution
# ============================================================================

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: ndl_converter.py <file>")
        sys.exit(1)

    converter = NDLConverter()
    result = converter.convert(sys.argv[1])

    if result:
        print("\n=== Conversion Successful ===")
        print(f"Generated {len(result.services)} container instances.")
        for svc in result.services:
            print(f"  - {svc.name} [{svc.image}] -> {svc.ip} ({svc.network})")