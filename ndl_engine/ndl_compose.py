"""
NDL Docker Compose Generator
Transforms the Intermediate Representation (IR) into a valid docker-compose.yml string.
"""

import yaml
from typing import Dict, Any, List

# Import IR classes for type hinting
try:
    from ndl_converter import IREnvironment, IRServiceInstance
except ImportError:
    # Fallback for standalone testing
    pass

class DockerComposeGenerator:
    def __init__(self, version: str = "3.8"):
        self.version = version

    def generate(self, ir_env: 'IREnvironment') -> str:
        """
        Main entry point. Converts IR object to YAML string.
        """
        compose_dict = {
            "version": self.version,
            "networks": self._generate_networks(ir_env.networks),
            "services": self._generate_services(ir_env.services),
            "volumes": self._generate_volumes(ir_env.services)
        }
        
        # Remove empty keys to keep YAML clean
        if not compose_dict["volumes"]:
            del compose_dict["volumes"]

        return yaml.dump(compose_dict, sort_keys=False, default_flow_style=False)

    def _generate_networks(self, networks: Dict) -> Dict[str, Any]:
        """
        Maps NDL Networks to Docker Compose networks.
        Ensures strict IPAM configuration (subnet + gateway).
        """
        out = {}
        for name, net_spec in networks.items():
            net_config = {
                "driver": "bridge",
                "ipam": {
                    "config": [
                        {
                            "subnet": net_spec.subnet
                        }
                    ]
                },
                "driver_opts": {
                    "com.docker.network.bridge.name": name
                }
            }
            
            # Add gateway if specified
            if net_spec.gateway:
                net_config["ipam"]["config"][0]["gateway"] = net_spec.gateway
                
            out[name] = net_config
        return out

    def _generate_services(self, services: List['IRServiceInstance']) -> Dict[str, Any]:
        """
        Maps IR Service Instances to Docker Compose services.
        Handles IP assignment, volumes, and capabilities.
        """
        out = {}
        for svc in services:
            # Base service definition
            service_def = {
                "image": svc.image,
                "container_name": svc.name,
                "hostname": svc.name,
                "networks": {
                    svc.network: {
                        "ipv4_address": svc.ip
                    }
                },
                "environment": svc.env,
                "labels": {
                    "com.ndl.original_name": svc.base_name,
                    "com.ndl.managed": "true"
                }
            }

            # Handle Ports
            if svc.ports:
                service_def["ports"] = svc.ports

            # Handle Volumes (Assumption: svc has .volumes attribute, if not, skip)
            if hasattr(svc, 'volumes') and svc.volumes:
                service_def["volumes"] = svc.volumes

            # Heuristic: If it's a Router or Firewall, give it superpowers
            # (In a real implementation, check for specific flags/classes in IR)
            if "router" in svc.base_name.lower() or "firewall" in svc.base_name.lower():
                service_def["cap_add"] = ["NET_ADMIN"]
                service_def["sysctls"] = {"net.ipv4.ip_forward": "1"}

            out[svc.name] = service_def
            
        return out

    def _generate_volumes(self, services: List['IRServiceInstance']) -> Dict[str, Any]:
        """
        Scans services for named volumes to declare them at top-level.
        """
        volumes = {}
        for svc in services:
            if not hasattr(svc, 'volumes') or not svc.volumes:
                continue
                
            for vol_str in svc.volumes:
                # Docker volume string format: "source:target:mode"
                parts = vol_str.split(':')
                source = parts[0]
                
                # If source is a path (./, /), it's a bind mount, not a named volume
                if source.startswith('.') or source.startswith('/'):
                    continue
                
                # It's a named volume
                volumes[source] = {}
                
        return volumes