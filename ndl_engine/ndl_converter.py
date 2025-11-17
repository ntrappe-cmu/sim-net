"""
NDL to Intermediate Structure Converter

Transforms Network Definition Language (NDL) files into Python data structures
for Docker Compose generation and validation.
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Any, Tuple
from ipaddress import ip_network, IPv4Address, ip_address
import re


# ============================================================================
# Data Classes - Internal Structures
# ============================================================================

@dataclass
class Network:
    """Represents a network segment"""
    name: str
    type: str  # bridge, overlay, macvlan, etc.
    subnet: str
    gateway: Optional[str] = None
    vlan: Optional[int] = None
    dns: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        # Auto-assign gateway if not provided
        if not self.gateway:
            network = ip_network(self.subnet, strict=False)
            self.gateway = str(network.network_address + 1)


@dataclass
class VolumeMount:
    """Represents a volume mount point"""
    volume: str
    path: str


@dataclass
class Service:
    """Represents a service/container instance"""
    name: str
    image: str
    network: str
    ip: Optional[str] = None
    ports: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    volumes: List[VolumeMount] = field(default_factory=list)
    is_instance: bool = False  # True if generated from COUNT>1
    base_name: Optional[str] = None  # Original name if is_instance=True


@dataclass
class Component:
    """Represents an ICS/SCADA component"""
    name: str
    type: str  # plc, hmi, historian, etc.
    network: str
    ip: Optional[str] = None
    critical: bool = False
    vendor: Optional[str] = None
    model: Optional[str] = None
    image: Optional[str] = None
    is_instance: bool = False
    base_name: Optional[str] = None
    
    def __post_init__(self):
        # Auto-assign image based on type if not provided
        if not self.image:
            default_images = {
                'plc': 'softplc:latest',
                'hmi': 'scadabr:latest',
                'historian': 'timescaledb:latest',
                'actuator': 'ics-actuator:latest',
                'sensor': 'ics-sensor:latest',
                'rtu': 'ics-rtu:latest',
                'gateway': 'ics-gateway:latest'
            }
            self.image = default_images.get(self.type, 'alpine:latest')


@dataclass
class Volume:
    """Represents a persistent volume"""
    name: str
    type: str  # local, nfs, tmpfs, bind, external
    size: Optional[str] = None
    path: Optional[str] = None
    driver: str = "local"
    driver_opts: Dict[str, str] = field(default_factory=dict)
    labels: Dict[str, str] = field(default_factory=dict)


@dataclass
class RouterInterface:
    """Represents a router interface"""
    name: str
    network: str
    ip: str


@dataclass
class Router:
    """Represents a routing device"""
    name: str
    networks: List[str]
    image: str
    interfaces: List[RouterInterface] = field(default_factory=list)


@dataclass
class Zone:
    """Represents a security zone"""
    name: str
    type: str  # dmz, internal, external, ot, it, etc.
    networks: List[str]
    trust_level: int = 5
    
    def __post_init__(self):
        # Auto-assign trust level based on type if not explicitly set
        if not hasattr(self, '_trust_set'):
            default_trust = {
                'external': 0,
                'dmz': 3,
                'internal': 7,
                'ot': 9,
                'it': 5,
                'management': 8,
                'restricted': 10
            }
            if self.type in default_trust:
                self.trust_level = default_trust[self.type]


@dataclass
class Group:
    """Represents a logical grouping"""
    name: str
    members: List[str]  # Will be expanded to actual instance names
    role: str
    tier: Optional[str] = None


@dataclass
class Vulnerability:
    """Represents a vulnerability (metadata only)"""
    target: str
    type: str
    cve: Optional[str] = None
    severity: Optional[str] = None
    port: Optional[str] = None
    exploit: Optional[str] = None


@dataclass
class Credential:
    """Represents credential relationships"""
    source: str
    target: str
    type: str
    username: str = "admin"
    strength: Optional[str] = None
    shared: bool = False


@dataclass
class AttackChain:
    """Represents an attack chain"""
    name: str
    path: List[str]  # List of services in order
    type: str
    goal: Optional[str] = None


@dataclass
class Rule:
    """Represents connectivity or security rules"""
    name: str
    rule_type: str  # allow, block, firewall, ids, ips, etc.
    source: Optional[str] = None
    destination: Optional[str] = None
    ports: List[str] = field(default_factory=list)
    protocol: str = "tcp"
    bidirectional: bool = False
    between: List[str] = field(default_factory=list)  # For RULE statements
    action: Optional[str] = None
    log: bool = False


@dataclass
class Topology:
    """Optional topology metadata"""
    type: str
    layers: Optional[int] = None
    width: Optional[int] = None


# ============================================================================
# Intermediate Representation
# ============================================================================

@dataclass
class IntermediateRepresentation:
    """Complete intermediate structure"""
    topology: Optional[Topology] = None
    networks: List[Network] = field(default_factory=list)
    volumes: List[Volume] = field(default_factory=list)
    services: List[Service] = field(default_factory=list)
    components: List[Component] = field(default_factory=list)
    routers: List[Router] = field(default_factory=list)
    zones: List[Zone] = field(default_factory=list)
    groups: List[Group] = field(default_factory=list)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    credentials: List[Credential] = field(default_factory=list)
    attack_chains: List[AttackChain] = field(default_factory=list)
    rules: List[Rule] = field(default_factory=list)
    
    # Internal tracking for validation and expansion
    _network_map: Dict[str, Network] = field(default_factory=dict)
    _service_instances: Dict[str, List[str]] = field(default_factory=dict)  # base_name -> [instances]
    _component_instances: Dict[str, List[str]] = field(default_factory=dict)
    _allocated_ips: Dict[str, Set[str]] = field(default_factory=dict)  # network -> set of IPs
    _volume_names: Set[str] = field(default_factory=set)


# ============================================================================
# Parser Utilities
# ============================================================================

class NDLParser:
    """Parses NDL statements into intermediate structures"""
    
    @staticmethod
    def parse_key_value_list(value_string: str) -> Dict[str, str]:
        """Parse KEY=value,KEY2=value2 into dictionary"""
        if not value_string:
            return {}
        
        result = {}
        pairs = value_string.split(',')
        for pair in pairs:
            if '=' in pair:
                key, val = pair.split('=', 1)
                result[key.strip()] = val.strip()
        return result
    
    @staticmethod
    def parse_comma_list(value_string: str) -> List[str]:
        """Parse comma-separated list"""
        if not value_string:
            return []
        return [item.strip() for item in value_string.split(',')]
    
    @staticmethod
    def parse_volume_mounts(volumes_string: str) -> List[VolumeMount]:
        """Parse volume=path,volume2=path2 into list of VolumeMount objects"""
        if not volumes_string:
            return []
        
        mounts = []
        pairs = volumes_string.split(',')
        for pair in pairs:
            if '=' in pair:
                vol, path = pair.split('=', 1)
                mounts.append(VolumeMount(volume=vol.strip(), path=path.strip()))
        return mounts
    
    @staticmethod
    def parse_arrow_path(path_string: str) -> List[str]:
        """Parse service1->service2->service3 into list"""
        return [s.strip() for s in path_string.split('->')]
    
    @staticmethod
    def parse_ip_range(ip_range_string: str) -> Tuple[str, str]:
        """Parse 10.1.0.10-10.1.0.20 into (start, end)"""
        parts = ip_range_string.split('-')
        return parts[0].strip(), parts[1].strip()
    
    @staticmethod
    def extract_params(statement: str) -> Dict[str, str]:
        """Extract KEY=value parameters from a statement line"""
        params = {}
        # Match KEY=value or KEY="quoted value"
        pattern = r'(\w+)=("(?:[^"\\]|\\.)*"|[^\s]+)'
        matches = re.findall(pattern, statement)
        
        for key, value in matches:
            # Remove quotes if present
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            params[key] = value
        
        return params


# ============================================================================
# NDL Converter - Main Class
# ============================================================================

class NDLConverter:
    """Converts NDL file to intermediate representation"""
    
    def __init__(self):
        self.ir = IntermediateRepresentation()
        self.parser = NDLParser()
        self._current_router = None  # Track router being parsed
    
    def _parse_bool(self, params: Dict[str, str], key: str, default: bool = False) -> bool:
        """Helper method to consistently parse boolean parameters"""
        return params.get(key, str(default).lower()).lower() == 'true'
    
    def convert_file(self, filepath: str) -> IntermediateRepresentation:
        """Convert NDL file to intermediate representation"""
        with open(filepath, 'r') as f:
            lines = f.readlines()
        
        return self.convert_lines(lines)
    
    def convert_lines(self, lines: List[str]) -> IntermediateRepresentation:
        """Convert list of NDL lines to intermediate representation"""
        # Phase 1: Parse statements into internal structures
        self._parse_statements(lines)
        
        # Phase 2: Expand multi-instances (COUNT>1)
        self._expand_instances()
        
        # Phase 3: Resolve group memberships
        self._resolve_groups()
        
        return self.ir
    
    def _parse_statements(self, lines: List[str]):
        """Parse NDL statements line by line"""
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            
            # Skip empty lines and comments
            if not line or line.startswith('#'):
                i += 1
                continue
            
            # Detect statement type
            if line.startswith('TOPOLOGY'):
                self._parse_topology(line)
            elif line.startswith('NETWORK'):
                self._parse_network(line)
            elif line.startswith('VOLUME'):
                self._parse_volume(line)
            elif line.startswith('SERVICE'):
                self._parse_service(line)
            elif line.startswith('COMPONENT'):
                self._parse_component(line)
            elif line.startswith('ZONE'):
                self._parse_zone(line)
            elif line.startswith('GROUP'):
                self._parse_group(line)
            elif line.startswith('ROUTER'):
                # Router can span multiple lines with INTERFACE sub-statements
                i = self._parse_router(lines, i)
                i += 1
                continue
            elif line.startswith('VULN'):
                self._parse_vulnerability(line)
            elif line.startswith('CREDS'):
                self._parse_credential(line)
            elif line.startswith('CHAIN'):
                self._parse_chain(line)
            elif line.startswith('ALLOW'):
                self._parse_allow(line)
            elif line.startswith('BLOCK'):
                self._parse_block(line)
            elif line.startswith('RULE'):
                self._parse_rule(line)
            
            i += 1
    
    def _parse_topology(self, line: str):
        """Parse TOPOLOGY statement"""
        params = self.parser.extract_params(line)
        
        self.ir.topology = Topology(
            type=params['TYPE'],
            layers=int(params['LAYERS']) if 'LAYERS' in params else None,
            width=int(params['WIDTH']) if 'WIDTH' in params else None
        )
    
    def _parse_network(self, line: str):
        """Parse NETWORK statement"""
        # Extract name (first word after NETWORK)
        parts = line.split()
        name = parts[1]
        
        params = self.parser.extract_params(line)
        
        network = Network(
            name=name,
            type=params['TYPE'],
            subnet=params['SUBNET'],
            gateway=params.get('GATEWAY'),
            vlan=int(params['VLAN']) if 'VLAN' in params else None,
            dns=self.parser.parse_comma_list(params.get('DNS', ''))
        )
        
        self.ir.networks.append(network)
        self.ir._network_map[name] = network
        self.ir._allocated_ips[name] = set()
        
        # Reserve gateway IP
        if network.gateway:
            self.ir._allocated_ips[name].add(network.gateway)
    
    def _parse_volume(self, line: str):
        """Parse VOLUME statement"""
        parts = line.split()
        name = parts[1]
        
        params = self.parser.extract_params(line)
        
        volume = Volume(
            name=name,
            type=params['TYPE'],
            size=params.get('SIZE'),
            path=params.get('PATH'),
            driver=params.get('DRIVER', 'local'),
            driver_opts=self.parser.parse_key_value_list(params.get('DRIVER_OPTS', '')),
            labels=self.parser.parse_key_value_list(params.get('LABELS', ''))
        )
        
        self.ir.volumes.append(volume)
        self.ir._volume_names.add(name)
    
    def _parse_service(self, line: str):
        """Parse SERVICE statement (will be expanded later if COUNT>1)"""
        parts = line.split()
        name = parts[1]
        
        params = self.parser.extract_params(line)
        
        # Store raw service definition for expansion
        count = int(params.get('COUNT', '1'))
        image = params['IMAGE']
        network = params['NETWORK']
        
        # Parse optional parameters
        ip = params.get('IP')
        ip_range = params.get('IP_RANGE')
        ports = self.parser.parse_comma_list(params.get('PORTS', ''))
        # ENV format: ENV=KEY1=value1,KEY2=value2 (comma-separated key=value pairs)
        env = self.parser.parse_key_value_list(params.get('ENV', ''))
        
        # Handle volumes
        volumes = []
        if 'VOLUME' in params:
            # Single volume with default path
            vol_name = params['VOLUME']
            default_path = f"/data"  # Can be made smarter based on image
            volumes.append(VolumeMount(volume=vol_name, path=default_path))
        
        if 'VOLUMES' in params:
            volumes.extend(self.parser.parse_volume_mounts(params['VOLUMES']))
        
        # Store for expansion phase
        service_def = {
            'name': name,
            'count': count,
            'image': image,
            'network': network,
            'ip': ip,
            'ip_range': ip_range,
            'ports': ports,
            'env': env,
            'volumes': volumes,
            'volume_pattern': params.get('VOLUME_PATTERN')
        }
        
        # Store in temporary structure for expansion
        if not hasattr(self, '_service_defs'):
            self._service_defs = []
        self._service_defs.append(service_def)
    
    def _parse_component(self, line: str):
        """Parse COMPONENT statement"""
        parts = line.split()
        name = parts[1]
        
        params = self.parser.extract_params(line)
        
        # Store for expansion (similar to service)
        count = int(params.get('COUNT', '1'))
        
        component_def = {
            'name': name,
            'count': count,
            'type': params['TYPE'],
            'network': params['NETWORK'],
            'ip': params.get('IP'),
            'ip_range': params.get('IP_RANGE'),
            'critical': self._parse_bool(params, 'CRITICAL', False),
            'vendor': params.get('VENDOR'),
            'model': params.get('MODEL'),
            'image': params.get('IMAGE')
        }
        
        if not hasattr(self, '_component_defs'):
            self._component_defs = []
        self._component_defs.append(component_def)
    
    def _parse_zone(self, line: str):
        """Parse ZONE statement"""
        parts = line.split()
        name = parts[1]
        
        params = self.parser.extract_params(line)
        
        zone = Zone(
            name=name,
            type=params['TYPE'],
            networks=self.parser.parse_comma_list(params['NETWORKS']),
            trust_level=int(params['TRUST_LEVEL']) if 'TRUST_LEVEL' in params else 5
        )
        
        # Mark trust level as explicitly set if provided
        if 'TRUST_LEVEL' in params:
            zone._trust_set = True
        
        zone.__post_init__()
        self.ir.zones.append(zone)
    
    def _parse_group(self, line: str):
        """Parse GROUP statement"""
        parts = line.split()
        name = parts[1]
        
        params = self.parser.extract_params(line)
        
        group = Group(
            name=name,
            members=self.parser.parse_comma_list(params['MEMBERS']),
            role=params['ROLE'],
            tier=params.get('TIER')
        )
        
        self.ir.groups.append(group)
    
    def _parse_router(self, lines: List[str], start_idx: int) -> int:
        """Parse ROUTER statement with INTERFACE sub-statements"""
        line = lines[start_idx].strip()
        parts = line.split()
        name = parts[1]
        
        params = self.parser.extract_params(line)
        
        router = Router(
            name=name,
            networks=self.parser.parse_comma_list(params['NETWORKS']),
            image=params['IMAGE']
        )
        
        # Parse INTERFACE sub-statements
        i = start_idx + 1
        while i < len(lines):
            interface_line = lines[i]
            
            # Check if this is an indented INTERFACE line
            if interface_line.startswith('  INTERFACE'):
                iface_params = self.parser.extract_params(interface_line.strip())
                iface_parts = interface_line.strip().split()
                iface_name = iface_parts[1]
                
                interface = RouterInterface(
                    name=iface_name,
                    network=iface_params['NETWORK'],
                    ip=iface_params['IP']
                )
                
                router.interfaces.append(interface)
                
                # Reserve router interface IP
                if iface_params['NETWORK'] not in self.ir._allocated_ips:
                    self.ir._allocated_ips[iface_params['NETWORK']] = set()
                self.ir._allocated_ips[iface_params['NETWORK']].add(iface_params['IP'])
                
                i += 1
            else:
                # End of INTERFACE statements
                break
        
        self.ir.routers.append(router)
        return i - 1  # Return last line index we processed
    
    def _parse_vulnerability(self, line: str):
        """Parse VULN statement"""
        parts = line.split()
        target = parts[1]
        
        params = self.parser.extract_params(line)
        
        vuln = Vulnerability(
            target=target,
            type=params['TYPE'],
            cve=params.get('CVE'),
            severity=params.get('SEVERITY'),
            port=params.get('PORT'),
            exploit=params.get('EXPLOIT')
        )
        
        self.ir.vulnerabilities.append(vuln)
    
    def _parse_credential(self, line: str):
        """Parse CREDS statement"""
        parts = line.split()
        source = parts[1]
        
        params = self.parser.extract_params(line)
        
        cred = Credential(
            source=source,
            target=params['TARGET'],
            type=params['TYPE'],
            username=params.get('USERNAME', 'admin'),
            strength=params.get('STRENGTH'),
            shared=self._parse_bool(params, 'SHARED', False)
        )
        
        self.ir.credentials.append(cred)
    
    def _parse_chain(self, line: str):
        """Parse CHAIN statement"""
        parts = line.split()
        name = parts[1]
        
        params = self.parser.extract_params(line)
        
        chain = AttackChain(
            name=name,
            path=self.parser.parse_arrow_path(params['PATH']),
            type=params['TYPE'],
            goal=params.get('GOAL')
        )
        
        self.ir.attack_chains.append(chain)
    
    def _parse_allow(self, line: str):
        """Parse ALLOW statement"""
        # Extract source -> destination
        arrow_match = re.search(r'(\S+)\s*->\s*(\S+)', line)
        if not arrow_match:
            return
        
        source = arrow_match.group(1)
        destination = arrow_match.group(2)
        
        params = self.parser.extract_params(line)
        
        rule = Rule(
            name=f"allow_{source}_to_{destination}",
            rule_type='allow',
            source=source,
            destination=destination,
            ports=self.parser.parse_comma_list(params.get('PORTS', '')),
            protocol=params.get('PROTOCOL', 'tcp'),
            bidirectional=self._parse_bool(params, 'BIDIRECTIONAL', False)
        )
        
        self.ir.rules.append(rule)
    
    def _parse_block(self, line: str):
        """Parse BLOCK statement"""
        arrow_match = re.search(r'(\S+)\s*->\s*(\S+)', line)
        if not arrow_match:
            return
        
        source = arrow_match.group(1)
        destination = arrow_match.group(2)
        
        params = self.parser.extract_params(line)
        
        rule = Rule(
            name=f"block_{source}_to_{destination}",
            rule_type='block',
            source=source,
            destination=destination,
            ports=self.parser.parse_comma_list(params.get('PORTS', '')),
            protocol=params.get('PROTOCOL', 'tcp')
        )
        
        self.ir.rules.append(rule)
    
    def _parse_rule(self, line: str):
        """Parse RULE statement"""
        parts = line.split()
        name = parts[1]
        
        params = self.parser.extract_params(line)
        
        rule = Rule(
            name=name,
            rule_type=params['TYPE'],
            between=self.parser.parse_comma_list(params['BETWEEN']),
            action=params.get('ACTION'),
            log=self._parse_bool(params, 'LOG', False)
        )
        
        self.ir.rules.append(rule)
    
    def _expand_instances(self):
        """Expand services and components with COUNT>1"""
        # Expand services
        if hasattr(self, '_service_defs'):
            for svc_def in self._service_defs:
                self._expand_service(svc_def)
        
        # Expand components
        if hasattr(self, '_component_defs'):
            for comp_def in self._component_defs:
                self._expand_component(comp_def)
    
    def _expand_service(self, svc_def: Dict[str, Any]):
        """Expand a service definition into instances"""
        count = svc_def['count']
        base_name = svc_def['name']
        
        # Get network object for validation
        network_obj = self.ir._network_map.get(svc_def['network'])
        if not network_obj:
            raise ValueError(f"Network '{svc_def['network']}' not found for service '{base_name}'")
        
        subnet = ip_network(network_obj.subnet, strict=False)
        
        # Allocate IPs if needed
        ips = []
        if svc_def['ip_range']:
            start_ip, end_ip = self.parser.parse_ip_range(svc_def['ip_range'])
            all_ips = self._generate_ip_range(start_ip, end_ip, count)
            
            # Validate that all IPs are within subnet
            for ip_str in all_ips:
                if ip_address(ip_str) not in subnet:
                    raise ValueError(
                        f"IP {ip_str} for service '{base_name}' is not within subnet {subnet}"
                    )
            ips = all_ips
        elif svc_def['ip']:
            # Validate single IP is within subnet
            if ip_address(svc_def['ip']) not in subnet:
                raise ValueError(
                    f"IP {svc_def['ip']} for service '{base_name}' is not within subnet {subnet}"
                )
            ips = [svc_def['ip']]
        
        # Track instances
        instances = []
        
        for i in range(count):
            # Generate instance name
            if count == 1:
                instance_name = base_name
            else:
                instance_name = f"{base_name}_{i+1}"
            
            instances.append(instance_name)
            
            # Handle volumes
            volumes = list(svc_def['volumes'])  # Copy base volumes
            
            # Handle VOLUME_PATTERN
            if svc_def['volume_pattern'] and count > 1:
                pattern = svc_def['volume_pattern']
                if '=' in pattern:
                    vol_pattern, mount_path = pattern.split('=', 1)
                    if '{instance}' not in vol_pattern:
                        raise ValueError(f"VOLUME_PATTERN must contain '{{instance}}' placeholder for service '{base_name}' (got: '{pattern}')")
                    vol_name = vol_pattern.replace('{instance}', str(i+1))
                    volumes.append(VolumeMount(volume=vol_name, path=mount_path))
                    
                    # Auto-create volume
                    if vol_name not in self.ir._volume_names:
                        self.ir.volumes.append(Volume(name=vol_name, type='local'))
                        self.ir._volume_names.add(vol_name)
            
            # Create service instance
            service = Service(
                name=instance_name,
                image=svc_def['image'],
                network=svc_def['network'],
                ip=ips[i] if i < len(ips) else None,
                ports=svc_def['ports'],
                env=svc_def['env'],
                volumes=volumes,
                is_instance=count > 1,
                base_name=base_name if count > 1 else None
            )
            
            self.ir.services.append(service)
            
            # Track allocated IP
            if service.ip and service.network in self.ir._allocated_ips:
                self.ir._allocated_ips[service.network].add(service.ip)
        
        # Track instances for group expansion
        self.ir._service_instances[base_name] = instances
    
    def _expand_component(self, comp_def: Dict[str, Any]):
        """Expand a component definition into instances"""
        count = comp_def['count']
        base_name = comp_def['name']
        
        # Get network object for validation
        network_obj = self.ir._network_map.get(comp_def['network'])
        if not network_obj:
            raise ValueError(f"Network '{comp_def['network']}' not found for component '{base_name}'")
        
        subnet = ip_network(network_obj.subnet, strict=False)
        
        # Allocate IPs if needed
        ips = []
        if comp_def['ip_range']:
            start_ip, end_ip = self.parser.parse_ip_range(comp_def['ip_range'])
            all_ips = self._generate_ip_range(start_ip, end_ip, count)
            
            # Validate that all IPs are within subnet
            for ip_str in all_ips:
                if ip_address(ip_str) not in subnet:
                    raise ValueError(
                        f"IP {ip_str} for component '{base_name}' is not within subnet {subnet}"
                    )
            ips = all_ips
        elif comp_def['ip']:
            # Validate single IP is within subnet
            if ip_address(comp_def['ip']) not in subnet:
                raise ValueError(
                    f"IP {comp_def['ip']} for component '{base_name}' is not within subnet {subnet}"
                )
            ips = [comp_def['ip']]
        
        # Track instances
        instances = []
        
        for i in range(count):
            # Generate instance name
            if count == 1:
                instance_name = base_name
            else:
                instance_name = f"{base_name}_{i+1}"
            
            instances.append(instance_name)
            
            # Create component instance
            component = Component(
                name=instance_name,
                type=comp_def['type'],
                network=comp_def['network'],
                ip=ips[i] if i < len(ips) else None,
                critical=comp_def['critical'],
                vendor=comp_def['vendor'],
                model=comp_def['model'],
                image=comp_def['image'],
                is_instance=count > 1,
                base_name=base_name if count > 1 else None
            )
            
            self.ir.components.append(component)
            
            # Track allocated IP
            if component.ip and component.network in self.ir._allocated_ips:
                self.ir._allocated_ips[component.network].add(component.ip)
        
        # Track instances for group expansion
        self.ir._component_instances[base_name] = instances
    
    def _generate_ip_range(self, start_ip: str, end_ip: str, count: int) -> List[str]:
        """Generate list of IPs from start to end (inclusive)"""
        start = IPv4Address(start_ip)
        end = IPv4Address(end_ip)
        
        # Validate that start <= end
        if start > end:
            raise ValueError(
                f"Invalid IP_RANGE {start_ip}-{end_ip}: start IP must be less than or equal to end IP"
            )
        
        # Calculate available IPs in range
        available_ips = int(end) - int(start) + 1
        
        # Raise error if count exceeds available IPs
        if count > available_ips:
            raise ValueError(
                f"IP_RANGE {start_ip}-{end_ip} has only {available_ips} IP(s) "
                f"but COUNT={count} requires {count} IP(s)"
            )
        
        ips = []
        current = start
        for _ in range(count):
            ips.append(str(current))
            current = IPv4Address(int(current) + 1)
        
        return ips
    
    def _resolve_groups(self):
        """Resolve group members to actual instance names"""
        for group in self.ir.groups:
            expanded_members = []
            
            for member in group.members:
                # Check if this is a base name that was expanded
                if member in self.ir._service_instances:
                    expanded_members.extend(self.ir._service_instances[member])
                elif member in self.ir._component_instances:
                    expanded_members.extend(self.ir._component_instances[member])
                else:
                    # It's a specific instance name or single-count service
                    expanded_members.append(member)
            
            group.members = expanded_members


# ============================================================================
# Example Usage
# ============================================================================

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python ndl_converter.py <ndl_file>")
        sys.exit(1)
    
    converter = NDLConverter()
    ir = converter.convert_file(sys.argv[1])
    
    # Print summary
    print(f"\n=== Conversion Summary ===")
    print(f"Networks: {len(ir.networks)}")
    print(f"Volumes: {len(ir.volumes)}")
    print(f"Services: {len(ir.services)}")
    print(f"Components: {len(ir.components)}")
    print(f"Routers: {len(ir.routers)}")
    print(f"Zones: {len(ir.zones)}")
    print(f"Groups: {len(ir.groups)}")
    print(f"Rules: {len(ir.rules)}")
    
    # Print detailed breakdown
    print(f"\n=== Service Instances ===")
    for base, instances in ir._service_instances.items():
        print(f"{base}: {instances}")
    
    print(f"\n=== Component Instances ===")
    for base, instances in ir._component_instances.items():
        print(f"{base}: {instances}")
    
    print(f"\n=== IP Allocations ===")
    for network, ips in ir._allocated_ips.items():
        print(f"{network}: {sorted(ips)}")
