#!/usr/bin/env python3
"""
NDL Validation Parser
A complete parser that validates NDL files for syntax and semantic correctness.
Focuses on validation and error reporting, not AST generation.
"""

import re
import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from enum import Enum


# ============================================================================
# Error Reporting
# ============================================================================

class Severity(Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"
    INFO = "INFO"


@dataclass
class ValidationError:
    """Represents a validation error or warning"""
    severity: Severity
    message: str
    line_number: int
    line_text: str
    suggestion: Optional[str] = None
    
    def __str__(self):
        severity_colors = {
            Severity.ERROR: "\033[91m",    # Red
            Severity.WARNING: "\033[93m",  # Yellow  
            Severity.INFO: "\033[94m"      # Blue
        }
        reset = "\033[0m"
        
        result = f"{severity_colors[self.severity]}{self.severity.value}{reset}: {self.message}\n"
        result += f"  Line {self.line_number}: {self.line_text}\n"
        if self.suggestion:
            result += f"  Fix: {self.suggestion}"
        return result


# ============================================================================
# Symbol Tables for Tracking Definitions
# ============================================================================

@dataclass
class NetworkInfo:
    name: str
    subnet: ipaddress.IPv4Network
    gateway: Optional[ipaddress.IPv4Address]
    type: str
    line_number: int
    allocated_ips: Set[ipaddress.IPv4Address] = field(default_factory=set)


@dataclass 
class ServiceInfo:
    name: str
    count: int
    network: str
    image: str
    ip: Optional[ipaddress.IPv4Address]
    ip_range: Optional[Tuple[ipaddress.IPv4Address, ipaddress.IPv4Address]]
    line_number: int
    expanded_names: List[str] = field(default_factory=list)


@dataclass
class VolumeInfo:
    name: str
    type: str
    line_number: int


@dataclass
class ComponentInfo:
    name: str
    type: str
    network: str
    count: int
    critical: bool
    line_number: int


# ============================================================================
# NDL Validation Parser
# ============================================================================

class NDLValidator:
    """
    Complete validation parser for NDL files.
    Performs both syntax and semantic validation.
    """
    
    # Statement order according to spec
    STATEMENT_ORDER = [
        'TOPOLOGY', 'INCLUDE', 'VOLUME', 'NETWORK', 'SERVICE',
        'COMPONENT', 'ZONE', 'GROUP', 'ROUTER', 'VULN', 
        'CREDS', 'CHAIN', 'ALLOW', 'BLOCK', 'RULE'
    ]
    
    # Valid values for various parameters
    NETWORK_TYPES = {'bridge', 'overlay', 'macvlan', 'ipvlan', 'host', 'none'}
    VOLUME_TYPES = {'local', 'nfs', 'tmpfs', 'bind', 'external'}
    COMPONENT_TYPES = {'plc', 'hmi', 'historian', 'actuator', 'sensor', 'rtu', 'gateway'}
    ZONE_TYPES = {'dmz', 'internal', 'external', 'ot', 'it', 'management', 'restricted'}
    VULN_TYPES = {'rce', 'sqli', 'xss', 'xxe', 'privesc', 'dos', 'info_disclosure', 
                  'default_creds', 'weak_crypto', 'firmware', 'buffer_overflow'}
    AUTH_TYPES = {'ssh', 'rdp', 'http', 'https', 'database', 'telnet', 'winrm', 'ldap'}
    PROTOCOLS = {'tcp', 'udp', 'icmp', 'all'}
    SEVERITIES = {'low', 'medium', 'high', 'critical'}
    
    def __init__(self):
        self.errors: List[ValidationError] = []
        self.warnings: List[ValidationError] = []
        
        # Symbol tables
        self.networks: Dict[str, NetworkInfo] = {}
        self.services: Dict[str, ServiceInfo] = {}
        self.volumes: Dict[str, VolumeInfo] = {}
        self.components: Dict[str, ComponentInfo] = {}
        self.zones: Dict[str, Any] = {}
        self.groups: Dict[str, Any] = {}
        self.routers: Dict[str, Any] = {}
        
        # Track statement order
        self.last_statement_index = -1
        self.current_line = 0
        
        # For semantic validation
        self.service_instances: Dict[str, List[str]] = {}
        self.ot_networks: Set[str] = set()
        self.it_networks: Set[str] = set()
        self.critical_components: List[str] = []
        
    def validate(self, text: str) -> Tuple[List[ValidationError], List[ValidationError]]:
        """
        Main validation entry point.
        Returns (errors, warnings)
        """
        lines = text.strip().split('\n')
        
        # First pass: Parse and validate syntax
        self._parse_and_validate_syntax(lines)
        
        # Second pass: Validate semantics
        self._validate_semantics()
        
        # Check security best practices
        self._check_security()
        
        return self.errors, self.warnings
    
    # ========================================================================
    # First Pass: Syntax Validation
    # ========================================================================
    
    def _parse_and_validate_syntax(self, lines: List[str]):
        """Parse lines and validate syntax"""
        i = 0
        while i < len(lines):
            self.current_line = i + 1
            line = lines[i]
            
            # Skip comments and empty lines
            clean_line = line.split('#')[0].strip()
            if not clean_line:
                i += 1
                continue
            
            # Handle indented INTERFACE lines
            if line.startswith('  '):
                # This should only be valid after ROUTER
                if not self._validate_interface_context(line, i):
                    self._add_error(
                        "INTERFACE must be indented under ROUTER statement",
                        i, line,
                        "Remove indentation or place under a ROUTER"
                    )
                i += 1
                continue
            
            # Parse regular statement
            tokens = clean_line.split()
            if not tokens:
                i += 1
                continue
            
            keyword = tokens[0]
            
            # Validate statement order
            if keyword in self.STATEMENT_ORDER:
                self._validate_statement_order(keyword, i, line)
            
            # Route to appropriate validator
            validators = {
                'TOPOLOGY': self._validate_topology,
                'INCLUDE': self._validate_include,
                'VOLUME': self._validate_volume,
                'NETWORK': self._validate_network,
                'SERVICE': self._validate_service,
                'COMPONENT': self._validate_component,
                'ZONE': self._validate_zone,
                'GROUP': self._validate_group,
                'ROUTER': (self._validate_router, lines),  # Special case - needs lines
                'VULN': self._validate_vuln,
                'CREDS': self._validate_creds,
                'CHAIN': self._validate_chain,
                'ALLOW': self._validate_allow,
                'BLOCK': self._validate_block,
                'RULE': self._validate_rule
            }
            
            if keyword in validators:
                validator = validators[keyword]
                if keyword == 'ROUTER':
                    # Router needs access to following lines
                    skip = validator[0](tokens, i, line, validator[1])
                    i += skip
                else:
                    validator(tokens, i, line)
            else:
                self._add_error(
                    f"Unknown statement keyword: {keyword}",
                    i, line,
                    f"Valid keywords: {', '.join(self.STATEMENT_ORDER)}"
                )
            
            i += 1
    
    def _validate_statement_order(self, keyword: str, line_num: int, line: str):
        """Check if statement appears in correct order"""
        current_index = self.STATEMENT_ORDER.index(keyword)
        
        if current_index < self.last_statement_index:
            self._add_warning(
                f"{keyword} appears out of order",
                line_num, line,
                f"Place {keyword} statements before {self.STATEMENT_ORDER[self.last_statement_index]} statements"
            )
        else:
            self.last_statement_index = current_index
    
    def _validate_network(self, tokens: List[str], line_num: int, line: str):
        """Validate NETWORK statement syntax"""
        if len(tokens) < 2:
            self._add_error("NETWORK requires a name", line_num, line,
                           "NETWORK <name> TYPE=<type> SUBNET=<cidr>")
            return
        
        name = tokens[1]
        
        # Check for duplicate
        if name in self.networks:
            self._add_error(
                f"Duplicate network name: {name}",
                line_num, line,
                f"Network already defined at line {self.networks[name].line_number}"
            )
            return
        
        params = self._extract_params(tokens[2:])
        
        # Validate required parameters
        if 'TYPE' not in params:
            self._add_error("NETWORK requires TYPE parameter", line_num, line,
                           "Add TYPE=bridge|overlay|macvlan|ipvlan|host|none")
            return
        
        if 'SUBNET' not in params:
            self._add_error("NETWORK requires SUBNET parameter", line_num, line,
                           "Add SUBNET=<CIDR> (e.g., SUBNET=10.1.0.0/24)")
            return
        
        # Validate TYPE value
        if params['TYPE'] not in self.NETWORK_TYPES:
            self._add_error(
                f"Invalid network TYPE: {params['TYPE']}",
                line_num, line,
                f"Valid types: {', '.join(self.NETWORK_TYPES)}"
            )
        
        # Validate SUBNET format
        try:
            subnet = ipaddress.IPv4Network(params['SUBNET'])
        except ValueError as e:
            self._add_error(
                f"Invalid SUBNET format: {params['SUBNET']}",
                line_num, line,
                "Use CIDR notation (e.g., 10.1.0.0/24)"
            )
            return
        
        # Validate GATEWAY if provided
        gateway = None
        if 'GATEWAY' in params:
            try:
                gateway = ipaddress.IPv4Address(params['GATEWAY'])
                if gateway not in subnet:
                    self._add_error(
                        f"GATEWAY {gateway} not within SUBNET {subnet}",
                        line_num, line,
                        f"Gateway must be within {subnet.network_address+1} - {subnet.broadcast_address-1}"
                    )
            except ValueError:
                self._add_error(
                    f"Invalid GATEWAY IP: {params['GATEWAY']}",
                    line_num, line,
                    "Use valid IPv4 address (e.g., 10.1.0.1)"
                )
        
        # Store network info
        self.networks[name] = NetworkInfo(
            name=name,
            subnet=subnet,
            gateway=gateway,
            type=params['TYPE'],
            line_number=line_num + 1
        )
    
    def _validate_service(self, tokens: List[str], line_num: int, line: str):
        """Validate SERVICE statement syntax"""
        if len(tokens) < 2:
            self._add_error("SERVICE requires a name", line_num, line,
                           "SERVICE <name> COUNT=<n> IMAGE=<image> NETWORK=<network>")
            return
        
        name = tokens[1]
        params = self._extract_params(tokens[2:])
        
        # Check for duplicate
        if name in self.services:
            self._add_error(
                f"Duplicate service name: {name}",
                line_num, line,
                f"Service already defined at line {self.services[name].line_number}"
            )
            return
        
        # Validate required parameters
        missing_required = False
        if 'IMAGE' not in params:
            self._add_error("SERVICE requires IMAGE parameter", line_num, line,
                           "Add IMAGE=<docker_image>")
            missing_required = True
        if 'NETWORK' not in params:
            self._add_error("SERVICE requires NETWORK parameter", line_num, line,
                           "Add NETWORK=<network_name>")
            missing_required = True
        if missing_required:
            return
        # Parse COUNT
        count = 1
        if 'COUNT' in params:
            try:
                count = int(params['COUNT'])
                if count < 1:
                    self._add_error("COUNT must be >= 1", line_num, line)
                    count = 1
            except ValueError:
                self._add_error(
                    f"COUNT must be a number, got: {params['COUNT']}",
                    line_num, line
                )
        
        # Parse IP configuration
        ip = None
        ip_range = None
        
        if 'IP' in params:
            if count > 1:
                self._add_warning(
                    "Single IP specified with COUNT>1",
                    line_num, line,
                    "Use IP_RANGE for multiple instances"
                )
            try:
                ip = ipaddress.IPv4Address(params['IP'])
            except ValueError:
                self._add_error(f"Invalid IP address: {params['IP']}", line_num, line)
        
        if 'IP_RANGE' in params:
            if count == 1:
                self._add_warning(
                    "IP_RANGE specified with COUNT=1",
                    line_num, line,
                    "Use IP for single instance"
                )
            
            # Parse IP range
            range_match = re.match(r'(\d+\.\d+\.\d+\.\d+)-(\d+\.\d+\.\d+\.\d+)', params['IP_RANGE'])
            if range_match:
                try:
                    start_ip = ipaddress.IPv4Address(range_match.group(1))
                    end_ip = ipaddress.IPv4Address(range_match.group(2))
                    
                    if start_ip > end_ip:
                        self._add_error(
                            f"Invalid IP_RANGE: start ({start_ip}) > end ({end_ip})",
                            line_num, line,
                            "Start IP must be <= end IP"
                        )
                    else:
                        ip_range = (start_ip, end_ip)
                        
                        # Check if range has enough IPs
                        ip_count = int(end_ip) - int(start_ip) + 1
                        if ip_count < count:
                            self._add_error(
                                f"IP_RANGE has {ip_count} IPs but COUNT={count}",
                                line_num, line,
                                f"Expand range to include at least {count} IPs"
                            )
                except ValueError as e:
                    self._add_error(f"Invalid IP in range: {e}", line_num, line)
            else:
                self._add_error(
                    f"Invalid IP_RANGE format: {params['IP_RANGE']}",
                    line_num, line,
                    "Use format: IP_RANGE=10.1.0.10-10.1.0.20"
                )
        
        # Validate VOLUME_PATTERN
        if 'VOLUME_PATTERN' in params and count == 1:
            self._add_warning(
                "VOLUME_PATTERN used with COUNT=1",
                line_num, line,
                "VOLUME_PATTERN only needed when COUNT>1"
            )
        
        # Store service info
        service = ServiceInfo(
            name=name,
            count=count,
            network=params.get('NETWORK', ''),
            image=params.get('IMAGE', ''),
            ip=ip,
            ip_range=ip_range,
            line_number=line_num + 1
        )
        
        # Expand service instances for COUNT > 1
        if count > 1:
            service.expanded_names = [f"{name}_{i}" for i in range(1, count + 1)]
            self.service_instances[name] = service.expanded_names
        else:
            service.expanded_names = [name]
        
        self.services[name] = service
    
    def _validate_volume(self, tokens: List[str], line_num: int, line: str):
        """Validate VOLUME statement"""
        if len(tokens) < 2:
            self._add_error("VOLUME requires a name", line_num, line)
            return
        
        name = tokens[1]
        
        if name in self.volumes:
            self._add_error(f"Duplicate volume name: {name}", line_num, line)
            return
        
        params = self._extract_params(tokens[2:])
        
        if 'TYPE' not in params:
            self._add_error("VOLUME requires TYPE parameter", line_num, line,
                           f"Add TYPE={'/'.join(self.VOLUME_TYPES)}")
            return
        
        if params['TYPE'] not in self.VOLUME_TYPES:
            self._add_error(
                f"Invalid volume TYPE: {params['TYPE']}",
                line_num, line,
                f"Valid types: {', '.join(self.VOLUME_TYPES)}"
            )
        
        self.volumes[name] = VolumeInfo(name, params['TYPE'], line_num + 1)
    
    def _validate_component(self, tokens: List[str], line_num: int, line: str):
        """Validate COMPONENT statement"""
        if len(tokens) < 2:
            self._add_error("COMPONENT requires a name", line_num, line)
            return
        
        name = tokens[1]
        params = self._extract_params(tokens[2:])
        
        if 'TYPE' not in params:
            self._add_error("COMPONENT requires TYPE parameter", line_num, line)
            return
        
        if 'NETWORK' not in params:
            self._add_error("COMPONENT requires NETWORK parameter", line_num, line)
            return
        
        if params['TYPE'] not in self.COMPONENT_TYPES:
            self._add_error(
                f"Invalid component TYPE: {params['TYPE']}",
                line_num, line,
                f"Valid types: {', '.join(self.COMPONENT_TYPES)}"
            )
        
        # Track critical components
        is_critical = params.get('CRITICAL', 'false').lower() == 'true'
        if is_critical:
            self.critical_components.append(name)
        
        self.components[name] = ComponentInfo(
            name=name,
            type=params['TYPE'],
            network=params.get('NETWORK', ''),
            count=int(params.get('COUNT', '1')),
            critical=is_critical,
            line_number=line_num + 1
        )
    
    def _validate_zone(self, tokens: List[str], line_num: int, line: str):
        """Validate ZONE statement"""
        if len(tokens) < 2:
            self._add_error("ZONE requires a name", line_num, line)
            return
        
        name = tokens[1]
        params = self._extract_params(tokens[2:])
        
        if 'TYPE' not in params:
            self._add_error("ZONE requires TYPE parameter", line_num, line)
            return
        
        if 'NETWORKS' not in params:
            self._add_error("ZONE requires NETWORKS parameter", line_num, line)
            return
        
        if params['TYPE'] not in self.ZONE_TYPES:
            self._add_error(
                f"Invalid zone TYPE: {params['TYPE']}",
                line_num, line,
                f"Valid types: {', '.join(self.ZONE_TYPES)}"
            )
        
        # Track OT/IT zones
        networks = [n.strip() for n in params['NETWORKS'].split(',')]
        if params['TYPE'] == 'ot':
            self.ot_networks.update(networks)
        elif params['TYPE'] == 'it':
            self.it_networks.update(networks)
        
        self.zones[name] = {
            'type': params['TYPE'],
            'networks': networks,
            'line': line_num + 1
        }
    
    def _validate_group(self, tokens: List[str], line_num: int, line: str):
        """Validate GROUP statement"""
        if len(tokens) < 2:
            self._add_error("GROUP requires a name", line_num, line)
            return
        
        name = tokens[1]
        params = self._extract_params(tokens[2:])
        
        if 'MEMBERS' not in params:
            self._add_error("GROUP requires MEMBERS parameter", line_num, line)
            return
        
        if 'ROLE' not in params:
            self._add_error("GROUP requires ROLE parameter", line_num, line)
            return
        
        members = [m.strip() for m in params['MEMBERS'].split(',')]
        
        self.groups[name] = {
            'members': members,
            'role': params['ROLE'],
            'line': line_num + 1
        }
    
    def _validate_router(self, tokens: List[str], line_num: int, line: str, all_lines: List[str]) -> int:
        """Validate ROUTER statement with INTERFACE sub-statements"""
        if len(tokens) < 2:
            self._add_error("ROUTER requires a name", line_num, line)
            return 0
        
        name = tokens[1]
        params = self._extract_params(tokens[2:])
        
        if 'NETWORKS' not in params:
            self._add_error("ROUTER requires NETWORKS parameter", line_num, line)
        
        if 'IMAGE' not in params:
            self._add_error("ROUTER requires IMAGE parameter", line_num, line)
        
        # Parse INTERFACE lines
        interfaces = []
        skip_lines = 0
        i = line_num + 1
        
        while i < len(all_lines):
            intf_line = all_lines[i]
            if intf_line.startswith('  '):
                clean = intf_line.strip()
                if clean.startswith('INTERFACE'):
                    intf_tokens = clean.split()
                    if len(intf_tokens) < 2:
                        self._add_error("INTERFACE requires a name", i, intf_line)
                    else:
                        intf_params = self._extract_params(intf_tokens[2:])
                        if 'NETWORK' not in intf_params:
                            self._add_error("INTERFACE requires NETWORK parameter", i, intf_line)
                        if 'IP' not in intf_params:
                            self._add_error("INTERFACE requires IP parameter", i, intf_line)
                        
                        interfaces.append({
                            'name': intf_tokens[1],
                            'network': intf_params.get('NETWORK'),
                            'ip': intf_params.get('IP')
                        })
                    skip_lines += 1
                else:
                    break
            else:
                break
            i += 1
        
        # Validate that each network in NETWORKS has an interface
        if 'NETWORKS' in params:
            networks = [n.strip() for n in params['NETWORKS'].split(',')]
            interface_networks = [intf['network'] for intf in interfaces]
            
            for net in networks:
                if net not in interface_networks:
                    self._add_warning(
                        f"Network '{net}' in NETWORKS has no INTERFACE",
                        line_num, line,
                        f"Add INTERFACE for network '{net}'"
                    )
        
        self.routers[name] = {
            'networks': params.get('NETWORKS', '').split(','),
            'interfaces': interfaces,
            'line': line_num + 1
        }
        
        return skip_lines
    
    def _validate_allow(self, tokens: List[str], line_num: int, line: str):
        """Validate ALLOW statement"""
        if '->' not in tokens:
            self._add_error(
                "ALLOW requires arrow (->)",
                line_num, line,
                "Format: ALLOW <source> -> <destination> [params]"
            )
            return
        
        arrow_idx = tokens.index('->')
        
        if arrow_idx < 2:
            self._add_error("ALLOW requires source before ->", line_num, line)
            return
        
        if arrow_idx >= len(tokens) - 1:
            self._add_error("ALLOW requires destination after ->", line_num, line)
            return
        
        # Check PROTOCOL if specified
        params = self._extract_params(tokens[arrow_idx + 2:])
        if 'PROTOCOL' in params and params['PROTOCOL'] not in self.PROTOCOLS:
            self._add_error(
                f"Invalid PROTOCOL: {params['PROTOCOL']}",
                line_num, line,
                f"Valid protocols: {', '.join(self.PROTOCOLS)}"
            )
    
    def _validate_block(self, tokens: List[str], line_num: int, line: str):
        """Validate BLOCK statement"""
        if '->' not in tokens:
            self._add_error(
                "BLOCK requires arrow (->)",
                line_num, line,
                "Format: BLOCK <source> -> <destination> [params]"
            )
            return
        
        # Same validation as ALLOW
        self._validate_allow(tokens, line_num, line)
    
    def _validate_vuln(self, tokens: List[str], line_num: int, line: str):
        """Validate VULN statement"""
        if len(tokens) < 2:
            self._add_error("VULN requires a target", line_num, line)
            return
        
        params = self._extract_params(tokens[2:])
        
        if 'TYPE' not in params:
            self._add_error("VULN requires TYPE parameter", line_num, line)
            return
        
        if params['TYPE'] not in self.VULN_TYPES:
            self._add_error(
                f"Invalid vulnerability TYPE: {params['TYPE']}",
                line_num, line,
                f"Valid types: {', '.join(self.VULN_TYPES)}"
            )
        
        if 'SEVERITY' in params and params['SEVERITY'] not in self.SEVERITIES:
            self._add_error(
                f"Invalid SEVERITY: {params['SEVERITY']}",
                line_num, line,
                f"Valid severities: {', '.join(self.SEVERITIES)}"
            )
    
    def _validate_creds(self, tokens: List[str], line_num: int, line: str):
        """Validate CREDS statement"""
        if len(tokens) < 2:
            self._add_error("CREDS requires a source", line_num, line)
            return
        
        params = self._extract_params(tokens[2:])
        
        if 'TARGET' not in params:
            self._add_error("CREDS requires TARGET parameter", line_num, line)
            return
        
        if 'TYPE' not in params:
            self._add_error("CREDS requires TYPE parameter", line_num, line)
            return
        
        if params['TYPE'] not in self.AUTH_TYPES:
            self._add_error(
                f"Invalid auth TYPE: {params['TYPE']}",
                line_num, line,
                f"Valid types: {', '.join(self.AUTH_TYPES)}"
            )
    
    def _validate_chain(self, tokens: List[str], line_num: int, line: str):
        """Validate CHAIN statement"""
        if len(tokens) < 2:
            self._add_error("CHAIN requires a name", line_num, line)
            return
        
        params = self._extract_params(tokens[2:])
        
        if 'PATH' not in params:
            self._add_error("CHAIN requires PATH parameter", line_num, line)
            return
        
        if 'TYPE' not in params:
            self._add_error("CHAIN requires TYPE parameter", line_num, line)
    
    def _validate_rule(self, tokens: List[str], line_num: int, line: str):
        """Validate RULE statement"""
        if len(tokens) < 2:
            self._add_error("RULE requires a name", line_num, line)
            return
        
        params = self._extract_params(tokens[2:])
        
        if 'TYPE' not in params:
            self._add_error("RULE requires TYPE parameter", line_num, line)
            return
        
        if 'BETWEEN' not in params:
            self._add_error("RULE requires BETWEEN parameter", line_num, line)
    
    def _validate_topology(self, tokens: List[str], line_num: int, line: str):
        """Validate TOPOLOGY statement"""
        params = self._extract_params(tokens[1:])
        
        if 'TYPE' not in params:
            self._add_error("TOPOLOGY requires TYPE parameter", line_num, line)
    
    def _validate_include(self, tokens: List[str], line_num: int, line: str):
        """Validate INCLUDE statement"""
        if len(tokens) < 2:
            self._add_error("INCLUDE requires a file path", line_num, line)
    
    def _validate_interface_context(self, line: str, line_num: int) -> bool:
        """Check if indented line is valid (should be INTERFACE under ROUTER)"""
        clean = line.strip()
        return clean.startswith('INTERFACE')
    
    # ========================================================================
    # Second Pass: Semantic Validation
    # ========================================================================
    
    def _validate_semantics(self):
        """Perform semantic validation across all statements"""
        
        # Validate service network references
        for name, service in self.services.items():
            if service.network not in self.networks:
                self._add_error(
                    f"Service '{name}' references undefined network '{service.network}'",
                    service.line_number - 1, f"SERVICE {name} ... NETWORK={service.network}",
                    f"Define network '{service.network}' before this service"
                )
                continue
            
            network = self.networks[service.network]
            
            # Validate IP assignments
            if service.ip:
                if service.ip not in network.subnet:
                    self._add_error(
                        f"Service '{name}' IP {service.ip} not in network {network.subnet}",
                        service.line_number - 1, f"SERVICE {name} ... IP={service.ip}",
                        f"IP must be within {network.subnet}"
                    )
                elif service.ip in network.allocated_ips:
                    self._add_error(
                        f"IP conflict: {service.ip} already allocated",
                        service.line_number - 1, f"SERVICE {name} ... IP={service.ip}",
                        "Choose a different IP address"
                    )
                else:
                    network.allocated_ips.add(service.ip)
            
            # Validate IP range
            if service.ip_range:
                start_ip, end_ip = service.ip_range
                
                if start_ip not in network.subnet or end_ip not in network.subnet:
                    self._add_error(
                        f"Service '{name}' IP range not within network {network.subnet}",
                        service.line_number - 1, f"SERVICE {name} ... IP_RANGE=...",
                        f"Range must be within {network.subnet}"
                    )
                else:
                    # Check for conflicts
                    current_ip = start_ip
                    while current_ip <= end_ip:
                        if current_ip in network.allocated_ips:
                            self._add_error(
                                f"IP conflict in range: {current_ip} already allocated",
                                service.line_number - 1, f"SERVICE {name} ... IP_RANGE=...",
                                "Adjust IP range to avoid conflicts"
                            )
                            break
                        network.allocated_ips.add(current_ip)
                        current_ip = ipaddress.IPv4Address(int(current_ip) + 1)
        
        # Validate component network references
        for name, component in self.components.items():
            if component.network not in self.networks:
                self._add_error(
                    f"Component '{name}' references undefined network '{component.network}'",
                    component.line_number - 1, f"COMPONENT {name} ... NETWORK={component.network}",
                    f"Define network '{component.network}' before this component"
                )
        
        # Validate zone network references
        for name, zone in self.zones.items():
            for network in zone['networks']:
                if network not in self.networks:
                    self._add_error(
                        f"Zone '{name}' references undefined network '{network}'",
                        zone['line'] - 1, f"ZONE {name} ... NETWORKS=...",
                        f"Define network '{network}' before this zone"
                    )
        
        # Validate group member references
        for name, group in self.groups.items():
            for member in group['members']:
                # Check if member is a service (base name or instance)
                if member not in self.services and member not in self.components:
                    # Check if it's an expanded service instance
                    found = False
                    for svc_name, instances in self.service_instances.items():
                        if member == svc_name or member in instances:
                            found = True
                            break
                    
                    if not found:
                        self._add_error(
                            f"Group '{name}' references undefined member '{member}'",
                            group['line'] - 1, f"GROUP {name} ... MEMBERS=...",
                            f"Define service or component '{member}' before this group"
                        )
        
        # Check for overlapping subnets
        networks_list = list(self.networks.values())
        for i in range(len(networks_list)):
            for j in range(i + 1, len(networks_list)):
                net1 = networks_list[i]
                net2 = networks_list[j]
                
                # Only check overlap for same network type
                if net1.type == net2.type and net1.subnet.overlaps(net2.subnet):
                    self._add_warning(
                        f"Networks '{net1.name}' and '{net2.name}' have overlapping subnets",
                        net1.line_number - 1, f"NETWORK {net1.name} ... SUBNET={net1.subnet}",
                        "Use non-overlapping subnets or different network types"
                    )
    
    # ========================================================================
    # Security Validation
    # ========================================================================
    
    def _check_security(self):
        """Check security best practices"""
        
        # Warn about critical components without firewall rules
        for comp_name in self.critical_components:
            if comp_name in self.components:
                comp = self.components[comp_name]
                # Check if network has any firewall rules
                has_firewall = False
                for router in self.routers.values():
                    if comp.network in router.get('networks', []):
                        has_firewall = True
                        break
                
                if not has_firewall:
                    self._add_warning(
                        f"Critical component '{comp_name}' network has no router/firewall",
                        comp.line_number - 1, f"COMPONENT {comp_name} ... CRITICAL=true",
                        f"Add router or firewall rules for network '{comp.network}'"
                    )
        
        # Warn about direct OT-IT connections
        if self.ot_networks and self.it_networks:
            # Check if any router directly connects OT and IT
            for router_name, router in self.routers.items():
                router_networks = set(router.get('networks', []))
                has_ot = bool(router_networks & self.ot_networks)
                has_it = bool(router_networks & self.it_networks)
                
                if has_ot and has_it:
                    self._add_warning(
                        f"Router '{router_name}' directly connects OT and IT networks",
                        router['line'] - 1, f"ROUTER {router_name} ...",
                        "Consider adding a DMZ between OT and IT zones"
                    )
    
    # ========================================================================
    # Helper Methods
    # ========================================================================
    
    def _extract_params(self, tokens: List[str]) -> Dict[str, str]:
        """Extract KEY=value parameters from tokens"""
        params = {}
        for token in tokens:
            if '=' in token:
                key, value = token.split('=', 1)
                params[key] = value
        return params
    
    def _add_error(self, message: str, line_num: int, line: str, suggestion: str = None):
        """Add an error to the list"""
        self.errors.append(ValidationError(
            Severity.ERROR,
            message,
            line_num + 1,
            line.strip(),
            suggestion
        ))
    
    def _add_warning(self, message: str, line_num: int, line: str, suggestion: str = None):
        """Add a warning to the list"""
        self.warnings.append(ValidationError(
            Severity.WARNING,
            message,
            line_num + 1,
            line.strip(),
            suggestion
        ))


# ============================================================================
# Main Validation Function
# ============================================================================

def validate_ndl(text: str) -> Tuple[bool, List[ValidationError], List[ValidationError]]:
    """
    Validate NDL text.
    Returns (is_valid, errors, warnings)
    """
    validator = NDLValidator()
    errors, warnings = validator.validate(text)
    is_valid = len(errors) == 0
    
    return is_valid, errors, warnings


def validate_file(filepath: str) -> Tuple[bool, List[ValidationError], List[ValidationError]]:
    """
    Validate NDL file.
    Returns (is_valid, errors, warnings)
    """
    try:
        with open(filepath, 'r') as f:
            content = f.read()
        return validate_ndl(content)
    except IOError as e:
        error = ValidationError(
            Severity.ERROR,
            f"Cannot read file: {e}",
            0,
            "",
            "Check file path and permissions"
        )
        return False, [error], []


def print_validation_report(errors: List[ValidationError], warnings: List[ValidationError]):
    """Pretty print validation results"""
    
    if errors:
        print("\n" + "=" * 60)
        print(f"ERRORS ({len(errors)})")
        print("=" * 60)
        for error in errors:
            print(error)
            print()
    
    if warnings:
        print("\n" + "=" * 60)
        print(f"WARNINGS ({len(warnings)})")
        print("=" * 60)
        for warning in warnings:
            print(warning)
            print()
    
    if not errors and not warnings:
        print("\n✓ Validation successful - no errors or warnings found")
    elif not errors:
        print(f"\n✓ Validation successful with {len(warnings)} warning(s)")
    else:
        print(f"\n✗ Validation failed with {len(errors)} error(s)")


# ============================================================================
# CLI Interface
# ============================================================================

if __name__ == "__main__":
    import sys
    import argparse
    
    # Built-in test NDL
    test_ndl = """
# Test various validation scenarios
TOPOLOGY TYPE=hierarchical LAYERS=3

# Valid network definitions
NETWORK dmz_net TYPE=bridge SUBNET=10.1.0.0/24 GATEWAY=10.1.0.1
NETWORK internal_net TYPE=bridge SUBNET=10.2.0.0/24
NETWORK data_net TYPE=bridge SUBNET=10.3.0.0/24

# Volume definition
VOLUME db_data TYPE=local SIZE=100G

# Service with various issues to test
SERVICE web_server COUNT=2 IMAGE=nginx:alpine NETWORK=dmz_net IP_RANGE=10.1.0.10-10.1.0.11
SERVICE app_server COUNT=1 IMAGE=node:16 NETWORK=internal_net IP=10.2.0.10
SERVICE database COUNT=1 IMAGE=postgres:13 NETWORK=data_net IP=10.3.0.10 VOLUME=db_data

# Component with critical flag
COMPONENT scada_hmi TYPE=hmi NETWORK=internal_net CRITICAL=true

# Zones
ZONE ot_zone TYPE=ot NETWORKS=internal_net TRUST_LEVEL=9
ZONE it_zone TYPE=it NETWORKS=dmz_net TRUST_LEVEL=5

# Group
GROUP web_tier MEMBERS=web_server ROLE=webserver

# Router
ROUTER core_router NETWORKS=dmz_net,internal_net IMAGE=frr:latest
  INTERFACE eth0 NETWORK=dmz_net IP=10.1.0.254
  INTERFACE eth1 NETWORK=internal_net IP=10.2.0.254

# Vulnerability
VULN web_server TYPE=rce CVE=CVE-2021-44228 SEVERITY=critical

# Credentials  
CREDS web_server TARGET=database TYPE=database USERNAME=dbuser

# Access rules
ALLOW dmz_net -> internal_net PORTS=443 PROTOCOL=tcp
BLOCK internet -> data_net

# This should trigger order warning - NETWORK after SERVICE
NETWORK late_net TYPE=bridge SUBNET=10.4.0.0/24

# This should trigger errors - undefined references
SERVICE broken_service COUNT=1 IMAGE=broken NETWORK=undefined_net
ZONE broken_zone TYPE=it NETWORKS=undefined_net1,undefined_net2
"""
    
    # Set up argument parser
    parser = argparse.ArgumentParser(
        description='NDL Validation Parser - Validate Network Definition Language files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                           # Run with built-in test
  %(prog)s network.ndl               # Validate a file
  %(prog)s network.ndl --quiet       # Only show errors
  %(prog)s network.ndl --no-warnings # Don't show warnings
  %(prog)s network.ndl --json        # Output as JSON
        """
    )
    
    parser.add_argument(
        'file',
        nargs='?',
        help='NDL file to validate (optional, uses test data if not provided)'
    )
    
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode - only show errors, no headers or summary'
    )
    
    parser.add_argument(
        '-w', '--no-warnings',
        action='store_true',
        help="Don't show warnings, only errors"
    )
    
    parser.add_argument(
        '-j', '--json',
        action='store_true',
        help='Output validation results as JSON'
    )
    
    parser.add_argument(
        '--no-color',
        action='store_true',
        help='Disable colored output'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output - show all validation steps'
    )
    
    args = parser.parse_args()
    
    # Disable colors if requested
    if args.no_color:
        # Monkey-patch the ValidationError __str__ to remove colors
        original_str = ValidationError.__str__
        def no_color_str(self):
            result = f"{self.severity.value}: {self.message}\n"
            result += f"  Line {self.line_number}: {self.line_text}\n"
            if self.suggestion:
                result += f"  Fix: {self.suggestion}"
            return result
        ValidationError.__str__ = no_color_str
    
    # Determine what to validate
    if args.file:
        # Validate the specified file
        filename = args.file
        if not args.quiet:
            print("=" * 60)
            print(f"NDL Validation Parser - Validating: {filename}")
            print("=" * 60)
        
        is_valid, errors, warnings = validate_file(filename)
        
    else:
        # Use built-in test
        if not args.quiet:
            print("=" * 60)
            print("NDL Validation Parser - Running Built-in Test")
            print("=" * 60)
        
        is_valid, errors, warnings = validate_ndl(test_ndl)
    
    # Filter warnings if requested
    if args.no_warnings:
        warnings = []
    
    # Output results
    if args.json:
        # JSON output
        import json
        output = {
            'valid': is_valid,
            'error_count': len(errors),
            'warning_count': len(warnings),
            'errors': [
                {
                    'severity': str(e.severity.value),
                    'message': e.message,
                    'line': e.line_number,
                    'text': e.line_text,
                    'suggestion': e.suggestion
                }
                for e in errors
            ],
            'warnings': [
                {
                    'severity': str(w.severity.value),
                    'message': w.message,
                    'line': w.line_number,
                    'text': w.line_text,
                    'suggestion': w.suggestion
                }
                for w in warnings
            ] if not args.no_warnings else []
        }
        print(json.dumps(output, indent=2))
        
    else:
        # Normal output
        if not args.quiet:
            print_validation_report(errors, warnings)
            
            # Summary
            print("\n" + "=" * 60)
            print("Summary:")
            print(f"  Valid: {is_valid}")
            print(f"  Errors: {len(errors)}")
            if not args.no_warnings:
                print(f"  Warnings: {len(warnings)}")
            print("=" * 60)
        else:
            # Quiet mode - just print errors
            for error in errors:
                print(error)
            if not args.no_warnings:
                for warning in warnings:
                    print(warning)
    
    # Exit code for CI/CD
    sys.exit(0 if is_valid else 1)