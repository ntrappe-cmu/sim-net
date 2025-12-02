#!/usr/bin/env python3
"""
NDL Parser & Validator
Parses NDL files into structured data and validates syntax/semantics.
"""

import re
import os
import ipaddress
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum

# ============================================================================
# Data Structures (The "Specification")
# ============================================================================

@dataclass
class SpecNetwork:
    name: str
    subnet: str
    gateway: Optional[str] = None
    vlan: Optional[int] = None

@dataclass
class SpecService:
    name: str
    image: str
    network: str
    count: int = 1
    ports: List[str] = field(default_factory=list)
    env: Dict[str, str] = field(default_factory=dict)
    volumes: List[str] = field(default_factory=list)
    meta: Dict[str, Any] = field(default_factory=dict) # For file/line tracking

@dataclass
class SpecRule:
    action: str # ALLOW/BLOCK
    src: str
    dst: str
    port: str
    proto: str

@dataclass
class NDLSpecification:
    """Holds the raw parsed data from NDL files"""
    networks: List[SpecNetwork] = field(default_factory=list)
    services: List[SpecService] = field(default_factory=list) # Includes Components
    routers: List[Any] = field(default_factory=list) # Simplified for brevity
    zones: List[Any] = field(default_factory=list)
    rules: List[SpecRule] = field(default_factory=list)
    
# ============================================================================
# Validation Classes
# ============================================================================

class Severity(Enum):
    ERROR = "ERROR"
    WARNING = "WARNING"

@dataclass
class ValidationError:
    severity: Severity
    message: str
    line_number: int
    line_text: str
    file_name: str

# ============================================================================
# Main Parser Class
# ============================================================================

class NDLParser:
    def __init__(self):
        self.errors = []
        self.warnings = []
        self.spec = NDLSpecification()
        self._defined_symbols = set()
        self._visited_files = set() # To prevent circular includes

        # Regex Patterns
        self.patterns = {
            'param': r'(\w+)=("(?:[^"\\]|\\.)*"|[^\s]+)',
            'comment': r'^\s*#.*$',
            'empty': r'^\s*$'
        }

    def parse(self, filepath: str) -> Tuple[NDLSpecification, List[ValidationError], List[ValidationError]]:
        """Main entry point. Parses file and all INCLUDES."""
        self._parse_file_recursive(filepath)
        self._run_semantic_validation() # Post-parse checks (references, etc)
        return self.spec, self.errors, self.warnings

    def _parse_file_recursive(self, filepath: str):
        if filepath in self._visited_files:
            return # Already parsed
        
        if not os.path.exists(filepath):
            self._add_error(f"File not found: {filepath}", 0, "INCLUDE " + filepath, filepath)
            return

        self._visited_files.add(filepath)
        
        try:
            with open(filepath, 'r') as f:
                lines = f.readlines()
        except Exception as e:
            self._add_error(f"Could not read file: {str(e)}", 0, "", filepath)
            return

        for i, line in enumerate(lines):
            line_num = i + 1
            text = line.strip()
            
            if not text or re.match(self.patterns['comment'], text):
                continue
                
            parts = text.split(maxsplit=1)
            keyword = parts[0].upper()
            content = parts[1] if len(parts) > 1 else ""

            # Dispatcher
            if keyword == 'INCLUDE':
                # Handle recursion immediately
                included_path = content.strip('"').strip("'")
                # Handle relative paths based on current file
                base_dir = os.path.dirname(filepath)
                full_path = os.path.join(base_dir, included_path)
                self._parse_file_recursive(full_path)
            elif keyword == 'NETWORK':
                self._parse_network(content, line_num, text, filepath)
            elif keyword in ['SERVICE', 'COMPONENT']:
                self._parse_service(content, line_num, text, filepath)
            elif keyword in ['ALLOW', 'BLOCK']:
                self._parse_rule(keyword, content, line_num, text, filepath)
            # ... Add other handlers (ROUTER, ZONE, etc) here ...

    def _extract_params(self, text: str) -> Dict[str, str]:
        """Helper to extract key=value pairs"""
        matches = re.findall(self.patterns['param'], text)
        params = {}
        for key, value in matches:
            if value.startswith('"') and value.endswith('"'):
                value = value[1:-1]
            params[key.lower()] = value
        return params

    def _parse_network(self, content, line, text, fname):
        params = self._extract_params(content)
        if 'name' not in params or 'subnet' not in params:
            self._add_error("NETWORK missing name or subnet", line, text, fname)
            return
        
        # Validation
        try:
            ipaddress.ip_network(params['subnet'], strict=False)
        except ValueError:
            self._add_error(f"Invalid subnet: {params['subnet']}", line, text, fname)

        self.spec.networks.append(SpecNetwork(
            name=params['name'],
            subnet=params['subnet'],
            gateway=params.get('gateway'),
            vlan=int(params['vlan']) if 'vlan' in params else None
        ))
        self._defined_symbols.add(params['name'])

    def _parse_service(self, content, line, text, fname):
        params = self._extract_params(content)
        # Required fields
        required = ['name', 'image', 'network']
        if not all(k in params for k in required):
            self._add_error(f"SERVICE missing required fields: {required}", line, text, fname)
            return

        # Handle Count
        count = 1
        if 'count' in params:
            try:
                count = int(params['count'])
            except ValueError:
                self._add_error("Count must be integer", line, text, fname)

        # Create Spec Object
        svc = SpecService(
            name=params['name'],
            image=params['image'],
            network=params['network'],
            count=count,
            meta={'file': fname, 'line': line}
        )
        
        # Parse simple comma lists for now (can expand regex later)
        if 'ports' in params:
            svc.ports = params['ports'].split(',')
        
        self.spec.services.append(svc)
        self._defined_symbols.add(params['name'])

    def _parse_rule(self, action, content, line, text, fname):
        # ALLOW src=X dst=Y port=Z proto=TCP
        params = self._extract_params(content)
        self.spec.rules.append(SpecRule(
            action=action,
            src=params.get('src', 'ANY'),
            dst=params.get('dst', 'ANY'),
            port=params.get('port', 'ANY'),
            proto=params.get('proto', 'TCP')
        ))

    def _run_semantic_validation(self):
        """Checks that references exist (e.g. Service references valid Network)"""
        network_names = {n.name for n in self.spec.networks}
        
        for svc in self.spec.services:
            if svc.network not in network_names:
                self._add_error(
                    f"Service '{svc.name}' references undefined network '{svc.network}'", 
                    svc.meta['line'], 
                    f"SERVICE name={svc.name}...", 
                    svc.meta['file']
                )

    def _add_error(self, msg, line, text, fname):
        self.errors.append(ValidationError(Severity.ERROR, msg, line, text, fname))

if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: ndl_parser.py <file>")
        sys.exit(1)
        
    p = NDLParser()
    spec, errs, warns = p.parse(sys.argv[1])
    
    # Simple JSON output for the CLI
    output = {
        "valid": len(errs) == 0,
        "networks": len(spec.networks),
        "services": len(spec.services),
        "errors": [e.message for e in errs]
    }
    print(json.dumps(output, indent=2))
    if errs: sys.exit(1)