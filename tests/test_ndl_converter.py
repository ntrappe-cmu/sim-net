"""
Unit tests for ndl_converter.py

Simple hello world tests to validate the NDL to IR converter functionality.
"""

import pytest
from ndl_engine.ndl_converter import NDLConverter, Network, Severity


def test_convert_simple_network():
    """Test conversion of a simple NETWORK statement"""
    ndl_lines = [
        "NETWORK test_net TYPE=bridge SUBNET=10.1.0.0/24 GATEWAY=10.1.0.1"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    # Should convert successfully with no errors
    assert len(errors) == 0
    assert len(ir.networks) == 1
    
    network = ir.networks[0]
    assert network.name == "test_net"
    assert network.type == "bridge"
    assert network.subnet == "10.1.0.0/24"
    assert network.gateway == "10.1.0.1"


def test_convert_service_with_count():
    """Test conversion of a SERVICE with COUNT parameter"""
    ndl_lines = [
        "NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24",
        "SERVICE web COUNT=2 IMAGE=nginx:latest NETWORK=dmz IP_RANGE=10.1.0.10-10.1.0.11"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    # Should convert successfully
    assert len(errors) == 0
    assert len(ir.networks) == 1
    assert len(ir.services) == 2  # COUNT=2 should create 2 service instances
    
    # Check instance names are expanded
    service_names = [s.name for s in ir.services]
    assert "web_1" in service_names
    assert "web_2" in service_names


def test_convert_network_auto_gateway():
    """Test network with auto-assigned gateway"""
    ndl_lines = [
        "NETWORK test TYPE=bridge SUBNET=10.1.0.0/24"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert len(ir.networks) == 1
    assert ir.networks[0].gateway == "10.1.0.1"  # Auto-assigned


def test_convert_network_with_vlan():
    """Test network with VLAN parameter"""
    ndl_lines = [
        "NETWORK test TYPE=bridge SUBNET=10.1.0.0/24 VLAN=100"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert ir.networks[0].vlan == 100


def test_convert_network_invalid_vlan():
    """Test network with invalid VLAN"""
    ndl_lines = [
        "NETWORK test TYPE=bridge SUBNET=10.1.0.0/24 VLAN=5000"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) > 0
    assert any('VLAN' in str(error.message) for error in errors)


def test_convert_volume():
    """Test conversion of VOLUME statement"""
    ndl_lines = [
        "VOLUME data TYPE=local SIZE=100G"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert len(ir.volumes) == 1
    assert ir.volumes[0].name == "data"
    assert ir.volumes[0].type == "local"
    assert ir.volumes[0].size == "100G"


def test_convert_service_single():
    """Test conversion of single service"""
    ndl_lines = [
        "NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24",
        "SERVICE web IMAGE=nginx:latest NETWORK=dmz IP=10.1.0.10"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert len(ir.services) == 1
    assert ir.services[0].name == "web"
    assert ir.services[0].ip == "10.1.0.10"


def test_convert_service_with_ports():
    """Test service with ports"""
    ndl_lines = [
        "NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24",
        "SERVICE web IMAGE=nginx:latest NETWORK=dmz PORTS=80,443"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert ir.services[0].ports == ["80", "443"]


def test_convert_service_with_env():
    """Test service with environment variables"""
    ndl_lines = [
        "NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24",
        "SERVICE web IMAGE=nginx:latest NETWORK=dmz ENV=KEY1=val1,KEY2=val2"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert ir.services[0].env == {"KEY1": "val1", "KEY2": "val2"}


def test_convert_service_invalid_count():
    """Test service with invalid COUNT"""
    ndl_lines = [
        "NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24",
        "SERVICE web COUNT=0 IMAGE=nginx:latest NETWORK=dmz"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) > 0


def test_convert_service_ip_range_insufficient():
    """Test service with IP range smaller than count"""
    ndl_lines = [
        "NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24",
        "SERVICE web COUNT=5 IMAGE=nginx:latest NETWORK=dmz IP_RANGE=10.1.0.10-10.1.0.11"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) > 0
    assert any('IP_RANGE' in str(error.message) for error in errors)


def test_convert_component():
    """Test conversion of COMPONENT statement"""
    ndl_lines = [
        "NETWORK ot TYPE=bridge SUBNET=10.2.0.0/24",
        "COMPONENT plc1 TYPE=plc NETWORK=ot IP=10.2.0.10"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert len(ir.components) == 1
    assert ir.components[0].name == "plc1"
    assert ir.components[0].type == "plc"
    assert ir.components[0].ip == "10.2.0.10"


def test_convert_component_with_count():
    """Test component with COUNT parameter"""
    ndl_lines = [
        "NETWORK ot TYPE=bridge SUBNET=10.2.0.0/24",
        "COMPONENT sensor COUNT=3 TYPE=sensor NETWORK=ot IP_RANGE=10.2.0.10-10.2.0.12"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert len(ir.components) == 3
    component_names = [c.name for c in ir.components]
    assert "sensor_1" in component_names
    assert "sensor_2" in component_names
    assert "sensor_3" in component_names


def test_convert_component_auto_image():
    """Test component gets auto-assigned image"""
    ndl_lines = [
        "NETWORK ot TYPE=bridge SUBNET=10.2.0.0/24",
        "COMPONENT hmi1 TYPE=hmi NETWORK=ot"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert ir.components[0].image is not None


def test_convert_zone():
    """Test conversion of ZONE statement"""
    ndl_lines = [
        "NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24",
        "ZONE dmz_zone TYPE=dmz NETWORKS=dmz TRUST_LEVEL=3"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert len(ir.zones) == 1
    assert ir.zones[0].name == "dmz_zone"
    assert ir.zones[0].type == "dmz"
    assert ir.zones[0].trust_level == 3


def test_convert_zone_invalid_trust():
    """Test zone with invalid trust level"""
    ndl_lines = [
        "NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24",
        "ZONE dmz_zone TYPE=dmz NETWORKS=dmz TRUST_LEVEL=15"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) > 0


def test_convert_group():
    """Test conversion of GROUP statement"""
    ndl_lines = [
        "NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24",
        "SERVICE web IMAGE=nginx:latest NETWORK=dmz",
        "GROUP web_tier MEMBERS=web ROLE=frontend"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert len(ir.groups) == 1
    assert ir.groups[0].name == "web_tier"
    assert "web" in ir.groups[0].members


def test_convert_group_expansion():
    """Test group member expansion for COUNT>1"""
    ndl_lines = [
        "NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24",
        "SERVICE web COUNT=2 IMAGE=nginx:latest NETWORK=dmz IP_RANGE=10.1.0.10-10.1.0.11",
        "GROUP web_tier MEMBERS=web ROLE=frontend"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert "web_1" in ir.groups[0].members
    assert "web_2" in ir.groups[0].members


def test_convert_router():
    """Test conversion of ROUTER statement"""
    ndl_lines = [
        "NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24",
        "NETWORK internal TYPE=bridge SUBNET=10.2.0.0/24",
        "ROUTER core NETWORKS=dmz,internal IMAGE=frr:latest",
        "  INTERFACE eth0 NETWORK=dmz IP=10.1.0.254",
        "  INTERFACE eth1 NETWORK=internal IP=10.2.0.254"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert len(ir.routers) == 1
    assert ir.routers[0].name == "core"
    assert len(ir.routers[0].interfaces) == 2


def test_convert_vulnerability():
    """Test conversion of VULN statement"""
    ndl_lines = [
        "NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24",
        "SERVICE web IMAGE=nginx:latest NETWORK=dmz",
        "VULN web TYPE=rce CVE=CVE-2021-1234 SEVERITY=critical"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert len(ir.vulnerabilities) == 1
    assert ir.vulnerabilities[0].target == "web"
    assert ir.vulnerabilities[0].type == "rce"


def test_convert_credential():
    """Test conversion of CREDS statement"""
    ndl_lines = [
        "NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24",
        "SERVICE web IMAGE=nginx:latest NETWORK=dmz",
        "SERVICE db IMAGE=postgres:latest NETWORK=dmz",
        "CREDS web TARGET=db TYPE=database USERNAME=dbuser"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert len(ir.credentials) == 1
    assert ir.credentials[0].source == "web"
    assert ir.credentials[0].target == "db"


def test_convert_chain():
    """Test conversion of CHAIN statement"""
    ndl_lines = [
        "CHAIN attack1 PATH=web->app->db TYPE=lateral GOAL=data_theft"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert len(ir.attack_chains) == 1
    assert ir.attack_chains[0].name == "attack1"
    assert ir.attack_chains[0].path == ["web", "app", "db"]


def test_convert_allow_rule():
    """Test conversion of ALLOW statement"""
    ndl_lines = [
        "ALLOW dmz -> internal PROTOCOL=tcp PORTS=443"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert len(ir.rules) == 1
    assert ir.rules[0].rule_type == "allow"
    assert ir.rules[0].source == "dmz"
    assert ir.rules[0].destination == "internal"


def test_convert_block_rule():
    """Test conversion of BLOCK statement"""
    ndl_lines = [
        "BLOCK internal -> dmz"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert len(ir.rules) == 1
    assert ir.rules[0].rule_type == "block"


def test_convert_rule():
    """Test conversion of RULE statement"""
    ndl_lines = [
        "RULE fw1 TYPE=firewall BETWEEN=zone1,zone2 LOG=true"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert len(ir.rules) == 1
    assert ir.rules[0].name == "fw1"
    assert ir.rules[0].log is True


def test_convert_topology():
    """Test conversion of TOPOLOGY statement"""
    ndl_lines = [
        "TOPOLOGY TYPE=hierarchical LAYERS=3 WIDTH=5"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) == 0
    assert ir.topology is not None
    assert ir.topology.type == "hierarchical"
    assert ir.topology.layers == 3
    assert ir.topology.width == 5


def test_convert_topology_invalid_layers():
    """Test topology with invalid layers"""
    ndl_lines = [
        "TOPOLOGY TYPE=hierarchical LAYERS=0"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) > 0


def test_convert_ip_outside_subnet():
    """Test service with IP outside subnet"""
    ndl_lines = [
        "NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24",
        "SERVICE web IMAGE=nginx:latest NETWORK=dmz IP=10.2.0.10"
    ]
    
    converter = NDLConverter()
    ir, errors, warnings = converter.convert_lines(ndl_lines)
    
    assert len(errors) > 0
    assert any('subnet' in str(error.message).lower() for error in errors)


def test_conversion_error_str():
    """Test ConversionError string representation"""
    from ndl_engine.ndl_converter import ConversionError
    error = ConversionError(
        Severity.ERROR,
        "Test error",
        "Fix this"
    )
    error_str = str(error)
    assert "ERROR" in error_str
    assert "Test error" in error_str
    assert "Fix this" in error_str


def test_parse_bool_helper():
    """Test _parse_bool helper method"""
    converter = NDLConverter()
    assert converter._parse_bool({"KEY": "true"}, "KEY") is True
    assert converter._parse_bool({"KEY": "false"}, "KEY") is False
    assert converter._parse_bool({}, "KEY", default=True) is True
