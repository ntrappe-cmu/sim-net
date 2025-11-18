"""
Unit tests for ndl_parser.py

Simple hello world tests to validate the NDL validation parser functionality.
"""

import pytest
from ndl_engine.ndl_parser import validate_ndl, NDLValidator, Severity


def test_validate_simple_valid_network():
    """Test validation of a simple valid NETWORK statement"""
    ndl_text = """
NETWORK test_net TYPE=bridge SUBNET=10.1.0.0/24 GATEWAY=10.1.0.1
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    
    # Should be valid with no errors
    assert is_valid is True
    assert len(errors) == 0


def test_validate_missing_required_params():
    """Test validation catches missing required parameters"""
    ndl_text = """
NETWORK test_net TYPE=bridge
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    
    # Should be invalid - missing SUBNET parameter
    assert is_valid is False
    assert len(errors) > 0
    # Check that the error mentions SUBNET
    assert any('SUBNET' in str(error.message) for error in errors)


def test_validate_service_basic():
    """Test validation of a basic SERVICE statement"""
    ndl_text = """
NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24
SERVICE web IMAGE=nginx:latest NETWORK=dmz
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is True
    assert len(errors) == 0


def test_validate_service_missing_image():
    """Test SERVICE validation catches missing IMAGE"""
    ndl_text = """
NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24
SERVICE web NETWORK=dmz
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is False
    assert any('IMAGE' in str(error.message) for error in errors)


def test_validate_service_missing_network():
    """Test SERVICE validation catches missing NETWORK"""
    ndl_text = """
SERVICE web IMAGE=nginx:latest
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is False
    assert any('NETWORK' in str(error.message) for error in errors)


def test_validate_service_with_count():
    """Test SERVICE with COUNT parameter"""
    ndl_text = """
NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24
SERVICE web COUNT=3 IMAGE=nginx:latest NETWORK=dmz IP_RANGE=10.1.0.10-10.1.0.12
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is True


def test_validate_service_invalid_count():
    """Test SERVICE validation catches invalid COUNT"""
    ndl_text = """
NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24
SERVICE web COUNT=0 IMAGE=nginx:latest NETWORK=dmz
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is False
    assert any('COUNT' in str(error.message) for error in errors)


def test_validate_volume_basic():
    """Test validation of a basic VOLUME statement"""
    ndl_text = """
VOLUME data TYPE=local
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is True
    assert len(errors) == 0


def test_validate_volume_missing_type():
    """Test VOLUME validation catches missing TYPE"""
    ndl_text = """
VOLUME data
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is False
    assert any('TYPE' in str(error.message) for error in errors)


def test_validate_volume_invalid_type():
    """Test VOLUME validation catches invalid TYPE"""
    ndl_text = """
VOLUME data TYPE=invalid_type
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is False


def test_validate_component_basic():
    """Test validation of a basic COMPONENT statement"""
    ndl_text = """
NETWORK ot TYPE=bridge SUBNET=10.2.0.0/24
COMPONENT plc1 TYPE=plc NETWORK=ot
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is True


def test_validate_component_missing_type():
    """Test COMPONENT validation catches missing TYPE"""
    ndl_text = """
NETWORK ot TYPE=bridge SUBNET=10.2.0.0/24
COMPONENT plc1 NETWORK=ot
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is False
    assert any('TYPE' in str(error.message) for error in errors)


def test_validate_component_invalid_type():
    """Test COMPONENT validation catches invalid TYPE"""
    ndl_text = """
NETWORK ot TYPE=bridge SUBNET=10.2.0.0/24
COMPONENT comp1 TYPE=invalid_type NETWORK=ot
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is False


def test_validate_zone_basic():
    """Test validation of a basic ZONE statement"""
    ndl_text = """
NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24
ZONE dmz_zone TYPE=dmz NETWORKS=dmz
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is True


def test_validate_zone_missing_type():
    """Test ZONE validation catches missing TYPE"""
    ndl_text = """
NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24
ZONE dmz_zone NETWORKS=dmz
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is False
    assert any('TYPE' in str(error.message) for error in errors)


def test_validate_zone_missing_networks():
    """Test ZONE validation catches missing NETWORKS"""
    ndl_text = """
ZONE dmz_zone TYPE=dmz
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is False
    assert any('NETWORKS' in str(error.message) for error in errors)


def test_validate_group_basic():
    """Test validation of a basic GROUP statement"""
    ndl_text = """
NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24
SERVICE web IMAGE=nginx:latest NETWORK=dmz
GROUP web_tier MEMBERS=web ROLE=frontend
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is True


def test_validate_group_missing_members():
    """Test GROUP validation catches missing MEMBERS"""
    ndl_text = """
GROUP web_tier ROLE=frontend
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is False
    assert any('MEMBERS' in str(error.message) for error in errors)


def test_validate_router_basic():
    """Test validation of a basic ROUTER statement"""
    ndl_text = """
NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24
NETWORK internal TYPE=bridge SUBNET=10.2.0.0/24
ROUTER core NETWORKS=dmz,internal IMAGE=frr:latest
  INTERFACE eth0 NETWORK=dmz IP=10.1.0.254
  INTERFACE eth1 NETWORK=internal IP=10.2.0.254
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is True


def test_validate_router_missing_networks():
    """Test ROUTER validation catches missing NETWORKS"""
    ndl_text = """
ROUTER core IMAGE=frr:latest
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is False
    assert any('NETWORKS' in str(error.message) for error in errors)


def test_validate_allow_block():
    """Test validation of ALLOW and BLOCK statements"""
    ndl_text = """
NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24
NETWORK internal TYPE=bridge SUBNET=10.2.0.0/24
ALLOW dmz -> internal PROTOCOL=tcp PORTS=443
BLOCK internal -> dmz
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is True


def test_validate_allow_missing_arrow():
    """Test ALLOW validation catches missing arrow"""
    ndl_text = """
ALLOW source destination
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is False
    assert any('arrow' in str(error.message).lower() for error in errors)


def test_validate_vuln_basic():
    """Test validation of a basic VULN statement"""
    ndl_text = """
NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24
SERVICE web IMAGE=nginx:latest NETWORK=dmz
VULN web TYPE=rce SEVERITY=high
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is True


def test_validate_vuln_missing_type():
    """Test VULN validation catches missing TYPE"""
    ndl_text = """
VULN web SEVERITY=high
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is False
    assert any('TYPE' in str(error.message) for error in errors)


def test_validate_creds_basic():
    """Test validation of a basic CREDS statement"""
    ndl_text = """
NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24
SERVICE web IMAGE=nginx:latest NETWORK=dmz
SERVICE db IMAGE=postgres:latest NETWORK=dmz
CREDS web TARGET=db TYPE=database
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is True


def test_validate_creds_missing_target():
    """Test CREDS validation catches missing TARGET"""
    ndl_text = """
CREDS web TYPE=database
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is False
    assert any('TARGET' in str(error.message) for error in errors)


def test_validate_chain_basic():
    """Test validation of a basic CHAIN statement"""
    ndl_text = """
CHAIN attack1 PATH=web->app->db TYPE=lateral
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is True


def test_validate_chain_missing_path():
    """Test CHAIN validation catches missing PATH"""
    ndl_text = """
CHAIN attack1 TYPE=lateral
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is False
    assert any('PATH' in str(error.message) for error in errors)


def test_validate_rule_basic():
    """Test validation of a basic RULE statement"""
    ndl_text = """
RULE rule1 TYPE=firewall BETWEEN=zone1,zone2
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is True


def test_validate_topology():
    """Test validation of TOPOLOGY statement"""
    ndl_text = """
TOPOLOGY TYPE=hierarchical LAYERS=3
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is True


def test_validate_ports():
    """Test validation of port specifications"""
    ndl_text = """
NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24
NETWORK internal TYPE=bridge SUBNET=10.2.0.0/24
ALLOW dmz -> internal PORTS=80,443,8000-8080 PROTOCOL=tcp
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is True


def test_validate_invalid_port():
    """Test validation catches invalid port numbers"""
    ndl_text = """
NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24
NETWORK internal TYPE=bridge SUBNET=10.2.0.0/24
ALLOW dmz -> internal PORTS=99999 PROTOCOL=tcp
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is False


def test_validate_semantic_undefined_network():
    """Test semantic validation catches undefined network reference"""
    ndl_text = """
SERVICE web IMAGE=nginx:latest NETWORK=undefined_network
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is False
    assert any('undefined' in str(error.message).lower() for error in errors)


def test_validate_semantic_ip_conflict():
    """Test semantic validation catches IP conflicts"""
    ndl_text = """
NETWORK dmz TYPE=bridge SUBNET=10.1.0.0/24
SERVICE web1 IMAGE=nginx:latest NETWORK=dmz IP=10.1.0.10
SERVICE web2 IMAGE=nginx:latest NETWORK=dmz IP=10.1.0.10
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is False
    assert any('conflict' in str(error.message).lower() for error in errors)


def test_validate_invalid_gateway():
    """Test validation catches gateway outside subnet"""
    ndl_text = """
NETWORK test TYPE=bridge SUBNET=10.1.0.0/24 GATEWAY=10.2.0.1
"""
    is_valid, errors, warnings = validate_ndl(ndl_text)
    assert is_valid is False
    assert any('GATEWAY' in str(error.message) for error in errors)


def test_validation_error_str():
    """Test ValidationError string representation"""
    from ndl_engine.ndl_parser import ValidationError
    error = ValidationError(
        Severity.ERROR,
        "Test error",
        10,
        "NETWORK test",
        "Fix this"
    )
    error_str = str(error)
    assert "ERROR" in error_str
    assert "Test error" in error_str
    assert "Line 10" in error_str
    assert "Fix this" in error_str
