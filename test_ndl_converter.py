"""
Unit tests for ndl_converter.py

Simple hello world tests to validate the NDL to IR converter functionality.
"""

import pytest
from ndl_engine.ndl_converter import NDLConverter, Network


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
