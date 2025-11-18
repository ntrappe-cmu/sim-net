"""
Unit tests for ndl_parser.py

Simple hello world tests to validate the NDL validation parser functionality.
"""

import pytest
from ndl_engine.ndl_parser import validate_ndl, NDLValidator


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
