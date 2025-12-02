#!/usr/bin/env python3
"""
NDL CLI - Unified Pipeline
Runs Parser -> Validator -> Converter -> Generator
"""

import sys
import argparse
import os

# Import our pipeline modules
from ndl_parser import NDLParser
from ndl_converter import NDLConverter
from ndl_compose import DockerComposeGenerator

def main():
    parser = argparse.ArgumentParser(description="NDL Network Deployer")
    parser.add_argument("ndl_file", help="Path to the .ndl file")
    parser.add_argument("-o", "--output", default="docker-compose.yml", help="Output file path")
    parser.add_argument("--dry-run", action="store_true", help="Validate only, do not generate output")
    args = parser.parse_args()

    print(f"--- NDL Pipeline Started: {args.ndl_file} ---")

    # 1. Parse & Validate
    print("[1/3] Parsing and Validating...")
    parser_tool = NDLParser()
    spec, errors, warnings = parser_tool.parse(args.ndl_file)

    if errors:
        print("\n❌ Validation Failed:")
        for e in errors:
            print(f"  [{e.file_name}:{e.line_number}] {e.message}")
        sys.exit(1)
    
    if warnings:
        print("\n⚠️  Warnings:")
        for w in warnings:
            print(f"  [{w.file_name}:{w.line_number}] {w.message}")

    # 2. Convert to IR (Intermediate Representation)
    print(f"[2/3] Converting to IR (Expanding {len(spec.services)} definitions)...")
    converter = NDLConverter()
    # Note: Using the 'spec' we just parsed, rather than re-parsing file
    # We need to slightly adjust converter usage to accept spec object
    # For now, we follow the pattern of the class provided previously:
    ir = converter.convert(args.ndl_file) 
    
    if not ir:
        print("❌ Conversion failed (IP Exhaustion or Logic Error)")
        sys.exit(1)

    if args.dry_run:
        print("✅ Dry run complete. No output generated.")
        sys.exit(0)

    # 3. Generate Docker Compose
    print(f"[3/3] Generating Docker Compose...")
    generator = DockerComposeGenerator()
    yaml_output = generator.generate(ir)

    # 4. Write Output
    with open(args.output, 'w') as f:
        f.write(yaml_output)
    
    print(f"\n✅ Success! Deployed definition to: {args.output}")
    print(f"   - Networks: {len(ir.networks)}")
    print(f"   - Containers: {len(ir.services)}")
    print("\nTo launch: docker-compose up -d")

if __name__ == "__main__":
    main()