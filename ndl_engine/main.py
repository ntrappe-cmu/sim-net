#!/usr/bin/env python3
"""
Sim-Net
Uses Anthropic's Claude to translate human requests into NDL, 
then compiles and deploys using the local NDL engine.
"""

import os
import sys
import subprocess
import anthropic
from typing import Tuple, Optional

# Import our internal engine
from ndl_parser import NDLParser
from ndl_converter import NDLConverter
from ndl_compose import DockerComposeGenerator

# ============================================================================
# Configuration & System Prompts
# ============================================================================

SIM_NET_PROMPT = """
You are an expert Network Architect for a security simulation platform.
Your job is to translate natural language requests into valid Network Definition Language (NDL) code.

NDL SYNTAX REFERENCE:
1. Define Networks:
   NETWORK name=dmz subnet=192.168.1.0/24 gateway=192.168.1.1
   
2. Define Services (Containers):
   SERVICE name=web image=nginx:alpine network=dmz count=2 ports=80:80 env=DEBUG=true
   (Note: 'count' creates multiple instances automatically)

3. Define Connectivity Rules:
   ALLOW src=dmz dst=internal port=5432 proto=TCP
   BLOCK src=ANY dst=internal port=22 proto=TCP

RULES:
- Infer reasonable subnets (10.x.x.x or 192.168.x.x) if not specified.
- Always define a NETWORK before a SERVICE that uses it.
- Use 'count' for scaling instead of defining multiple services manually.
- Use standard Docker images (alpine, nginx, postgres, ubuntu) unless specified.
- Output ONLY the NDL code in the final generation step.
"""

def get_claude_client():
    """Initialize Claude API client."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print("\033[31;1mError: ANTHROPIC_API_KEY environment variable not set.\033[0m")
        sys.exit(1)
    return anthropic.Anthropic(api_key=api_key)

# ============================================================================
# LLM Interaction Functions
# ============================================================================

def get_user_request() -> str:
    print("\n\033[36;1m===========================================\033[0m")
    print("\033[36;1m   SIM-NET Architect (Powered by Claude)   \033[0m")
    print("\033[36;1m===========================================\033[0m")
    return input("Describe the network you want to build: ")

def confirm_plan(client, user_request: str) -> Tuple[bool, str]:
    """Ask Claude to summarize the plan before generating code."""
    
    print("\n\033[90mThinking...\033[0m")
    
    message = client.messages.create(
        model="claude-sonnet-4-5-20250929", # Or your preferred model version
        max_tokens=1024,
        system=SIM_NET_PROMPT,
        messages=[{
            "role": "user",
            "content": f"Analyze this request. Briefly summarize the architecture (networks, services, scale) you will build. Do NOT write code yet.\n\nRequest: {user_request}"
        }]
    )
    
    summary = message.content[0].text
    print(f"\n\033[33;1mProposed Plan:\033[0m\n{summary}\n")
    
    confirm = input("Proceed with this plan? (Y/n): ").strip().lower()
    return confirm in ['', 'y', 'yes'], summary

def generate_ndl_code(client, user_request: str, plan_summary: str) -> str:
    """Ask Claude to generate the actual NDL code."""
    print("\n\033[36;1mGenerating NDL Specification...\033[0m")
    
    message = client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=2048,
        system=SIM_NET_PROMPT,
        messages=[
            {"role": "user", "content": user_request},
            {"role": "assistant", "content": plan_summary},
            {"role": "user", "content": "Generate the complete NDL code now. Provide ONLY the code inside a markdown code block."}
        ]
    )
    
    content = message.content[0].text
    return _clean_markdown(content)

def _clean_markdown(text: str) -> str:
    """Extract code from markdown fences."""
    lines = text.strip().split('\n')
    if lines[0].startswith('```'):
        # Find the end of the block
        end_idx = -1
        for i in range(len(lines)-1, 0, -1):
            if lines[i].startswith('```'):
                end_idx = i
                break
        return '\n'.join(lines[1:end_idx])
    return text

# ============================================================================
# Local Engine Integration
# ============================================================================

def compile_ndl_to_docker(ndl_content: str, output_filename: str) -> bool:
    """
    Feeds the AI-generated NDL into our local python engine.
    Returns True if successful.
    """
    # 1. Save to temp file
    ndl_file = "generated_ai.ndl"
    with open(ndl_file, "w") as f:
        f.write(ndl_content)
    
    print(f"\033[90m-> Saved draft to {ndl_file}\033[0m")

    # 2. Parse & Validate
    print("[1/3] Validating NDL syntax...")
    parser = NDLParser()
    spec, errors, warnings = parser.parse(ndl_file)
    
    if errors:
        print("\033[31;1m❌ AI Generation produced invalid NDL:\033[0m")
        for e in errors:
            print(f"  Line {e.line_number}: {e.message}")
        return False

    # 3. Convert to IR
    print("[2/3] Calculating IP allocations...")
    converter = NDLConverter()
    ir = converter.convert(ndl_file)
    
    if not ir:
        print("\033[31;1m❌ IR Conversion failed (IP exhaustion or logic error)\033[0m")
        return False

    # 4. Generate Docker Compose
    print("[3/3] Generating Docker Compose YAML...")
    generator = DockerComposeGenerator()
    yaml_output = generator.generate(ir)
    
    with open(output_filename, "w") as f:
        f.write(yaml_output)
        
    print(f"\033[32;1m✓ Successfully compiled to {output_filename}\033[0m")
    return True

def deploy_docker(compose_file: str):
    """Run docker-compose up."""
    confirm = input("\nDo you want to deploy this network now? (Y/n): ").strip().lower()
    if confirm not in ['', 'y', 'yes']:
        print("Skipping deployment.")
        return

    print(f"\n\033[36;1mDeploying {compose_file}...\033[0m")
    try:
        subprocess.run(["docker-compose", "-f", compose_file, "up", "-d"], check=True)
        print("\n\033[32;1m✓ Deployment Complete!\033[0m")
        print("Run 'docker ps' to see your containers.")
    except subprocess.CalledProcessError:
        print("\n\033[31;1m❌ Docker deployment failed.\033[0m Check if Docker Desktop is running.")

# ============================================================================
# Main Workflow
# ============================================================================

def main():
    try:
        # 1. Setup
        client = get_claude_client()
        
        # 2. Get Intent
        user_req = get_user_request()
        
        # 3. Plan & Confirm
        confirmed, summary = confirm_plan(client, user_req)
        if not confirmed:
            print("Aborted.")
            return

        # 4. Generate Code
        ndl_code = generate_ndl_code(client, user_req, summary)
        print(f"\n\033[90m-- Generated NDL --\n{ndl_code}\n-------------------\033[0m")

        # 5. Compile locally (The Safety Check)
        compose_file = "ai_docker_compose.yml"
        success = compile_ndl_to_docker(ndl_code, compose_file)
        
        # 6. Deploy
        if success:
            deploy_docker(compose_file)

    except KeyboardInterrupt:
        print("\nGoodbye!")
    except Exception as e:
        print(f"\n\033[31;1mError: {e}\033[0m")

if __name__ == "__main__":
    main()