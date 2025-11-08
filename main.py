import anthropic
import os
from sim_net import NetworkManager

"""
Interactive script to let users use natual language to specify a network. LLM will
generate a docker-compose file. Then, we'll deploy the network using Docker Compose.
From there, the user can interact with the network using natural language commands.

Example: Make the simplest hello world network with just a victim and attack and 
the smallest container images (nginx and alpine)
"""

def get_claude_client():
    """Initialize Claude API client."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("ANTHROPIC_API_KEY not found in environment")
    return anthropic.Anthropic(api_key=api_key)

def get_system_context():
    """Return system prompt for Claude."""
    return """You are an experienced systems and network engineer helping students 
create experimental networks. When they describe a network in natural language:
1. Infer reasonable defaults (subnets, drivers, names)
2. Use bridge driver for simple networks, overlay for multi-host
3. Follow Docker networking best practices
4. Be concise and technical"""

def get_user_network_request():
    """Prompt user for network description."""
    return input("\033[36;1mDescribe the network you want to create: \033[0m")

def confirm_network_plan(client, system_context, user_request):
    """Have Claude summarize the plan and get user confirmation."""
    response = client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=1024,
        system=system_context,
        messages=[{
            "role": "user",
            "content": f"Analyze this network request and summarize what you'll create. Ask user to confirm (Y/yes) or provide feedback (N/no).\n\nRequest: {user_request}"
        }]
    )
    
    print(f"\n\033[36;1m{response.content[0].text}\033[0m\n")
    confirmation = input("Your response (Y/N): ").strip().lower()
    
    return confirmation in ['y', 'yes'], response.content[0].text

def generate_compose_file(client, system_context, user_request, initial_response):
    """Generate docker-compose.yml content."""
    print("\n\033[36;1mGenerating docker-compose.yml...\033[0m\n")
    
    conversation = [
        {"role": "user", "content": f"Analyze this network request and summarize what you'll create. Ask user to confirm (Y/yes) or provide feedback (N/no).\n\nRequest: {user_request}"},
        {"role": "assistant", "content": initial_response},
        {"role": "user", "content": "Generate the complete docker-compose.yml file. Provide only YAML content, no explanations."}
    ]
    
    response = client.messages.create(
        model="claude-sonnet-4-5-20250929",
        max_tokens=2048,
        system=system_context,
        messages=conversation
    )
    
    return response.content[0].text


def clean_yaml_content(yaml_content):
    """Remove markdown code fences from YAML."""
    lines = yaml_content.strip().split('\n')
    if len(lines) > 3 and lines[0].startswith('```'):
        return '\n'.join(lines[1:-1])
    return yaml_content


def save_compose_file(yaml_content, filename="docker-compose.yml"):
    """Save YAML content to file."""
    with open(filename, "w") as f:
        f.write(yaml_content)
    print(f"\033[36;1m✓ {filename} created\033[0m")
    return filename

def deploy_network(manager, compose_file, project_name="test-net"):
    """Deploy the network and return results."""
    if not input("\nDeploy network? (Y/N): ").strip().lower() in ['y', 'yes']:
        print("\033[31;1mSkipping deployment\033[0m")
        return False
    
    print("\n\033[36;1mDeploying network...\033[0m")
    success, msg, err = manager.deploy(compose_file, project_name)
    
    if success:
        print(f"\033[32;1m✓ {msg}\033[0m")
    else:
        print(f"\033[31;1m✗ {err}\033[0m")
    
    return success

def main():
    """Main workflow."""
    try:
        # Setup
        client = get_claude_client()
        system_context = get_system_context()
        manager = NetworkManager()
        
        # Get network description
        user_request = get_user_network_request()
        
        # Confirm plan
        confirmed, initial_response = confirm_network_plan(client, system_context, user_request)
        if not confirmed:
            print("\033[31;1mPlease refine your request and try again\033[0m")
            return
        
        # Generate compose file
        yaml_content = generate_compose_file(client, system_context, user_request, initial_response)
        yaml_content = clean_yaml_content(yaml_content)
        compose_file = save_compose_file(yaml_content)
        
        # Deploy and check status
        deploy_network(manager, compose_file)
            
    except Exception as e:
        print(f"\033[31;1mError: {e}\033[0m")

if __name__ == "__main__":
    main()