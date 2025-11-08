import docker
import os
import yaml
import subprocess
from docker.errors import DockerException, APIError, NotFound

# (a) LLM generation validation
#     LLM should generate a valid docker-compose file for a high level
#     description of a network.
#     Risks: (i) Can LLMs understand high level network descriptions?
#            (ii) Can LLMs generate valid docker-compose files?
#            (iii) Can LLMs generate semantically correct networks?
# (b) container deployment validation
#     Develop an API that allows user to start, stop, and monitor the
#     network. Also can execute an attack using an LLM.
# (c) integration

# Docker system networks that should not be created or removed
SYSTEM_NETWORKS = {'bridge', 'host', 'none'}

class NetworkManager:
    def __init__(self):
        try:
            self.client = docker.from_env()
            self.client.ping()
            self.active_networks = {}
        except docker.errors.DockerException as e:
            raise Exception(f"Cannot connect to Docker daemon: {e}")

    def deploy(self, network_spec, project_name='network'):
        """
        Deploy network from a docker-compose.yml or mininet .py file.
        Returns: (success: bool, message: str, error: str or None)
        """
        # Detect file type
        if network_spec.endswith('.yml') or network_spec.endswith('.yaml'):
            return self._deploy_docker_compose(network_spec, project_name)
        elif network_spec.endswith('.py'):
            return self._deploy_mininet(network_spec, project_name)
        else:
            return False, "", f"ERROR: Unsupported file type: {network_spec}\nUse .yml/.yaml for docker-compose or .py for mininet."

    def status(self, project_name=None):
        """
        Show network status with containers, networks, and health.
        If project_name is None, show all active networks.
        """
        if project_name:
            return self._status_single(project_name)
        else:
            return self._status_all()
        
    def _status_single(self, project_name):
        """
        Detail status for a single network.
        """
        if 'test-net' not in self.active_networks:
            print("active networks:", self.active_networks)
            return False, "", f"ERROR: No active network with name '{project_name}'"
        
        network_info = self.active_networks[project_name]

        # Get containers
        containers = self.client.containers.list(
            all=True,
            filters={'label': f'com.docker.compose.project={project_name}'}
        )

        networks = set()
        for c in containers:
            networks.update(c.attrs['NetworkSettings']['Networks'].keys())

        # Build status
        output = [f"\n=== Network: {project_name} ==="]
        output.append(f"Status: {'🟢 Running' if containers else '🔴 Stopped'}")
        output.append(f"Compose file: {network_info['compose_file']}")

        # Networks section
        output.append(f"\nNetworks ({len(networks)}):")
        for net_name in networks:
            try:
                net = self.client.networks.get(net_name)
                subnet = net.attrs['IPAM']['Config'][0]['Subnet'] if net.attrs['IPAM']['Config'] else 'N/A'
                output.append(f"  • {net_name} - {subnet}")
            except:
                output.append(f"  • {net_name}")

        # Containers section
        output.append(f"\nContainers ({len(containers)}):")
        for c in containers:
            status_icon = "🟢" if c.status == "running" else "🔴"
            
            # Get IP address
            networks_data = c.attrs['NetworkSettings']['Networks']
            ip = list(networks_data.values())[0]['IPAddress'] if networks_data else 'N/A'
            
            # Health check
            health = c.attrs['State'].get('Health', {}).get('Status', 'N/A')
            health_str = f" [{health}]" if health != 'N/A' else ""
            
            output.append(f"  {status_icon} {c.name}")
            output.append(f"      IP: {ip} | Status: {c.status}{health_str}")
            
            # Show error if container crashed
            if c.status == 'exited':
                exit_code = c.attrs['State']['ExitCode']
                output.append(f"      ⚠️  Exited with code {exit_code}")
        
        return '\n'.join(output)

    def _deploy_docker_compose(self, compose_file, project_name):
        """
        Deploy network from docker-compose file.
        Returns: (success: bool, message: str, error: str or None)
        """

        # 1. File validation
        try:
            with open(compose_file, 'r') as file:
                content = file.read()
                if not content.strip():
                    return False, "", f"ERROR: Compose file is empty: {compose_file}"
        except FileNotFoundError:
            return False, "", f"ERROR: Compose file not found: {compose_file}\nCheck the path is correct."
        except PermissionError:
            return False, "", f"ERROR: Cannot read {compose_file}\nCheck file permissions."
        
        # 2. YAML syntax validation
        try:
            with open(compose_file, 'r') as file:
                yaml.safe_load(file)
        except yaml.YAMLError as e:
            return False, "", f"ERROR: Invalid YAML syntax in {compose_file}\nDetails: {e}"
        
        # 3. Check for name conflicts
        existing = self.client.containers.list(
            filters={'label': f'com.docker.compose.project={project_name}'}
        )
        if existing:
            return False, "", f"ERROR: A network with project name '{project_name}' is already running."

        # 4. Deploy using docker-compose
        try:
            result = subprocess.run(
                ['docker-compose', '-f', compose_file, '-p', project_name, 'up', '-d'],
                capture_output=True,
                text=True,
                timeout=120
            )

            # 5. Check for specific errors patterns
            if "pool overlaps" in result.stderr.lower() or "address space" in result.stderr.lower():
                return False, "", f"ERROR: IP address conflict\nAnother network network is using these IPs. Change subnet in compose file."
            
            if "port is already allocated" in result.stderr.lower():
                import re
                port_match = re.search(r'port (\d+)', result.stderr.lower())
                port = port_match.group(1) if port_match else "unknown"
                return False, "", f"ERROR: Port {port} already in use\nStop other services using this port or change port in compose file."
            
            if "no such image" in result.stderr.lower():
                return False, "", "ERROR: Docker image not found\nCheck image names in compose file or run: docker pull <image>"

            # 6. Generic failure
            if result.returncode != 0:
                return False, result.stdout, f"ERROR: docker-compose failed\nExit code: {result.returncode}\nDetails: {result.stderr}"
            
            # 7. Verify containers started
            containers = self.client.containers.list(
                filters={'label': f'com.docker.compose.project={project_name}'}
            )

            if not containers:
                return False, "", f"ERROR: No containers started\nCompose command succeeded but found no running containers.\nCheck logs: docker-compose -p {project_name} logs"
            
            # 8. Check if any containers immediately exited
            all_containers = self.client.containers.list(
                all=True,
                filters={'label': f'com.docker.compose.project={project_name}'}
            )
            exited = [c for c in all_containers if c.status == 'exited']
            if exited:
                exited_names = ', '.join([c.name for c in exited])
                return False, "", f"WARNING: Some containers crashed immediately: {exited_names}\nCheck logs: docker logs {exited[0].name}"

            # 9. Success
            self.active_networks[project_name] = {
                'compose_file': compose_file,
                'containers': [c.name for c in containers]
            }
            # print('added: ', self.active_networks)

            return True, f"Started {len(containers)} containers", None
        
        except subprocess.TimeoutExpired:
            return False, "", f"ERROR: Deployment timed out after 120s\nContainers may still be starting. Check: docker ps"
        except DockerException as e:
            return False, "", f"ERROR: Docker daemon error\nDetails: {str(e)}\nIs Docker running? Check: docker info"
        except Exception as e:
            return False, "", f"ERROR: Unexpected failure\nDetails: {str(e)}"

    def _deploy_mininet(self, python_file, project_name):
        """
        Deploy network from mininet python file.
        Returns: (success: bool, message: str, error: str or None)
        """
        # 1. File validation
        try:
            with open(python_file, 'r') as file:
                content = file.read()
                if not content.strip():
                    return False, "", f"ERROR: Mininet script is empty: {python_file}"
                if 'Mininet' not in content:
                    return False, "", f"ERROR: Invalid Mininet script: {python_file}\nMissing 'Mininet' import."
        except FileNotFoundError:
            return False, "", f"ERROR: Mininet script not found: {python_file}\nCheck the path is correct."
        except PermissionError:
            return False, "", f"ERROR: Cannot read {python_file}\nCheck file permissions"
        
        # 2. Check Mininet installation
        try:
            subprocess.run(['mn', '--version'], capture_output=True, text=True)
        except FileNotFoundError:
            return False, "", "ERROR: Mininet not installed\nInstall: sudo apt-get install mininet"

        # Mininet requires root
        if os.geteuid() != 0:
            return False, "", "ERROR: Mininet requires root\nRun with: sudo python your_script.py"
            

        # 3. Deploy Mininet network
        try:
            # Run Mininet script in background
            result = subprocess.Popen(
                ['python3', python_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        
            # Wait briefly to check for immediate failures
            import time
            time.sleep(2)
            poll = result.poll()
            
            if poll is not None:  # Process exited
                _, stderr = result.communicate()
                return False, "", f"ERROR: Mininet script failed\n{stderr}"
            
            # Track progress
            self.active_networks[project_name] = {
                'type': 'mininet',
                'file': python_file,
                'process': result
            }
            return True, "Mininet network started", None
        except Exception as e:
            return False, "", f"ERROR: Failed to run Mininet\n{str(e)}"
            

# manager = NetworkManager()
# success, msg, err = manager.deploy('/Users/ntrappe/Desktop/CMU/Research/sim-net/approach-1/docker-compose.yml', 'nginx-test-network')
# if success:
#     print(f"\033[92m✔️ {msg}\033[0m")
# else:
#     print(f"\033[91m✘ Failed: {err}\033[0m")
# print(manager.status('nginx-test-network'))
# print('active networks?', manager.active_networks)
