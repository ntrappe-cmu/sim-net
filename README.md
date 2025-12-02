# SIM-NET: AI-Powered Network Simulation

SIM-NET is a toolchain for rapidly defining, simulating, and deploying complex network topologies using Docker. It bridges the gap between high-level architectural design and low-level container orchestration.

Instead of writing thousands of lines of verbose `docker-compose.yml` configuration, you define your network in a simple, human-readable syntax called NDL (Network Definition Language). The SIM-NET engine handles IP address management (IPAM), subnet calculation, service scaling, and router configuration automatically.

SIM-NET features an AI Architect mode powered by Claude, allowing you to build networks using natural language. The LLM writes the NDL code, and SIM-NET validates and compiles it into a deployable environment.

## Getting Started

### AI Architect (*)
The easiest way to start. Describe what you want, and the LLM writes the NDL for you.

1. **Navigate to the engine directory:**

```bash
cd ndl_engine
```

2. **Run the AI CLI:**
```bash
python3 ndl_llm_cli.py
```

3. **Example Interaction:**
> 4 Layer chain. Each host has credentials to another host in the network. Each host has critical data. 25 hosts.

The system will:
  - Plan the architecture and ask for confirmation.
  - Generate valid NDL code.
  - Compile it to Docker Compose.
  - Ask to deploy it immediately.

### Manual NDL (File-Based)

For precise control or reproducible scenarios, write `.ndl` files directly.

1. **Write your file (e.g., `benchmarks/01_equifax.ndl`):
```bash
NETWORK name=dmz subnet=10.0.1.0/24
SERVICE name=web image=nginx:alpine network=dmz count=3
```

2. **Compile it:**
```bash
cd ndl_engine
python3 ndl_cli.py ../benchmarks/01_equifax.ndl -o ../benchmarks/docker-compose.yml
```

3. **Deploy it:**
```bash
cd ../benchmarks
docker-compose -f docker-compose.yml up -d
```

## Features

- **Human-Readable Syntax (NDL):** Define networks, services, and rules in one line each.
- **Automatic IPAM:** No more manual IP assignment. The engine calculates subnets and prevents conflicts.
- **Security Metadata:** Define ALLOW/BLOCK rules and vulnerability data (CVEs) directly in the topology.
- **AI-Powered Design:** Describe a "corporate network with a DMZ" in plain English, and the system builds it.

## Architecture

The system follows a strict pipeline to ensure reliability:
1. **Input:** User provides Natural Language (AI Mode) or raw NDL files (Manual Mode).
2. **LLM Layer:** Translates Natural Language into valid NDL.
3. **Sim-Net Engine:**
  - **Parser:** Validates syntax and checks for semantic errors (e.g., referencing a missing network).
  - **Converter:** Expands service counts into concrete instances and allocates static IPs.
  - **Generator:** Transpiles the Internal Representation into a valid `docker-compose.yml`.
4. **Runtime:** Docker Compose deploys the containers.

## ⚠️ Important Disclaimers

### The Role of the AI

The LLM (Claude) is responsible for **Architecture and NDL Syntax**. It ensures the logical design makes sense (e.g., "Web servers need to talk to Databases").
- It writes the **NDL** intermediary file.
- It does not interact directly with your Docker daemon.

### Docker Runtime Realities

Sim-Net generates valid Docker Compose files, but the **LLM cannot guarantee successful deployment**. Runtime failures may still occur due to your local environment:

1. **Port Conflicts:** If you already have a service on port 80, the deployment will fail. You must check your own open ports.
2. **Resource Exhaustion:** Asking for "50 databases" in your description will generate valid code, but may crash your computer if you lack the RAM.
3. **Image Pulls:** If the LLM hallucinates a non-existent Docker image name, the deployment will hang during the pull phase.

## Project Structure
```
/
├── ndl_engine/           # Sim-Net Core Logic
│   ├── ndl_cli.py        # Manual CLI Entrypoint for testing
│   ├── ndl_llm_cli.py    # AI CLI Entrypoint (*)
│   ├── ndl_parser.py     # Syntax & Validation
│   ├── ndl_converter.py  # IP Allocation & Logic
│   └── ndl_compose.py    # YAML Generation
├── benchmarks/           # Examples from MHBench
│   ├── 01_equifax.ndl
│   └── 02_colonial_pipeline.ndl
└── README.md
```
