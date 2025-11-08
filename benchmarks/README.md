## 1. Equifax‑inspired (50 hosts, many DBs)
- Default: **bridge** per‑host network. Use separate networks for web / app / db segments.
- If you want to replicate multi‑host behavior or real VLAN separation, consider using **overlay** or separate subnets + a router container.

## 2. Colonial Pipeline‑inspired (IT/IT/OT)
- OT often requires simulating device/fieldbus behavior and sometimes L2 connectivity. Default use **bridge** for IT networks; for OT consider **macvlan** or host networking if you must emulate device MACs or physical separation.
- Also model a gateway/router between IT and OT networks.

## 3. Enterprise A (3 networks: web/employee/db)
- **Bridge** networks with an internal router/firewall container between segments is fine.

## 4. Enterprise B (4 networks)
- Same as A. Use one **bridge** per segment; if you need cross‑host deployment, switch to **overlay**.

## 5. 4‑Layer chain (credential chaining)
- **Bridge** is fine; careful with services that need privileged host access — these should be separate with explicit volume mounts.

## 6. 6‑Layer chain (privileged data + escalation vuln)
- **Bridge** works for logic. If you need to simulate privilege boundaries at the kernel/host level, consider VMs or host network containers for higher fidelity.

## 7–8. 4/6‑Layer star (RCE on hosts)
- Bridge networks; focus on vulnerability attributes as metadata rather than giving containers extra host visibility. Use separate networks if you want to model segmentation.

## 9–10. Dumbbell A/B (webservers ↔ databases)
- Two networks: external (web-facing) and internal (db). Bridge networks with strict network attachment for web vs db. Consider adding a reverse proxy container in the external network and keep DBs internal only.