#!/usr/bin/env python3
"""
GCP Architecture Scanner MCP Server
Scans GCP environments across all accessible projects and generates architecture insights.
Credentials: set GOOGLE_APPLICATION_CREDENTIALS or use Application Default Credentials.
"""

import asyncio
import json
import os
import warnings
from datetime import datetime, timezone
from typing import Any

warnings.filterwarnings("ignore")

import google.auth
import google.auth.transport.requests
import requests as req_lib
from google.cloud import compute_v1, storage, container_v1
from google.api_core.exceptions import GoogleAPICallError

from mcp.server import Server
from mcp.types import Tool, TextContent
import mcp.server.stdio

server = Server("gcp-architecture-scanner")


# ── auth & HTTP helpers ────────────────────────────────────────────────────────

def _refresh_token() -> str:
    creds, _ = google.auth.default(scopes=["https://www.googleapis.com/auth/cloud-platform"])
    creds.refresh(google.auth.transport.requests.Request())
    return creds.token


def _get(url: str, params: dict = None) -> dict:
    r = req_lib.get(
        url,
        headers={"Authorization": f"Bearer {_refresh_token()}"},
        params=params,
        verify=False,
    )
    r.raise_for_status()
    return r.json()


def _ok(data: dict) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(data, indent=2, default=str))]


def _err(e: Exception) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps({"error": str(e)}, indent=2))]


def _default_project() -> str:
    _, project = google.auth.default()
    return project or os.environ.get("GOOGLE_PROJECT", "")


# ── scan functions ─────────────────────────────────────────────────────────────

def _list_projects() -> list[dict]:
    data = _get("https://cloudresourcemanager.googleapis.com/v1/projects")
    return [
        {
            "project_id": p["projectId"],
            "name": p.get("name", ""),
            "state": p.get("lifecycleState", ""),
            "labels": p.get("labels", {}),
            "parent": p.get("parent", {}),
        }
        for p in data.get("projects", [])
        if p.get("lifecycleState") == "ACTIVE"
    ]


def _scan_networks(project: str) -> list[dict]:
    try:
        client = compute_v1.NetworksClient()
        result = []
        for net in client.list(project=project):
            subnets = []
            for url in net.subnetworks:
                parts = url.split("/")
                region_idx = parts.index("regions") + 1 if "regions" in parts else None
                subnets.append({
                    "name": parts[-1],
                    "region": parts[region_idx] if region_idx else "unknown",
                })
            result.append({
                "name": net.name,
                "description": net.description,
                "auto_create_subnetworks": net.auto_create_subnetworks,
                "routing_mode": net.routing_config.routing_mode if net.routing_config else None,
                "subnet_count": len(subnets),
                "subnets": subnets,
            })
        return result
    except GoogleAPICallError as e:
        return [{"error": str(e)}]


def _scan_subnets(project: str) -> list[dict]:
    try:
        client = compute_v1.SubnetworksClient()
        result = []
        for _scope, scoped in client.aggregated_list(project=project):
            for sub in scoped.subnetworks:
                result.append({
                    "name": sub.name,
                    "region": sub.region.split("/")[-1] if sub.region else None,
                    "network": sub.network.split("/")[-1] if sub.network else None,
                    "ip_cidr_range": sub.ip_cidr_range,
                    "private_ip_google_access": sub.private_ip_google_access,
                    "purpose": sub.purpose,
                })
        return result
    except GoogleAPICallError as e:
        return [{"error": str(e)}]


def _scan_firewalls(project: str) -> list[dict]:
    try:
        client = compute_v1.FirewallsClient()
        result = []
        for fw in client.list(project=project):
            allowed = [
                {"protocol": r.I_p_protocol, "ports": list(r.ports)}
                for r in fw.allowed
            ]
            denied = [
                {"protocol": r.I_p_protocol, "ports": list(r.ports)}
                for r in fw.denied
            ]
            result.append({
                "name": fw.name,
                "network": fw.network.split("/")[-1] if fw.network else None,
                "direction": fw.direction,
                "priority": fw.priority,
                "action": "allow" if allowed else "deny",
                "rules": allowed or denied,
                "source_ranges": list(fw.source_ranges),
                "target_tags": list(fw.target_tags),
                "disabled": fw.disabled,
            })
        return result
    except GoogleAPICallError as e:
        return [{"error": str(e)}]


def _scan_instances(project: str) -> list[dict]:
    try:
        client = compute_v1.InstancesClient()
        result = []
        for _scope, scoped in client.aggregated_list(project=project):
            for inst in scoped.instances:
                internal_ip = external_ip = network = subnetwork = None
                if inst.network_interfaces:
                    nic = inst.network_interfaces[0]
                    internal_ip = nic.network_i_p
                    network = nic.network.split("/")[-1] if nic.network else None
                    subnetwork = nic.subnetwork.split("/")[-1] if nic.subnetwork else None
                    if nic.access_configs:
                        external_ip = nic.access_configs[0].nat_i_p or None
                result.append({
                    "name": inst.name,
                    "status": inst.status,
                    "machine_type": inst.machine_type.split("/")[-1] if inst.machine_type else None,
                    "zone": inst.zone.split("/")[-1] if inst.zone else None,
                    "internal_ip": internal_ip,
                    "external_ip": external_ip,
                    "network": network,
                    "subnetwork": subnetwork,
                    "labels": dict(inst.labels),
                    "tags": list(inst.tags.items) if inst.tags else [],
                })
        return result
    except GoogleAPICallError as e:
        return [{"error": str(e)}]


def _scan_buckets(project: str) -> list[dict]:
    try:
        client = storage.Client(project=project)
        result = []
        for b in client.list_buckets():
            result.append({
                "name": b.name,
                "location": b.location,
                "storage_class": b.storage_class,
                "labels": dict(b.labels) if b.labels else {},
                "versioning_enabled": b.versioning_enabled,
                "uniform_bucket_level_access": b.iam_configuration.uniform_bucket_level_access_enabled,
            })
        return result
    except GoogleAPICallError as e:
        return [{"error": str(e)}]


def _scan_gke(project: str) -> list[dict]:
    try:
        client = container_v1.ClusterManagerClient()
        resp = client.list_clusters(parent=f"projects/{project}/locations/-")
        return [
            {
                "name": c.name,
                "location": c.location,
                "status": c.status.name,
                "version": c.current_master_version,
                "node_count": c.current_node_count,
                "network": c.network,
                "subnetwork": c.subnetwork,
                "endpoint": c.endpoint,
                "private_cluster": c.private_cluster_config.enable_private_nodes if c.private_cluster_config else False,
            }
            for c in resp.clusters
        ]
    except GoogleAPICallError as e:
        return [{"error": str(e)}]


def _scan_artifact_registry(project: str) -> list[dict]:
    regions = ["europe-west2", "europe", "us", "us-central1", "asia", "asia-east1", "asia-northeast1"]
    result = []
    for loc in regions:
        try:
            token = _refresh_token()
            url = f"https://artifactregistry.googleapis.com/v1/projects/{project}/locations/{loc}/repositories"
            r = req_lib.get(url, headers={"Authorization": f"Bearer {token}"}, verify=False)
            if r.ok:
                for repo in r.json().get("repositories", []):
                    name = repo.get("name", "").split("/repositories/")[-1]
                    result.append({
                        "name": name,
                        "location": loc,
                        "format": repo.get("format", ""),
                        "mode": repo.get("mode", ""),
                        "size_bytes": int(repo.get("sizeBytes", 0)),
                        "create_time": repo.get("createTime", ""),
                        "update_time": repo.get("updateTime", ""),
                        "description": repo.get("description", ""),
                        "labels": repo.get("labels", {}),
                    })
        except Exception:
            pass
    return result


def _scan_shared_vpc(project: str) -> dict:
    try:
        base = "https://compute.googleapis.com/compute/v1/projects"
        # Is this project a host? Get its associated service projects.
        r = req_lib.get(
            f"{base}/{project}/getXpnResources",
            headers={"Authorization": f"Bearer {_refresh_token()}"},
            verify=False,
        )
        service_projects = []
        if r.ok:
            for res in r.json().get("resources", []):
                service_projects.append(res.get("id", ""))

        # Is this project a service project? Get its host.
        r2 = req_lib.get(
            f"{base}/{project}/getXpnHost",
            headers={"Authorization": f"Bearer {_refresh_token()}"},
            verify=False,
        )
        host_project = None
        if r2.ok and r2.json().get("name"):
            host_project = r2.json()["name"]

        return {
            "is_host_project": bool(service_projects),
            "service_projects": service_projects,
            "host_project": host_project,
            "is_service_project": bool(host_project),
        }
    except Exception as e:
        return {"error": str(e)}


def _full_project_scan(project: str) -> dict:
    return {
        "project_id": project,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "networks": _scan_networks(project),
        "subnets": _scan_subnets(project),
        "firewall_rules": _scan_firewalls(project),
        "compute_instances": _scan_instances(project),
        "gcs_buckets": _scan_buckets(project),
        "gke_clusters": _scan_gke(project),
        "artifact_registry": _scan_artifact_registry(project),
        "shared_vpc": _scan_shared_vpc(project),
    }


def _security_scan(project: str) -> dict:
    concerns = []

    # Default VPC check
    for net in _scan_networks(project):
        if isinstance(net, dict) and "error" not in net:
            if net["name"] == "default":
                concerns.append({
                    "severity": "MEDIUM",
                    "resource": f"VPC: {net['name']}",
                    "issue": "Default VPC exists — spans all regions with auto-created subnets",
                    "recommendation": "Delete the default VPC if no workloads depend on it",
                })
            if net.get("auto_create_subnetworks") and net["name"] != "default":
                concerns.append({
                    "severity": "LOW",
                    "resource": f"VPC: {net['name']}",
                    "issue": "Auto-create subnetworks enabled — implicit subnets across all regions",
                    "recommendation": "Use custom mode VPC for explicit subnet management",
                })

    # Overly permissive firewall rules
    for fw in _scan_firewalls(project):
        if isinstance(fw, dict) and "error" not in fw and not fw.get("disabled"):
            if "0.0.0.0/0" in fw.get("source_ranges", []) and fw.get("action") == "allow":
                risky_ports = []
                for rule in fw.get("rules", []):
                    ports = rule.get("ports", [])
                    proto = rule.get("protocol", "")
                    if proto in ("all", "tcp", "udp") and (
                        not ports or any(p in ports for p in ["22", "3389", "0-65535"])
                    ):
                        risky_ports.extend(ports or ["ALL"])
                if risky_ports:
                    concerns.append({
                        "severity": "HIGH",
                        "resource": f"Firewall: {fw['name']}",
                        "issue": f"Allows inbound from 0.0.0.0/0 on ports: {risky_ports}",
                        "recommendation": "Restrict source ranges; use Cloud IAP for admin access",
                    })

    # GCE instances with public IPs
    for inst in _scan_instances(project):
        if isinstance(inst, dict) and "error" not in inst:
            if inst.get("external_ip"):
                concerns.append({
                    "severity": "MEDIUM",
                    "resource": f"GCE: {inst['name']} ({inst['zone']})",
                    "issue": f"Instance has a public IP: {inst['external_ip']}",
                    "recommendation": "Use Cloud IAP or a load balancer; remove direct public IP",
                })

    # GCS bucket access controls
    for bucket in _scan_buckets(project):
        if isinstance(bucket, dict) and "error" not in bucket:
            if not bucket.get("uniform_bucket_level_access"):
                concerns.append({
                    "severity": "LOW",
                    "resource": f"GCS: {bucket['name']}",
                    "issue": "Uniform bucket-level access disabled — object ACLs can bypass bucket policy",
                    "recommendation": "Enable uniform bucket-level access",
                })

    # GKE clusters without private nodes
    for cluster in _scan_gke(project):
        if isinstance(cluster, dict) and "error" not in cluster:
            if not cluster.get("private_cluster"):
                concerns.append({
                    "severity": "MEDIUM",
                    "resource": f"GKE: {cluster['name']} ({cluster['location']})",
                    "issue": "GKE cluster is not a private cluster — nodes may have public IPs",
                    "recommendation": "Enable private nodes and private endpoint for production clusters",
                })

    return {
        "project_id": project,
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "total_concerns": len(concerns),
        "high": sum(1 for c in concerns if c["severity"] == "HIGH"),
        "medium": sum(1 for c in concerns if c["severity"] == "MEDIUM"),
        "low": sum(1 for c in concerns if c["severity"] == "LOW"),
        "concerns": concerns,
    }


def _generate_markdown_report(projects: list[dict], output_path: str) -> str:
    lines = [
        "# GCP Architecture Report",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Projects scanned:** {len(projects)}",
        "",
        "---",
        "",
        "## Project Inventory",
        "",
        "| Project ID | Name | Labels |",
        "|---|---|---|",
    ]
    for p in projects:
        labels = ", ".join(f"{k}={v}" for k, v in p.get("labels", {}).items()) or "—"
        lines.append(f"| `{p['project_id']}` | {p.get('name', '—')} | {labels} |")

    lines += ["", "---", ""]

    for p in projects:
        pid = p["project_id"]
        lines += [f"## Project: `{pid}`", ""]
        scan = _full_project_scan(pid)
        security = _security_scan(pid)
        shared = scan["shared_vpc"]

        # Shared VPC role
        if shared.get("is_host_project"):
            lines.append(f"**Role:** Shared VPC Host — serves: {', '.join(shared['service_projects'])}")
        elif shared.get("is_service_project"):
            lines.append(f"**Role:** Shared VPC Service Project — host: `{shared['host_project']}`")
        else:
            lines.append("**Role:** Standalone project")
        lines.append("")

        # Networking
        nets = [n for n in scan["networks"] if "error" not in n]
        if nets:
            lines += ["### Networking", "", "| VPC | Mode | Subnets |", "|---|---|---|"]
            for net in nets:
                mode = "Auto" if net["auto_create_subnetworks"] else "Custom"
                lines.append(f"| `{net['name']}` | {mode} | {net['subnet_count']} |")
            lines.append("")

            subnets = [s for s in scan["subnets"] if "error" not in s]
            if subnets:
                lines += ["**Subnets:**", "", "| Name | Network | Region | CIDR | Private Google Access |", "|---|---|---|---|---|"]
                for sub in subnets:
                    pga = "Yes" if sub.get("private_ip_google_access") else "No"
                    lines.append(f"| `{sub['name']}` | {sub['network']} | {sub['region']} | {sub['ip_cidr_range']} | {pga} |")
                lines.append("")

        # Compute
        instances = [i for i in scan["compute_instances"] if "error" not in i]
        if instances:
            lines += ["### Compute (GCE)", "", "| Name | Status | Type | Zone | Internal IP | External IP |", "|---|---|---|---|---|---|"]
            for inst in instances:
                ext = inst.get("external_ip") or "None"
                lines.append(f"| `{inst['name']}` | {inst['status']} | {inst['machine_type']} | {inst['zone']} | {inst['internal_ip']} | {ext} |")
            lines.append("")
        else:
            lines += ["### Compute (GCE)", "", "_No GCE instances_", ""]

        # GKE
        clusters = [c for c in scan["gke_clusters"] if "error" not in c]
        if clusters:
            lines += ["### GKE Clusters", "", "| Name | Location | Status | Version | Nodes | Private |", "|---|---|---|---|---|---|"]
            for c in clusters:
                private = "Yes" if c.get("private_cluster") else "No"
                lines.append(f"| `{c['name']}` | {c['location']} | {c['status']} | {c['version']} | {c['node_count']} | {private} |")
            lines.append("")

        # Storage
        buckets = [b for b in scan["gcs_buckets"] if "error" not in b]
        if buckets:
            lines += ["### Cloud Storage (GCS)", "", "| Bucket | Location | Class | Versioning | Uniform Access |", "|---|---|---|---|---|"]
            for b in buckets:
                ver = "Yes" if b.get("versioning_enabled") else "No"
                uba = "Yes" if b.get("uniform_bucket_level_access") else "No"
                lines.append(f"| `{b['name']}` | {b['location']} | {b['storage_class']} | {ver} | {uba} |")
            lines.append("")
        else:
            lines += ["### Cloud Storage (GCS)", "", "_No GCS buckets_", ""]

        # Security
        lines += [
            "### Security Posture",
            "",
            f"**Concerns:** {security['total_concerns']} "
            f"(HIGH: {security['high']}, MEDIUM: {security['medium']}, LOW: {security['low']})",
            "",
        ]
        if security["concerns"]:
            lines += ["| Severity | Resource | Issue | Recommendation |", "|---|---|---|---|"]
            for c in security["concerns"]:
                lines.append(f"| **{c['severity']}** | {c['resource']} | {c['issue']} | {c['recommendation']} |")
        else:
            lines.append("_No security concerns detected_")
        lines += ["", "---", ""]

    report = "\n".join(lines)
    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w") as f:
        f.write(report)
    return f"Report written to: {output_path} ({len(lines)} lines)"


# ── diagram generator ─────────────────────────────────────────────────────────

def _generate_diagram(projects: list[dict], output_path: str, fmt: str = "png") -> str:
    from diagrams import Diagram, Cluster, Edge
    from diagrams.gcp.network import VPC, FirewallRules, NAT
    from diagrams.gcp.compute import GCE, GKE
    from diagrams.gcp.storage import GCS
    from diagrams.gcp.devtools import Build, GCR
    from diagrams.gcp.security import IAP

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)

    # Collect full scan data for all projects
    scans = {p["project_id"]: _full_project_scan(p["project_id"]) for p in projects}

    # Identify host→service relationships
    host_to_services: dict[str, list[str]] = {}
    service_to_host: dict[str, str] = {}
    for pid, scan in scans.items():
        svpc = scan.get("shared_vpc", {})
        if svpc.get("is_host_project"):
            host_to_services[pid] = svpc.get("service_projects", [])
        if svpc.get("is_service_project") and svpc.get("host_project"):
            service_to_host[pid] = svpc["host_project"]

    base = os.path.splitext(output_path)[0]

    with Diagram(
        "GCP Environment Architecture",
        filename=base,
        outformat=fmt,
        show=False,
        direction="TB",
        graph_attr={"pad": "0.75", "splines": "ortho", "nodesep": "0.8", "ranksep": "1.2"},
    ):
        iap = IAP("Cloud IAP\n(SSH access)")

        project_vpc_nodes: dict[str, list] = {}  # project_id -> VPC/subnet nodes
        project_vm_nodes: dict[str, list] = {}   # project_id -> VM nodes

        for p in projects:
            pid = p["project_id"]
            scan = scans[pid]
            short = pid.replace("eco-", "").replace("-01", "").replace("-02", "")

            with Cluster(f"Project: {pid}\n[{p.get('labels', {}).get('env', 'no env label')}]"):

                # Networking — custom VPCs only
                custom_nets = [n for n in scan["networks"]
                               if isinstance(n, dict) and "error" not in n and n["name"] != "default"]
                vpc_nodes = []
                for net in custom_nets:
                    subnets = [s for s in scan["subnets"]
                               if isinstance(s, dict) and "error" not in s
                               and s.get("network") == net["name"]]
                    with Cluster(f"VPC: {net['name']}"):
                        vpc_node = VPC(net["name"])
                        vpc_nodes.append(vpc_node)
                        for sub in subnets:
                            cidr = sub.get("ip_cidr_range", "")
                            purpose = sub.get("purpose", "")
                            label = f"{sub['name']}\n{cidr}"
                            if "REGIONAL_MANAGED_PROXY" in (purpose or ""):
                                FirewallRules(label + "\n[proxy]")
                            else:
                                FirewallRules(label)

                # Default VPC warning node (if present)
                default_nets = [n for n in scan["networks"]
                                if isinstance(n, dict) and n.get("name") == "default"]
                if default_nets:
                    with Cluster("⚠ default VPC (43 regions — delete)"):
                        VPC("default\n[auto-mode]")

                # Compute
                instances = [i for i in scan["compute_instances"] if isinstance(i, dict) and "error" not in i]
                vm_nodes = []
                for inst in instances:
                    label = f"{inst['name']}\n{inst['machine_type']}\n{inst['zone']}\n{inst.get('internal_ip', '')}"
                    vm = GCE(label)
                    vm_nodes.append(vm)
                    iap >> Edge(label="IAP SSH", style="dashed", color="darkgreen") >> vm

                # GKE — store nodes so AR can draw pull edges to them
                gke_nodes = []
                for cluster in [c for c in scan["gke_clusters"] if isinstance(c, dict) and "error" not in c]:
                    gke_node = GKE(f"{cluster['name']}\nv{cluster['version']}\n{cluster['node_count']} nodes")
                    gke_nodes.append(gke_node)

                # Artifact Registry
                ar_repos = [r for r in scan.get("artifact_registry", []) if isinstance(r, dict) and "error" not in r]
                if ar_repos:
                    with Cluster("Artifact Registry"):
                        for repo in ar_repos:
                            size_b = repo.get("size_bytes", 0)
                            size_label = f"{size_b/1024/1024/1024:.1f} GB" if size_b >= 1024**3 else f"{size_b/1024/1024:.0f} MB"
                            ar_node = GCR(f"{repo['name']}\n{repo.get('format','')}\n{size_label}")
                            for gke_node in gke_nodes:
                                ar_node >> Edge(label="pulls", style="dashed", color="darkorange") >> gke_node

                # Storage
                buckets = [b for b in scan["gcs_buckets"] if isinstance(b, dict) and "error" not in b]
                if buckets:
                    with Cluster("Cloud Storage"):
                        for b in buckets:
                            GCS(b["name"].replace("eco-", "").replace("-01", ""))

                # Cloud Build (if CB logs bucket exists)
                cb_buckets = [b for b in buckets if "cb-logs" in b.get("name", "")]
                if cb_buckets:
                    Build("Cloud Build\n(CI/CD)")

                # Firewall warnings
                risky_fw = [fw for fw in scan["firewall_rules"]
                            if isinstance(fw, dict) and not fw.get("disabled")
                            and "0.0.0.0/0" in fw.get("source_ranges", [])
                            and fw.get("action") == "allow"]
                if risky_fw:
                    with Cluster("⚠ Open Firewall Rules"):
                        for fw in risky_fw:
                            ports = [p for r in fw.get("rules", []) for p in r.get("ports", ["ALL"])]
                            FirewallRules(f"{fw['name']}\n0.0.0.0/0:{','.join(ports)}")

                project_vpc_nodes[pid] = vpc_nodes
                project_vm_nodes[pid] = vm_nodes

        # Shared VPC edges between service project VMs and host project VPCs
        for service_pid, host_pid in service_to_host.items():
            svc_vms = project_vm_nodes.get(service_pid, [])
            host_vpcs = project_vpc_nodes.get(host_pid, [])
            for vm in svc_vms:
                for vpc_node in host_vpcs:
                    vm >> Edge(label="Shared VPC", style="dotted", color="blue") >> vpc_node

    out_file = f"{base}.{fmt}"
    return f"Diagram saved to: {out_file}"


# ── tool definitions ───────────────────────────────────────────────────────────

@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="list_gcp_projects",
            description="List all GCP projects accessible to the current credentials",
            inputSchema={"type": "object", "properties": {}},
        ),
        Tool(
            name="scan_gcp_project",
            description="Deep scan a single GCP project: VPCs, subnets, firewall rules, GCE instances, GCS buckets, GKE clusters, and Shared VPC relationships",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "GCP project ID to scan (uses default credentials project if omitted)",
                    }
                },
            },
        ),
        Tool(
            name="scan_gcp_environment",
            description="Full scan across ALL accessible GCP projects — returns a complete inventory of every resource",
            inputSchema={
                "type": "object",
                "properties": {
                    "include_projects": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional: restrict scan to specific project IDs",
                    }
                },
            },
        ),
        Tool(
            name="scan_shared_vpc",
            description="Discover Shared VPC (XPN) relationships for a project — identifies host projects and service projects",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "GCP project ID to check Shared VPC status for",
                    }
                },
                "required": ["project_id"],
            },
        ),
        Tool(
            name="scan_gcp_security",
            description="Security posture scan for a GCP project — checks for public IPs, overly permissive firewall rules, default VPCs, and missing controls",
            inputSchema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "GCP project ID to security-scan (uses default if omitted)",
                    }
                },
            },
        ),
        Tool(
            name="generate_architecture_report",
            description="Scan all accessible GCP projects and generate a detailed markdown architecture report saved to a file",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_path": {
                        "type": "string",
                        "description": "Full file path for the markdown output (e.g. /tmp/gcp-report.md)",
                    },
                    "include_projects": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional: restrict to specific project IDs",
                    },
                },
                "required": ["output_path"],
            },
        ),
        Tool(
            name="generate_architecture_diagram",
            description="Scan all accessible GCP projects and generate a visual architecture diagram (PNG or SVG) showing projects, VPCs, subnets, VMs, GKE clusters, GCS buckets, Shared VPC links, IAP access, and security findings",
            inputSchema={
                "type": "object",
                "properties": {
                    "output_path": {
                        "type": "string",
                        "description": "Full file path for the diagram output, without extension (e.g. /tmp/gcp-architecture)",
                    },
                    "format": {
                        "type": "string",
                        "description": "Output format: png or svg (default: png)",
                        "enum": ["png", "svg"],
                        "default": "png",
                    },
                    "include_projects": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Optional: restrict diagram to specific project IDs",
                    },
                },
                "required": ["output_path"],
            },
        ),
    ]


# ── tool dispatch ──────────────────────────────────────────────────────────────

@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    try:
        if name == "list_gcp_projects":
            return _ok({"projects": _list_projects()})

        elif name == "scan_gcp_project":
            project = arguments.get("project_id") or _default_project()
            return _ok(_full_project_scan(project))

        elif name == "scan_gcp_environment":
            all_projects = _list_projects()
            include = arguments.get("include_projects")
            if include:
                all_projects = [p for p in all_projects if p["project_id"] in include]
            results = {}
            for p in all_projects:
                results[p["project_id"]] = _full_project_scan(p["project_id"])
            return _ok({
                "scan_time": datetime.now(timezone.utc).isoformat(),
                "project_count": len(all_projects),
                "projects": results,
            })

        elif name == "scan_shared_vpc":
            project = arguments["project_id"]
            return _ok({"project_id": project, **_scan_shared_vpc(project)})

        elif name == "scan_gcp_security":
            project = arguments.get("project_id") or _default_project()
            return _ok(_security_scan(project))

        elif name == "generate_architecture_report":
            output_path = arguments["output_path"]
            all_projects = _list_projects()
            include = arguments.get("include_projects")
            if include:
                all_projects = [p for p in all_projects if p["project_id"] in include]
            result = _generate_markdown_report(all_projects, output_path)
            return _ok({"result": result, "projects_scanned": len(all_projects)})

        elif name == "generate_architecture_diagram":
            output_path = arguments["output_path"]
            fmt = arguments.get("format", "png")
            all_projects = _list_projects()
            include = arguments.get("include_projects")
            if include:
                all_projects = [p for p in all_projects if p["project_id"] in include]
            result = _generate_diagram(all_projects, output_path, fmt)
            return _ok({"result": result, "projects_scanned": len(all_projects)})

        else:
            return _err(ValueError(f"Unknown tool: {name}"))

    except Exception as e:
        return _err(e)


# ── entry point ────────────────────────────────────────────────────────────────

async def main():
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    asyncio.run(main())
