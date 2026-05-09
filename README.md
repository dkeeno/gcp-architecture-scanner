# GCP Architecture Scanner (MCP Server)

A Model Context Protocol (MCP) server that scans Google Cloud Platform projects and produces:

- **Architecture diagrams** (PNG/SVG) using Python Diagrams
- **Detailed inventory reports** (markdown)
- **Security posture scans** — public IPs, overly permissive firewall rules, default VPCs, missing controls

## Why this exists

Onboarding to a new GCP environment is painful. Documentation lies, console-clicking is slow, and there's no canonical view of what's deployed. This MCP server gives you a current diagram + report in 30 seconds.

## Capabilities

- Scan a single project, multiple projects, or all accessible projects
- Detect Shared VPC (XPN) host/service relationships
- Generate visual architecture (PNG/SVG)
- Generate full markdown inventory report
- Security findings: public exposure, weak controls, default-VPC usage

## Install

```bash
pip install -r requirements.txt
gcloud auth application-default login
brew install graphviz   # required for diagram rendering
```

## Usage

In any MCP client (Claude Code, etc.):
- "Generate an architecture diagram of all my GCP projects"
- "Run a security scan on project my-prod-project"
- "Show me which projects are using the default VPC"

## License

MIT — see [LICENSE](LICENSE).

## Support

See [SUPPORT.md](SUPPORT.md) for community + commercial support.
