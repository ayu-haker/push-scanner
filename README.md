# push-scanner 🛡️ (v0.4.0 Supply-Chain & SLSA)

[![Go Version](https://img.shields.io/badge/Go-1.21%2B-00ADD8?style=flat&logo=go)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![MCP Compatible](https://img.shields.io/badge/MCP-Server%20Ready-6f42c1)](https://modelcontextprotocol.io)
[![SLSA v1.0 Attestation](https://img.shields.io/badge/SLSA-v1.0%20Provenance-green?logo=sigstore)](#-slsa-provenance-v10-attestation)
[![CycloneDX SBOM](https://img.shields.io/badge/SBOM-CycloneDX%20v1.5-blue)](#-cyclonedx-v15-sbom-generation)

> **High-Performance, Single-Binary Pre-Publish Security Gate, SLSA Attestation Builder, & MCP Server for Packages and Containers.**

`push-scanner` is an enterprise security platform designed to stop developers and AI coding agents from accidentally publishing sensitive secrets, unminified source maps, leftover test artifacts, dangerous dependency hooks, or container layer leaks to public registries (**npm**, **PyPI**, **Maven**, **Cargo**, **NuGet**).

---

## 🔗 What's New in v0.4.0 (Supply-Chain & SLSA Release)

`push-scanner v0.4.0` bridges pre-publish security verification directly into the software supply-chain ecosystem by outputting **CycloneDX SBOMs** and **Sigstore / SLSA Provenance v1.0 Attestations** on a passing security gate:

### 1. 📜 CycloneDX v1.5 SBOM Generation (`--sbom`)
Automatically extracts package components, versions, license declarations, and SHA-256 file hashes to generate a CycloneDX v1.5 JSON Software Bill of Materials upon passing gate verification.

### 2. 🔐 Sigstore / SLSA Provenance v1.0 Attestations (`--attest` / `push-scanner attest`)
Generates an in-toto SLSA Provenance v1.0 Attestation statement (`provenance.slsa.json`) certifying:
- Staged package distribution digest
- Security gate verification verdict (`PASSED`)
- Policy mode, team identifier, and environment ring
- Builder identity (`https://github.com/push-scanner/push-scanner@v0.4.0`)

### 3. 📦 npm `--provenance` Integration
Attestation payloads tie directly into npm's official `npm publish --provenance` workflow and Sigstore transparency logs.

---

## 📑 Table of Contents

- [✨ Key Features](#-key-features)
- [🚀 Quick Start & CLI Usage](#-quick-start--cli-usage)
  - [1. Generate SBOM & SLSA Attestations](#1-generate-sbom--slsa-attestations)
  - [2. Multi-Ecosystem Security Scan](#2-multi-ecosystem-security-scan)
  - [3. Enterprise Environment Rings](#3-enterprise-environment-rings)
  - [4. Docker Image Layer Scan](#4-docker-image-layer-scan)
- [🤖 Setting Up MCP Server (For AI Agents)](#-setting-up-mcp-server-for-ai-agents)
- [🔍 Security Scanners Reference](#-security-scanners-reference)
- [⚙️ Enterprise Policy (`.push-scanner.yml`)](#️-enterprise-policy-push-scanneryml)
- [🐙 GitHub Actions & CI/CD Integration](#-github-actions--cicd-integration)

---

## 🚀 Quick Start & CLI Usage

### 1. Generate SBOM & SLSA Attestations

Generate both a CycloneDX SBOM and SLSA Attestation bundle for your package:

```bash
# Run scan & generate sbom.cyclonedx.json + provenance.slsa.json on gate pass
push-scanner attest .
```

Or export individually using flags:

```bash
push-scanner scan --sbom my-sbom.json --attest my-provenance.json .
```

#### Sample SLSA Provenance Attestation Payload (`provenance.slsa.json`):
```json
{
  "_type": "https://in-toto.io/Statement/v1",
  "subject": [
    {
      "name": "my-npm-package",
      "digest": {
        "sha256": "f6aa1b910afb23606be5802c43d7b89f71ab15925ef2a3f991db827c1020ce36"
      }
    }
  ],
  "predicateType": "https://slsa.dev/provenance/v1",
  "predicate": {
    "buildDefinition": {
      "buildType": "https://push-scanner.dev/attestation/v1",
      "externalParameters": {
        "root_path": "/repos/my-npm-package",
        "policy_mode": "default",
        "environment_ring": "prod",
        "team": "platform-sec"
      }
    },
    "runDetails": {
      "builder": {
        "id": "https://github.com/push-scanner/push-scanner@v0.4.0"
      }
    }
  }
}
```

---

### 2. Multi-Ecosystem Security Scan

```bash
# Scan npm, PyPI, Maven, Cargo, or NuGet projects
push-scanner scan .
```

---

### 3. Enterprise Environment Rings

```bash
push-scanner scan --ring prod --webhook-url https://siem.internal/audit .
```

---

### 4. Docker Image Layer Scan

```bash
push-scanner docker my-app-image.tar
```

---

## 🤖 Setting Up MCP Server (For AI Agents)

Add `push-scanner` to your MCP config (`claude_desktop_config.json` / Cursor):

```json
{
  "mcpServers": {
    "push-scanner": {
      "command": "D:/god project placement/push-scanner/push-scanner.exe",
      "args": ["mcp"]
    }
  }
}
```

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.
