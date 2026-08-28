const secretRules = [
  { name: "AWS Access Key ID", pattern: /(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/, cwe: "CWE-798", desc: "AWS Access Key ID discovered in code." },
  { name: "GitHub Personal Access Token", pattern: /(ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9]{22}_[a-zA-Z0-9]{59})/, cwe: "CWE-798", desc: "GitHub Personal Access Token exposed in source file." },
  { name: "OpenAI API Key", pattern: /sk-[a-zA-Z0-9]{48}/, cwe: "CWE-798", desc: "OpenAI Secret API Key exposed." },
  { name: "Stripe Live Key", pattern: /sk_live_[0-9a-zA-Z]{24,34}/, cwe: "CWE-798", desc: "Stripe Live Secret Key exposed." },
  { name: "Slack Token", pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}/, cwe: "CWE-798", desc: "Slack API Bot or OAuth Token exposed." },
  { name: "RSA / Elliptic Private Key", pattern: /-----BEGIN (RSA|EC|OPENSSH|DSA|PRIVATE) KEY-----/, cwe: "CWE-312", desc: "Unencrypted Private Cryptographic Key file content." },
  { name: "Google API Key", pattern: /AIzaSy[a-zA-Z0-9_-]{33}/, cwe: "CWE-798", desc: "Google Cloud / Firebase API Key exposed." },
  { name: "Database Connection URL with Password", pattern: /(postgres|mysql|mongodb|redis):\/\/[^:]+:([^@]+)@/i, cwe: "CWE-798", desc: "Hardcoded database URI containing plaintext password." }
];

const typosquatMap = {
  "reqeusts": "requests",
  "requets": "requests",
  "expresss": "express",
  "lodash-v2": "lodash",
  "cross-env-v2": "cross-env"
};

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed. Use POST." });
  }

  const { file_name = "package.json", content = "", mode = "default", ring = "dev" } = req.body || {};

  const findings = [];
  let count = 1;
  let hardBlock = false;

  const lines = content.split("\n");

  // 1. Secret Scanner
  lines.forEach((line, idx) => {
    secretRules.forEach(rule => {
      const match = rule.pattern.exec(line);
      if (match) {
        hardBlock = true;
        findings.push({
          id: `PS-SEC-${String(count++).padStart(3, '0')}`,
          title: `${rule.name} Exposed`,
          description: rule.desc,
          file: file_name,
          line: idx + 1,
          scanner: "SecretScanner",
          severity: "CRITICAL",
          cwe: rule.cwe,
          remediation: "Revoke and rotate compromised credentials immediately.",
          is_hard_block: true,
          context: redactSecret(line.trim(), match[0]),
          is_staged_for_publish: true
        });
      }
    });
  });

  // 2. Config Scanner
  if (file_name.endsWith("package.json")) {
    try {
      const pkg = JSON.parse(content);
      if (pkg.scripts) {
        Object.entries(pkg.scripts).forEach(([name, cmd]) => {
          if (["preinstall", "postinstall", "install"].includes(name)) {
            const isDanger = /(curl|wget|bash|sh|eval|nc)/i.test(cmd);
            findings.push({
              id: `PS-CFG-${String(count++).padStart(3, '0')}`,
              title: `Package Lifecycle Hook Detected: ${name}`,
              description: "Lifecycle scripts run automatically when consumers install your package. Malicious packages abuse install scripts.",
              file: file_name,
              scanner: "ConfigScanner",
              severity: isDanger ? "CRITICAL" : "MEDIUM",
              cwe: "CWE-829",
              remediation: "Avoid prepublish/postinstall hooks fetching remote scripts.",
              context: `${name}: ${cmd}`,
              is_staged_for_publish: true
            });
          }
        });
      }
      if (pkg.dependencies) {
        Object.entries(pkg.dependencies).forEach(([depName, ver]) => {
          if (typosquatMap[depName.toLowerCase()]) {
            hardBlock = true;
            findings.push({
              id: `PS-DEP-${String(count++).padStart(3, '0')}`,
              title: `Potential Typosquatting Dependency Detected: ${depName}`,
              description: `Package name ${depName} closely mimics popular package ${typosquatMap[depName.toLowerCase()]}.`,
              file: file_name,
              scanner: "DependencyScanner",
              severity: "CRITICAL",
              cwe: "CWE-829",
              remediation: `Change dependency to official package ${typosquatMap[depName.toLowerCase()]}.`,
              context: `${depName}: ${ver}`,
              is_hard_block: true,
              is_staged_for_publish: true
            });
          }
        });
      }
    } catch (e) {}
  }

  // 3. Artifact Scanner
  if (file_name.endsWith(".env") || file_name.includes(".env.")) {
    findings.push({
      id: `PS-ART-${String(count++).padStart(3, '0')}`,
      title: "Environment Configuration File Included",
      description: "Environment files contain secret tokens and passwords.",
      file: file_name,
      scanner: "ArtifactScanner",
      severity: "HIGH",
      cwe: "CWE-540",
      remediation: "Add .env files to .npmignore or .gitignore.",
      is_staged_for_publish: true
    });
  }

  // 4. SourceMap Scanner
  if (file_name.endsWith(".map")) {
    findings.push({
      id: `PS-SRC-${String(count++).padStart(3, '0')}`,
      title: "Unminified SourceMap File Staged for Publish",
      description: "Publishing .map files exposes original unminified source code.",
      file: file_name,
      scanner: "SourceMapScanner",
      severity: "HIGH",
      cwe: "CWE-540",
      remediation: "Exclude .map files from public package releases.",
      is_staged_for_publish: true
    });
  }

  // Summary calculation
  const summary = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  let passed = true;

  findings.forEach(f => {
    summary[f.severity] = (summary[f.severity] || 0) + 1;
    if (f.severity === "CRITICAL" || f.severity === "HIGH") {
      passed = false;
    }
  });

  if (hardBlock) {
    passed = false;
  }

  return res.status(200).json({
    timestamp: new Date().toISOString(),
    file_name,
    passed,
    hard_block_triggered: hardBlock,
    policy_mode: mode,
    environment_ring: ring,
    findings_count: findings.length,
    summary,
    findings
  });
}

function redactSecret(line, secret) {
  if (secret.length <= 4) return line.replace(secret, "****");
  const redacted = secret.slice(0, 2) + "*".repeat(secret.length - 4) + secret.slice(-2);
  return line.replace(secret, redacted);
}
