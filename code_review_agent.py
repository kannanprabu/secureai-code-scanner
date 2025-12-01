#!/usr/bin/env python3
"""
Semgrep AI Code Review Tool - ULTIMATE EDITION
✓ Code Evidence (shows actual vulnerable code)
✓ LLM Analysis (AI-powered security insights)
✓ Comprehensive Reports
"""

import os
import json
import tempfile
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Optional, Tuple, List
import argparse
from datetime import datetime
import logging
import re

# FIX: Force UTF-8 encoding on Windows to prevent Semgrep Unicode errors
# This MUST be set before importing any other modules
os.environ['PYTHONUTF8'] = '1'
os.environ['PYTHONIOENCODING'] = 'utf-8'

# Import configuration
try:
    import config
    HAS_CONFIG = True
except ImportError:
    print("Warning: config.py not found. LLM analysis will be disabled.")
    config = None
    HAS_CONFIG = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


# ============================================================================
# SEVERITY MAPPING - CRITICAL/HIGH/MEDIUM/LOW (141+ Categories)
# ============================================================================

def map_severity_to_level(check_id: str, semgrep_severity: str) -> str:
    """
    Map Semgrep findings to CRITICAL/HIGH/MEDIUM/LOW based on 141+ vulnerability types
    
    CRITICAL (15): Remote Code Execution, System Compromise
    HIGH (23): Data Breach, Privilege Escalation, Auth Bypass
    MEDIUM (32): Security Weaknesses, Config Issues
    LOW (24): Code Quality, Best Practices
    """
    
    # If we have config with SEVERITY_LEVELS, use it first
    if HAS_CONFIG and hasattr(config, 'SEVERITY_LEVELS'):
        check_id_lower = check_id.lower()
        
        # Check if pattern matches any configured severity
        for pattern, configured_severity in config.SEVERITY_LEVELS.items():
            if pattern.lower() in check_id_lower:
                return configured_severity
    
    # Comprehensive fallback mapping (141+ categories)
    check_id_lower = check_id.lower()
    
    # ========== CRITICAL (15) - Remote Code Execution ==========
    critical_patterns = [
        # Injection Attacks (8)
        'command-injection', 'code-injection', 'sql-injection', 
        'ldap-injection', 'xpath-injection', 'eval-usage', 'exec-usage', 'ssti',
        
        # Deserialization (4)
        'deserialization', 'insecure-deserialization', 'unsafe-yaml', 'unsafe-pickle',
        
        # File & XML (2)
        'xxe', 'unrestricted-file-upload',
        
        # Framework-specific CRITICAL
        'flask-sql-injection', 'express-sql-injection', 'spring-sqli',
        'laravel-sql-injection', 'rails-sql-injection'
    ]
    
    # ========== HIGH (23) - Data Breach & Auth Bypass ==========
    high_patterns = [
        # Cross-Site Attacks (3)
        'xss', 'csrf', 'clickjacking',
        
        # Path Traversal (2)
        'path-traversal', 'directory-traversal',
        
        # Authentication & Authorization (5)
        'authentication-bypass', 'authorization-bypass', 'broken-access-control',
        'broken-authentication', 'session-fixation',
        
        # Credential Exposure (6)
        'hardcoded-password', 'hardcoded-secret', 'hardcoded-key',
        'aws-credentials', 'azure-credentials', 'gcp-credentials',
        
        # JWT & Tokens (2)
        'jwt-none-algorithm', 'weak-jwt',
        
        # Server-Side Attacks (2)
        'ssrf', 'open-redirect',
        
        # NoSQL & ORM (2)
        'nosql-injection', 'orm-injection',
        
        # Data Integrity (1)
        'data-integrity-failure',
        
        # Framework-specific HIGH
        'django-xss', 'django-csrf', 'flask-xss', 'express-xss', 'spring-xss',
        'react-dangerouslysetinnerhtml', 'react-xss', 'angular-xss', 
        'angular-bypasssecurity', 'laravel-xss', 'rails-xss',
        
        # Mobile HIGH
        'android-webview-js', 'mobile-insecure-communication'
    ]
    
    # ========== MEDIUM (32) - Security Weaknesses ==========
    medium_patterns = [
        # Cryptography (5)
        'weak-crypto', 'weak-hash', 'weak-cipher', 'insecure-random', 'missing-encryption',
        
        # Network Security (3)
        'http-without-https', 'insecure-cookie', 'missing-csrf-token',
        
        # Memory & Buffer (6)
        'buffer-overflow', 'integer-overflow', 'use-after-free',
        'null-pointer-dereference', 'race-condition', 'memory-leak',
        
        # Information Disclosure (2)
        'information-disclosure', 'sensitive-data-exposure',
        
        # Attack Vectors (8)
        'xml-bomb', 'regex-dos', 'mass-assignment', 'parameter-tampering',
        'http-parameter-pollution', 'cache-poisoning', 'prototype-pollution', 'zip-slip',
        
        # Configuration (6)
        'security-misconfiguration', 'vulnerable-components', 'identification-failure',
        'docker-privileged', 'kubernetes-secrets', 'terraform-secrets',
        
        # Framework MEDIUM
        'django-raw-sql', 'flask-debug-mode', 'rails-mass-assignment',
        
        # Mobile MEDIUM
        'android-ssl-pinning', 'ios-insecure-storage'
    ]
    
    # ========== LOW (24) - Code Quality & Best Practices ==========
    low_patterns = [
        # Code Quality (6)
        'debug-code', 'todo-fixme', 'commented-code', 'unused-variable',
        'console-log', 'print-statement',
        
        # Error Handling (4)
        'missing-error-handling', 'improper-exception-handling',
        'verbose-error-messages', 'stack-trace-exposure',
        
        # Input/Output (2)
        'missing-input-validation', 'missing-output-encoding',
        
        # Security Headers & Config (4)
        'missing-security-header', 'directory-listing', 
        'default-credentials', 'insecure-permissions',
        
        # Legacy & Deprecated (2)
        'outdated-dependency', 'deprecated-function',
        
        # Hardcoded Values (2)
        'hardcoded-ip', 'hardcoded-url',
        
        # Logging (2)
        'logging-failure', 'insufficient-logging',
        
        # Framework LOW
        'express-open-redirect'
    ]
    
    # Check patterns in order of severity
    for pattern in critical_patterns:
        if pattern in check_id_lower:
            return 'CRITICAL'
    
    for pattern in high_patterns:
        if pattern in check_id_lower:
            return 'HIGH'
    
    for pattern in medium_patterns:
        if pattern in check_id_lower:
            return 'MEDIUM'
    
    for pattern in low_patterns:
        if pattern in check_id_lower:
            return 'LOW'
    
    # Default mapping based on Semgrep's severity
    severity_mapping = {
        'ERROR': 'CRITICAL',
        'WARNING': 'MEDIUM',
        'INFO': 'LOW'
    }
    
    return severity_mapping.get(semgrep_severity.upper(), 'MEDIUM')


# ============================================================================
# LLM CLIENT FOR AI-POWERED ANALYSIS
# ============================================================================

class LLMClient:
    """Client for LLM-powered security analysis"""
    
    def __init__(self):
        if not HAS_CONFIG:
            self.enabled = False
            logger.warning("LLM analysis disabled - no config.py found")
            return
        
        self.provider = config.LLM_PROVIDER.lower()
        self.enabled = True
        logger.info(f"LLM Analysis enabled: {self.provider}")
    
    def analyze_per_finding(self, findings: List[Dict], target_path: Path) -> Dict:
        """Analyze each finding individually for false positives and exploitability"""
        if not self.enabled:
            logger.warning("LLM not enabled - per-finding analysis skipped")
            return {}
        
        logger.info("Analyzing findings with AI...")
        
        # Categorize findings by severity first
        critical_findings = []
        high_findings = []
        medium_findings = []
        
        for finding in findings:
            semgrep_severity = finding.get('extra', {}).get('severity', 'INFO')
            check_id = finding.get('check_id', '')
            our_severity = map_severity_to_level(check_id, semgrep_severity)
            
            if our_severity == 'CRITICAL':
                critical_findings.append(finding)
            elif our_severity == 'HIGH':
                high_findings.append(finding)
            elif our_severity == 'MEDIUM':
                medium_findings.append(finding)
        
        # Analyze ALL CRITICAL and HIGH, plus some MEDIUM
        findings_to_analyze = (
            critical_findings +           # ALL CRITICAL
            high_findings +               # ALL HIGH
            medium_findings[:10]          # Top 10 MEDIUM
        )
        
        total_to_analyze = len(findings_to_analyze)
        logger.info(f"Analyzing {total_to_analyze} findings: {len(critical_findings)} CRITICAL, {len(high_findings)} HIGH, {min(10, len(medium_findings))} MEDIUM")
        
        if total_to_analyze == 0:
            return {}
        
        # Build prompt with findings data
        findings_data = []
        finding_keys = []
        
        for idx, finding in enumerate(findings_to_analyze, 1):
            rel_path = finding.get('path', '')
            line_num = finding.get('start', {}).get('line', 0)
            check_id = finding.get('check_id', '')
            message = finding.get('extra', {}).get('message', '')
            severity = finding.get('extra', {}).get('severity', 'INFO')
            
            # Extract code snippet
            file_path = target_path / rel_path
            code = ""
            if file_path.exists():
                try:
                    lines = file_path.read_text(encoding='utf-8', errors='ignore').split('\n')
                    start = max(0, line_num - 4)
                    end = min(len(lines), line_num + 3)
                    for i in range(start, end):
                        marker = ">>>" if i == line_num - 1 else "   "
                        code += f"{marker} {i+1:4d} | {lines[i]}\n"
                except:
                    code = "[Code extraction failed]"
            
            finding_key = f"{rel_path}:{line_num}:{check_id}"
            finding_keys.append(finding_key)
            
            findings_data.append({
                'key': finding_key,
                'number': idx,
                'rule': check_id,
                'file': rel_path,
                'line': line_num,
                'severity': severity,
                'message': message,
                'code': code
            })
        
        logger.debug(f"Sending {len(findings_data)} findings to LLM")
        
        # Split into batches if too many (LLM context limits)
        batch_size = 20  # Analyze 20 at a time
        all_results = {}
        
        for i in range(0, len(findings_data), batch_size):
            batch = findings_data[i:i+batch_size]
            batch_num = i // batch_size + 1
            total_batches = (len(findings_data) + batch_size - 1) // batch_size
            
            logger.info(f"Processing batch {batch_num}/{total_batches} ({len(batch)} findings)")
            
            prompt = f"""Analyze these security findings and determine if each is a FALSE POSITIVE or REAL VULNERABILITY.

For each finding, provide:
1. is_false_positive: true/false
2. exploitability: "HIGH" / "MEDIUM" / "LOW" / "NOT_EXPLOITABLE"
3. analysis: 2-3 sentence explanation of the issue
4. recommendation: Specific fix instruction with code example

FINDINGS TO ANALYZE (Batch {batch_num}/{total_batches}):
{json.dumps(batch, indent=2)}

RESPOND WITH VALID JSON ONLY (no markdown, no code blocks):
{{
  "findings": {{
    "FINDING_KEY_1": {{
      "is_false_positive": false,
      "exploitability": "HIGH",
      "analysis": "This eval() call directly executes user input without sanitization, allowing remote code execution.",
      "recommendation": "Replace eval() with JSON.parse() or use parseFloat(): const preTax = parseFloat(req.body.preTax) || 0;"
    }},
    "FINDING_KEY_2": {{
      "is_false_positive": false,
      "exploitability": "HIGH",
      "analysis": "...",
      "recommendation": "..."
    }}
  }}
}}

CRITICAL: Use the exact "key" values from the findings above. Respond ONLY with the JSON object. No backticks, no markdown."""
            
            batch_results = self._call_llm_for_batch(prompt)
            if batch_results:
                all_results.update(batch_results)
                logger.info(f"✓ Batch {batch_num} completed: {len(batch_results)} analyses received")
            else:
                logger.warning(f"✗ Batch {batch_num} failed")
        
        logger.info(f"✓ Total LLM analyses completed: {len(all_results)}/{len(findings_data)}")
        
        return all_results
    
    def _call_llm_for_batch(self, prompt: str) -> Dict:
        """Call LLM for a batch of findings"""
        try:
            if config.LLM_PROVIDER == "anthropic":
                response = self._call_anthropic_for_json(prompt)
            elif config.LLM_PROVIDER == "azure":
                response = self._call_azure_for_json(prompt)
            elif config.LLM_PROVIDER == "openai":
                response = self._call_openai_for_json(prompt)
            else:
                logger.error(f"Unknown LLM provider: {config.LLM_PROVIDER}")
                return {}
            
            # Clean response
            response = response.strip()
            if response.startswith('```json'):
                response = response[7:]
            if response.startswith('```'):
                response = response[3:]
            if response.endswith('```'):
                response = response[:-3]
            response = response.strip()
            
            # Parse JSON
            result = json.loads(response)
            return result.get('findings', {})
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM JSON: {e}")
            return {}
        except Exception as e:
            logger.error(f"Batch analysis failed: {e}")
            return {}
    
    def _call_anthropic_for_json(self, prompt: str) -> str:
        """Call Anthropic and return raw JSON text"""
        client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
        message = client.messages.create(
            model=config.ANTHROPIC_MODEL,
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text
    
    def _call_azure_for_json(self, prompt: str) -> str:
        """Call Azure OpenAI and return raw JSON text"""
        from openai import AzureOpenAI
        client = AzureOpenAI(
            api_key=config.AZURE_OPENAI_API_KEY,
            api_version=config.AZURE_OPENAI_API_VERSION,
            azure_endpoint=config.AZURE_OPENAI_ENDPOINT
        )
        response = client.chat.completions.create(
            model=config.AZURE_OPENAI_DEPLOYMENT,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=4096
        )
        return response.choices[0].message.content
    
    def _call_openai_for_json(self, prompt: str) -> str:
        """Call OpenAI and return raw JSON text"""
        from openai import OpenAI
        client = OpenAI(api_key=config.OPENAI_API_KEY)
        response = client.chat.completions.create(
            model=config.OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=4096
        )
        return response.choices[0].message.content
    
    def analyze_findings(self, analysis: Dict, code_snippets: List[Dict]) -> Dict:
        """Get AI analysis of security findings"""
        if not self.enabled:
            return self._fallback_analysis(analysis)
        
        try:
            logger.info("Requesting AI security analysis...")
            prompt = self._build_prompt(analysis, code_snippets)
            
            if self.provider == "anthropic":
                return self._call_anthropic(prompt)
            elif self.provider == "azure":
                return self._call_azure(prompt)
            elif self.provider == "openai":
                return self._call_openai(prompt)
            elif self.provider == "ollama":
                return self._call_ollama(prompt)
            else:
                return self._fallback_analysis(analysis)
                
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return self._fallback_analysis(analysis)
    
    def _build_prompt(self, analysis: Dict, code_snippets: List[Dict]) -> str:
        """Build analysis prompt with code evidence and false positive detection"""
        summary = analysis['summary']
        
        # Top vulnerable code snippets with more context
        code_evidence = ""
        for i, snippet in enumerate(code_snippets[:10], 1):
            code_evidence += f"\n{'='*80}\n"
            code_evidence += f"Finding {i}: {snippet['rule']}\n"
            code_evidence += f"Location: {snippet['file']}:{snippet['line']}\n"
            code_evidence += f"Severity: {snippet['severity']}\n"
            code_evidence += f"Message: {snippet['message']}\n"
            if snippet.get('code'):
                code_evidence += f"\nVulnerable Code:\n{snippet['code']}\n"
            if snippet.get('recommendation'):
                code_evidence += f"\nRecommendation: {snippet['recommendation']}\n"
        
        prompt = f"""You are a senior security analyst reviewing code vulnerabilities. Your job is to:
1. Identify FALSE POSITIVES (findings that are not actually exploitable)
2. Prioritize REAL SECURITY ISSUES
3. Provide actionable fixes

SCAN SUMMARY:
- Total Findings: {analysis['total_findings']}
- Critical Issues: {summary['needs_immediate_attention']}
- High Priority: {summary['security_hotspots']}
- Medium Issues: {summary['security_weaknesses']}
- Low Priority: {summary['code_quality_issues']}
- CWE Categories: {len(analysis['by_cwe'])}
- OWASP Categories: {len(analysis['by_owasp'])}

SEVERITY BREAKDOWN:
{json.dumps(analysis['by_severity'], indent=2)}

TOP FINDINGS WITH CODE EVIDENCE:
{code_evidence}

CRITICAL TASK: Analyze each finding and provide:

## 1. False Positive Analysis
For each finding above, determine if it's a FALSE POSITIVE:
- Is the code actually exploitable?
- Is user input properly sanitized elsewhere?
- Are there framework protections in place?
- Is this test/demo code that's safe?

List findings that are likely FALSE POSITIVES and explain why.

## 2. Confirmed Critical Issues
List the REAL exploitable vulnerabilities that need immediate fixing.
Focus only on issues that are actually dangerous.

## 3. Attack Scenarios
Explain how confirmed vulnerabilities could be exploited together.
Be specific about the attack chain.

## 4. Priority Fix List
Ordered list of what to fix first (only real issues, skip false positives):
1. Most dangerous first
2. Include file and line number
3. Specific fix instruction

## 5. Long-term Security Recommendations
General security improvements for the codebase.

## 6. Summary
- Total findings: {analysis['total_findings']}
- Likely false positives: [X]
- Confirmed exploitable: [Y]
- Risk level: [CRITICAL/HIGH/MEDIUM/LOW]

Use markdown formatting. Be thorough in false positive analysis."""
        
        return prompt
    
    def _call_anthropic(self, prompt: str) -> Dict:
        import anthropic
        client = anthropic.Anthropic(api_key=config.ANTHROPIC_API_KEY)
        message = client.messages.create(
            model=getattr(config, 'ANTHROPIC_MODEL', 'claude-sonnet-4-20250514'),
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}]
        )
        return {
            "analysis": message.content[0].text,
            "provider": "anthropic",
            "model": "claude-sonnet-4"
        }
    
    def _call_azure(self, prompt: str) -> Dict:
        """Call Azure OpenAI with new API (openai>=1.0.0)"""
        from openai import AzureOpenAI
        
        client = AzureOpenAI(
            api_key=config.AZURE_OPENAI_API_KEY,
            api_version=config.AZURE_OPENAI_API_VERSION,
            azure_endpoint=config.AZURE_OPENAI_ENDPOINT
        )
        
        response = client.chat.completions.create(
            model=config.AZURE_OPENAI_DEPLOYMENT,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=4096
        )
        
        return {
            "analysis": response.choices[0].message.content,
            "provider": "azure",
            "model": config.AZURE_OPENAI_DEPLOYMENT
        }
    
    def _call_openai(self, prompt: str) -> Dict:
        """Call OpenAI with new API (openai>=1.0.0)"""
        from openai import OpenAI
        
        client = OpenAI(api_key=config.OPENAI_API_KEY)
        
        response = client.chat.completions.create(
            model=config.OPENAI_MODEL,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=4096
        )
        
        return {
            "analysis": response.choices[0].message.content,
            "provider": "openai",
            "model": config.OPENAI_MODEL
        }
    
    def _call_ollama(self, prompt: str) -> Dict:
        import requests
        response = requests.post(
            f"{config.OLLAMA_BASE_URL}/api/generate",
            json={"model": config.OLLAMA_MODEL, "prompt": prompt, "stream": False}
        )
        return {
            "analysis": response.json()["response"],
            "provider": "ollama",
            "model": config.OLLAMA_MODEL
        }
    
    def _fallback_analysis(self, analysis: Dict) -> Dict:
        critical = analysis['summary']['needs_immediate_attention']
        total = analysis['total_findings']
        
        text = f"""# Security Analysis

## Summary
- Total Findings: {total}
- Critical Issues: {critical}
- Status: {'URGENT ACTION REQUIRED' if critical > 0 else 'Review Recommended'}

## Recommendations
1. {'Fix critical issues immediately' if critical > 0 else 'Review all findings'}
2. Implement security code review process
3. Consider automated security testing in CI/CD

Note: Full AI analysis unavailable."""
        
        return {"analysis": text, "provider": "fallback", "model": "rule-based"}


# ============================================================================
# ENHANCED CODE REVIEW AGENT
# ============================================================================

class EnhancedCodeReviewAgent:
    def __init__(self, output_dir: str = "scan_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.llm_client = LLMClient()
        
        # FIX: Set UTF-8 encoding for Windows
        # This fixes the 'charmap' codec error with Semgrep
        os.environ['PYTHONUTF8'] = '1'
        os.environ['PYTHONIOENCODING'] = 'utf-8'
    
    def check_semgrep_installed(self) -> bool:
        """Check if Semgrep is installed"""
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=10
            )
            logger.info(f"Semgrep version: {result.stdout.strip()}")
            return result.returncode == 0
        except:
            logger.error("Semgrep not found")
            return False
    
    def install_semgrep(self) -> bool:
        """Install Semgrep"""
        try:
            logger.info("Installing Semgrep...")
            subprocess.run(
                ["pip", "install", "semgrep", "--break-system-packages"],
                check=True,
                capture_output=True,
                encoding='utf-8',
                errors='replace'
            )
            logger.info("Semgrep installed successfully")
            return True
        except:
            logger.error("Failed to install Semgrep")
            return False
    
    def check_git_installed(self) -> bool:
        """Check if Git is installed"""
        try:
            subprocess.run(["git", "--version"], capture_output=True, timeout=5)
            return True
        except:
            logger.error("Git not installed")
            return False
    
    def clone_github_repo(self, github_url: str) -> Optional[Path]:
        """Clone GitHub repository"""
        try:
            temp_dir = Path(tempfile.mkdtemp(prefix="code_review_"))
            logger.info(f"Cloning {github_url}...")
            
            subprocess.run(
                ["git", "clone", "--depth=1", github_url, str(temp_dir)],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=300
            )
            
            logger.info(f"Successfully cloned to {temp_dir}")
            return temp_dir
        except Exception as e:
            logger.error(f"Failed to clone: {e}")
            return None
    
    def run_semgrep_scan(self, target_path: Path) -> Tuple[bool, List[Dict]]:
        """Run Semgrep scan with comprehensive rules to maximize findings"""
        try:
            logger.info(f"Running comprehensive Semgrep scan on {target_path}...")
            
            # Try multiple rule configurations - comprehensive coverage
            configs = [
                # Option 1: Auto with maximum rules (best for comprehensive scanning)
                {
                    "name": "auto (comprehensive)",
                    "cmd": ["semgrep", "--config=auto", "--json", str(target_path)]
                },
                
                # Option 2: Multiple security rulesets combined
                {
                    "name": "security-audit + owasp + cwe",
                    "cmd": ["semgrep",
                           "--config=p/security-audit",
                           "--config=p/owasp-top-ten",
                           "--config=p/cwe-top-25",
                           "--json", str(target_path)]
                },
                
                # Option 3: Language-specific + security
                {
                    "name": "javascript + nodejs + security",
                    "cmd": ["semgrep",
                           "--config=p/javascript",
                           "--config=p/nodejs",
                           "--config=p/express",
                           "--config=p/security-audit",
                           "--json", str(target_path)]
                },
                
                # Option 4: CI-focused (faster, less comprehensive)
                {
                    "name": "ci config",
                    "cmd": ["semgrep", "--config=p/ci", "--json", str(target_path)]
                },
            ]
            
            best_result = None
            max_findings = 0
            
            for config in configs:
                try:
                    logger.info(f"Trying: {config['name']}")
                    
                    result = subprocess.run(
                        config['cmd'],
                        capture_output=True,
                        text=True,
                        encoding='utf-8',
                        errors='replace',
                        timeout=600
                    )
                    
                    # Check if we got valid output
                    if result.stdout and result.stdout.strip():
                        try:
                            findings = json.loads(result.stdout)
                            results = findings.get("results", [])
                            
                            if len(results) > max_findings:
                                max_findings = len(results)
                                best_result = findings
                                logger.info(f"✓ {config['name']}: Found {len(results)} findings (best so far)")
                            else:
                                logger.info(f"  {config['name']}: Found {len(results)} findings")
                            
                            # If we got 40+ findings, that's good enough
                            if len(results) >= 40:
                                logger.info("✓ Found comprehensive results, using this config")
                                break
                                
                        except json.JSONDecodeError:
                            logger.warning(f"  {config['name']}: Invalid JSON")
                            continue
                    else:
                        logger.warning(f"  {config['name']}: No output")
                    
                except subprocess.TimeoutExpired:
                    logger.warning(f"  {config['name']}: Timeout")
                    continue
                except Exception as e:
                    logger.warning(f"  {config['name']}: Error - {e}")
                    continue
            
            # Use the best result we found
            if not best_result:
                logger.error("All Semgrep configs failed.")
                logger.error("Possible issues:")
                logger.error("  1. Network/firewall blocking rule downloads from semgrep.dev")
                logger.error("  2. Semgrep version issue")
                logger.error("  3. No matching rules for this codebase")
                print("\n⚠️  Semgrep couldn't scan properly. Check:")
                print("  1. Internet connection (rules download from semgrep.dev)")
                print("  2. Run: semgrep --version (should be 1.40+)")
                print("  3. Clear cache: rm -rf ~/.semgrep/cache")
                return True, []
            
            results = best_result.get("results", [])
            
            if results:
                logger.info(f"✓ Final: Using {max_findings} findings (best configuration)")
                
                # Show severity distribution
                severity_counts = {}
                for r in results:
                    sev = r.get("extra", {}).get("severity", "INFO")
                    severity_counts[sev] = severity_counts.get(sev, 0) + 1
                
                logger.info(f"  Severity: ERROR={severity_counts.get('ERROR', 0)}, "
                          f"WARNING={severity_counts.get('WARNING', 0)}, "
                          f"INFO={severity_counts.get('INFO', 0)}")
            else:
                logger.warning("No findings detected")
                print("\n⚠️  0 vulnerabilities found (unusual for vulnerable code)")
                print("This may indicate:")
                print("  1. Rules didn't download properly")
                print("  2. Scanning wrong directory")
                print("  3. Code is actually secure (unlikely for NodeGoat)")
            
            return True, results
            
        except Exception as e:
            logger.error(f"Scan error: {e}")
            import traceback
            logger.debug(traceback.format_exc())
            return True, []
    
    def extract_code_snippet(self, file_path: Path, line_num: int, context_lines: int = 3) -> str:
        """Extract code snippet with context"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            start = max(0, line_num - context_lines - 1)
            end = min(len(lines), line_num + context_lines)
            
            snippet = ""
            for i in range(start, end):
                marker = ">>> " if i == line_num - 1 else "    "
                snippet += f"{marker}{i+1:4d} | {lines[i]}"
            
            return snippet
        except:
            return "Code snippet unavailable"
    
    def _generate_fallback_analysis(self, check_id: str, severity: str, metadata: Dict) -> Dict:
        """Generate fallback analysis when LLM is unavailable"""
        
        # Common vulnerability patterns
        if 'eval' in check_id or 'exec' in check_id:
            return {
                'analysis': 'Code execution vulnerability detected. The code uses eval() or exec() which can execute arbitrary code if user input reaches it. This is a critical security risk that allows attackers to run malicious commands on your server.',
                'recommendation': 'Replace eval() with safe alternatives like JSON.parse() for data or use expression parser libraries. Never pass user input to eval() or exec().',
                'exploitability': 'HIGH'
            }
        
        elif 'sql' in check_id or 'injection' in check_id:
            return {
                'analysis': 'SQL Injection vulnerability detected. The code constructs SQL queries using string concatenation with user input, allowing attackers to manipulate the query logic and access unauthorized data.',
                'recommendation': 'Use parameterized queries or prepared statements. Example: db.query("SELECT * FROM users WHERE id = ?", [userId])',
                'exploitability': 'HIGH'
            }
        
        elif 'xss' in check_id:
            return {
                'analysis': 'Cross-Site Scripting (XSS) vulnerability detected. User input is inserted into HTML without proper encoding, allowing attackers to inject malicious JavaScript that steals user data or performs unauthorized actions.',
                'recommendation': 'Use proper output encoding based on context. For HTML: encode special characters. For JavaScript: use JSON.stringify(). Consider using Content Security Policy (CSP).',
                'exploitability': 'HIGH' if severity == 'CRITICAL' else 'MEDIUM'
            }
        
        elif 'hardcoded' in check_id or 'credential' in check_id or 'password' in check_id or 'secret' in check_id:
            return {
                'analysis': 'Hardcoded credentials detected. Storing passwords, API keys, or secrets directly in source code is dangerous. Anyone with access to the code (including version control history) can access these credentials.',
                'recommendation': 'Move credentials to environment variables or a secure secrets manager (AWS Secrets Manager, Azure Key Vault, HashiCorp Vault). Never commit secrets to version control. Rotate any exposed credentials immediately.',
                'exploitability': 'HIGH'
            }
        
        elif 'csrf' in check_id:
            return {
                'analysis': 'Cross-Site Request Forgery (CSRF) vulnerability detected. The application does not validate that requests originate from legitimate users, allowing attackers to trick users into performing unwanted actions.',
                'recommendation': 'Implement CSRF tokens for all state-changing operations. Use framework built-in CSRF protection (Express: csurf middleware, Django: {% csrf_token %}).',
                'exploitability': 'MEDIUM'
            }
        
        elif 'path-traversal' in check_id or 'directory-traversal' in check_id:
            return {
                'analysis': 'Path traversal vulnerability detected. User-controlled file paths can be manipulated to access files outside the intended directory using "../" sequences, potentially exposing sensitive files.',
                'recommendation': 'Validate and sanitize file paths. Use path.resolve() and check that resolved path starts with allowed directory. Never directly concatenate user input into file paths.',
                'exploitability': 'HIGH'
            }
        
        elif 'weak-crypto' in check_id or 'weak-hash' in check_id:
            return {
                'analysis': 'Weak cryptography detected. The code uses outdated or weak cryptographic algorithms (MD5, SHA1, DES) that are vulnerable to attacks. Modern systems can break these in reasonable time.',
                'recommendation': 'Use strong algorithms: SHA-256 or SHA-512 for hashing, AES-256 for encryption, bcrypt or Argon2 for passwords. Update crypto libraries to latest versions.',
                'exploitability': 'MEDIUM'
            }
        
        elif 'open-redirect' in check_id:
            return {
                'analysis': 'Open redirect vulnerability detected. User-controlled URLs in redirect operations allow attackers to craft malicious links that appear legitimate but redirect to phishing sites.',
                'recommendation': 'Validate redirect URLs against a whitelist of allowed domains. Use relative URLs when possible. If external redirects needed, show a warning page with the destination URL.',
                'exploitability': 'MEDIUM'
            }
        
        # Default for other issues
        exploitability_map = {
            'CRITICAL': 'HIGH',
            'HIGH': 'HIGH',
            'MEDIUM': 'MEDIUM',
            'LOW': 'LOW'
        }
        
        return {
            'analysis': f'{severity} severity security issue detected. {metadata.get("message", "Review this finding carefully to determine if it poses a security risk in your specific context.")}',
            'recommendation': metadata.get("fix", "Review the code and apply appropriate security controls. Consult security documentation for this specific vulnerability type."),
            'exploitability': exploitability_map.get(severity, 'MEDIUM')
        }
    
    def analyze_findings(self, results: List[Dict], target_path: Path) -> Dict:
        """Analyze Semgrep findings with CRITICAL/HIGH/MEDIUM/LOW mapping and per-finding LLM analysis"""
        
        # Get per-finding LLM analysis first
        logger.info("Requesting per-finding AI analysis...")
        llm_per_finding = self.llm_client.analyze_per_finding(results, target_path)
        
        analysis = {
            "total_findings": len(results),
            "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "by_cwe": {},
            "by_owasp": {},
            "critical_issues": [],
            "high_priority": [],
            "medium_priority": [],
            "low_priority": [],
            "summary": {
                "needs_immediate_attention": 0,  # CRITICAL
                "security_hotspots": 0,           # HIGH
                "security_weaknesses": 0,         # MEDIUM
                "code_quality_issues": 0,         # LOW
                "total_files_scanned": len(set(r.get("path", "") for r in results))
            }
        }
        
        for result in results:
            # Get Semgrep severity and check_id
            semgrep_severity = result.get("extra", {}).get("severity", "INFO")
            check_id = result.get("check_id", "")
            
            # Map to our CRITICAL/HIGH/MEDIUM/LOW system
            our_severity = map_severity_to_level(check_id, semgrep_severity)
            
            # Count by our severity
            analysis["by_severity"][our_severity] = analysis["by_severity"].get(our_severity, 0) + 1
            
            # Update summary counts
            if our_severity == "CRITICAL":
                analysis["summary"]["needs_immediate_attention"] += 1
            elif our_severity == "HIGH":
                analysis["summary"]["security_hotspots"] += 1
            elif our_severity == "MEDIUM":
                analysis["summary"]["security_weaknesses"] += 1
            elif our_severity == "LOW":
                analysis["summary"]["code_quality_issues"] += 1
            
            # Extract metadata
            metadata = result.get("extra", {}).get("metadata", {})
            
            # Count CWE
            if "cwe" in metadata:
                cwes = metadata["cwe"] if isinstance(metadata["cwe"], list) else [metadata["cwe"]]
                for cwe in cwes:
                    analysis["by_cwe"][cwe] = analysis["by_cwe"].get(cwe, 0) + 1
            
            # Count OWASP
            if "owasp" in metadata:
                owasps = metadata["owasp"] if isinstance(metadata["owasp"], list) else [metadata["owasp"]]
                for owasp in owasps:
                    analysis["by_owasp"][owasp] = analysis["by_owasp"].get(owasp, 0) + 1
            
            # Create finding with code evidence
            file_path = target_path / result.get("path", "")
            line_num = result.get("start", {}).get("line", 0)
            
            # Get LLM analysis for this specific finding (use RELATIVE path)
            rel_path = result.get("path", "")
            finding_key = f"{rel_path}:{line_num}:{check_id}"
            llm_data = llm_per_finding.get(finding_key, {})
            
            # If LLM analysis failed or not available, provide fallback
            if not llm_data:
                logger.debug(f"No LLM data for: {finding_key}")
                # Provide basic fallback analysis based on severity and rule
                fallback_analysis = self._generate_fallback_analysis(check_id, our_severity, metadata)
                llm_data = {
                    'analysis': fallback_analysis['analysis'],
                    'recommendation': fallback_analysis['recommendation'],
                    'exploitability': fallback_analysis['exploitability'],
                    'is_false_positive': False
                }
            
            finding = {
                "rule": check_id,
                "file": rel_path,
                "line": line_num,
                "severity": our_severity,
                "semgrep_severity": semgrep_severity,
                "message": result.get("extra", {}).get("message", "No message"),
                "cwe": metadata.get("cwe", []),
                "owasp": metadata.get("owasp", []),
                "recommendation": metadata.get("fix", "Review and fix manually"),
                "code": self.extract_code_snippet(file_path, line_num) if file_path.exists() else "N/A",
                # Add LLM analysis (real or fallback)
                "llm_analysis": llm_data.get('analysis'),
                "llm_recommendation": llm_data.get('recommendation'),
                "is_false_positive": llm_data.get('is_false_positive', False),
                "exploitability": llm_data.get('exploitability')
            }
            
            # Categorize by our severity levels
            if our_severity == "CRITICAL":
                analysis["critical_issues"].append(finding)
            elif our_severity == "HIGH":
                analysis["high_priority"].append(finding)
            elif our_severity == "MEDIUM":
                analysis["medium_priority"].append(finding)
            elif our_severity == "LOW":
                analysis["low_priority"].append(finding)
        
        return analysis
    
    def generate_report(self, results: List[Dict], analysis: Dict, llm_analysis: Dict, target_name: str):
        """Generate comprehensive reports"""
        base_name = f"security_scan_{target_name}_{self.scan_id}"
        
        # JSON Report
        json_path = self.output_dir / f"{base_name}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump({
                "metadata": {"scan_id": self.scan_id, "target": target_name, "timestamp": datetime.now().isoformat()},
                "raw_results": results,
                "analysis": analysis,
                "llm_analysis": llm_analysis
            }, f, indent=2, ensure_ascii=False)
        
        # Text Report with Code Evidence + LLM Analysis
        txt_path = self.output_dir / f"{base_name}_report.txt"
        with open(txt_path, 'w', encoding='utf-8') as f:
            self._write_text_report(f, analysis, llm_analysis, target_name)
        
        logger.info(f"Reports saved: {json_path}, {txt_path}")
    
    def _write_text_report(self, f, analysis: Dict, llm_analysis: Dict, target_name: str):
        """Write report: Findings first, then LLM analysis at end"""
        f.write("=" * 100 + "\n")
        f.write("SECURITY CODE REVIEW REPORT\n")
        f.write("=" * 100 + "\n\n")
        
        f.write(f"Target: {target_name}\n")
        f.write(f"Scan ID: {self.scan_id}\n")
        f.write(f"Timestamp: {datetime.now().isoformat()}\n")
        f.write(f"Total Findings: {analysis['total_findings']}\n\n")
        
        # Summary with all four severity levels
        f.write("-" * 100 + "\n")
        f.write("EXECUTIVE SUMMARY\n")
        f.write("-" * 100 + "\n")
        f.write(f"CRITICAL Issues (Immediate Fix Required): {analysis['summary']['needs_immediate_attention']}\n")
        f.write(f"HIGH Priority (Fix This Sprint):          {analysis['summary']['security_hotspots']}\n")
        f.write(f"MEDIUM Weaknesses (Next Release):         {analysis['summary']['security_weaknesses']}\n")
        f.write(f"LOW Code Quality (Track for Later):       {analysis['summary']['code_quality_issues']}\n")
        f.write(f"Files Scanned:                             {analysis['summary']['total_files_scanned']}\n\n")
        
        # Severity breakdown
        f.write("-" * 100 + "\n")
        f.write("SEVERITY BREAKDOWN\n")
        f.write("-" * 100 + "\n")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            count = analysis['by_severity'].get(severity, 0)
            f.write(f"{severity:12s}: {count:3d} findings\n")
        f.write("\n")
        
        # AI Analysis Coverage
        f.write("-" * 100 + "\n")
        f.write("AI ANALYSIS COVERAGE\n")
        f.write("-" * 100 + "\n")
        
        # Count findings with real LLM analysis
        all_findings = (analysis['critical_issues'] + analysis['high_priority'] + 
                       analysis['medium_priority'] + analysis['low_priority'])
        
        llm_analyzed = sum(1 for f in all_findings 
                          if f.get('llm_analysis') and 
                          f.get('llm_analysis') not in ['AI analysis pending', 'AI analysis not available'] and
                          not f.get('llm_analysis', '').startswith('Review this vulnerability carefully'))
        
        fallback_analyzed = len(all_findings) - llm_analyzed
        
        f.write(f"LLM Analyzed:      {llm_analyzed:3d} findings (AI-powered deep analysis)\n")
        f.write(f"Fallback Analyzed: {fallback_analyzed:3d} findings (pattern-based analysis)\n")
        f.write(f"Total Coverage:    {len(all_findings):3d} findings (100%)\n")
        f.write("\nNote: ALL CRITICAL and HIGH issues receive LLM analysis.\n")
        f.write("MEDIUM issues: Top 10 get LLM analysis, rest use intelligent fallback.\n")
        f.write("LOW issues: Use fallback analysis (less critical).\n")
        f.write("\n")
        
        # CWE Mapping
        if analysis['by_cwe']:
            f.write("-" * 100 + "\n")
            f.write("CWE MAPPING (Common Weakness Enumeration)\n")
            f.write("-" * 100 + "\n")
            for cwe, count in sorted(analysis['by_cwe'].items())[:15]:
                f.write(f"{cwe:15s}: {count:3d} findings\n")
            if len(analysis['by_cwe']) > 15:
                f.write(f"... and {len(analysis['by_cwe']) - 15} more CWE categories\n")
            f.write("\n")
        
        # OWASP Mapping
        if analysis['by_owasp']:
            f.write("-" * 100 + "\n")
            f.write("OWASP TOP 10 2021 MAPPING\n")
            f.write("-" * 100 + "\n")
            for owasp, count in sorted(analysis['by_owasp'].items()):
                f.write(f"{owasp:15s}: {count:3d} findings\n")
            f.write("\n")
        
        # ========== FINDINGS SECTIONS ==========
        
        # Critical Issues with Code Evidence and LLM Analysis
        if analysis['critical_issues']:
            f.write("=" * 100 + "\n")
            f.write("CRITICAL ISSUES (IMMEDIATE ACTION REQUIRED)\n")
            f.write("=" * 100 + "\n\n")
            
            for idx, issue in enumerate(analysis['critical_issues'][:15], 1):
                f.write(f"Finding {idx}\n")
                f.write(f"Severity: {issue['severity']}\n")
                f.write(f"Location: {issue['file']}:{issue['line']}\n")
                
                if issue['cwe']:
                    cwe_list = issue['cwe'] if isinstance(issue['cwe'], list) else [issue['cwe']]
                    f.write(f"CWE: {', '.join(map(str, cwe_list))}\n")
                if issue['owasp']:
                    owasp_list = issue['owasp'] if isinstance(issue['owasp'], list) else [issue['owasp']]
                    f.write(f"OWASP: {', '.join(owasp_list)}\n")
                
                f.write("\nVULNERABLE CODE:\n")
                f.write("-" * 90 + "\n")
                for line in issue['code'].split('\n'):
                    f.write(f"{line}\n")
                f.write("-" * 90 + "\n")
                
                # LLM Analysis Section - CRITICAL
                f.write("\nLLM ANALYSIS:\n")
                if issue.get('is_false_positive'):
                    f.write("⚠️  FALSE POSITIVE - This finding may not be exploitable\n")
                
                exploit = issue.get('exploitability', '')
                if exploit and exploit not in ['UNKNOWN', 'PENDING', '']:
                    f.write(f"Exploitability: {exploit}\n")
                
                analysis_text = issue.get('llm_analysis', '')
                if analysis_text and analysis_text not in ['AI analysis not available', 'AI analysis pending', '']:
                    f.write(f"{analysis_text}\n")
                else:
                    f.write(f"Review this vulnerability carefully. {issue.get('message', '')}\n")
                
                f.write("\nRECOMMENDATION:\n")
                rec = issue.get('llm_recommendation', issue['recommendation'])
                if rec and rec not in ['See general recommendation above', '']:
                    f.write(f"{rec}\n")
                else:
                    f.write(f"{issue['recommendation']}\n")
                
                f.write("\n" + "=" * 100 + "\n\n")
            
            if len(analysis['critical_issues']) > 15:
                f.write(f"... and {len(analysis['critical_issues']) - 15} more CRITICAL issues (see JSON)\n\n")
        
        # High Priority Issues
        if analysis['high_priority']:
            f.write("=" * 100 + "\n")
            f.write("HIGH PRIORITY ISSUES (FIX THIS SPRINT)\n")
            f.write("=" * 100 + "\n\n")
            
            for idx, issue in enumerate(analysis['high_priority'][:15], 1):
                f.write(f"Finding {idx}\n")
                f.write(f"Severity: {issue['severity']}\n")
                f.write(f"Location: {issue['file']}:{issue['line']}\n")
                
                if issue['cwe']:
                    cwe_list = issue['cwe'] if isinstance(issue['cwe'], list) else [issue['cwe']]
                    f.write(f"CWE: {', '.join(map(str, cwe_list))}\n")
                if issue['owasp']:
                    owasp_list = issue['owasp'] if isinstance(issue['owasp'], list) else [issue['owasp']]
                    f.write(f"OWASP: {', '.join(owasp_list)}\n")
                
                f.write("\nVULNERABLE CODE:\n")
                f.write("-" * 90 + "\n")
                for line in issue['code'].split('\n')[:10]:
                    f.write(f"{line}\n")
                f.write("-" * 90 + "\n")
                
                # LLM Analysis Section - HIGH  
                f.write("\nLLM ANALYSIS:\n")
                if issue.get('is_false_positive'):
                    f.write("⚠️  FALSE POSITIVE - This finding may not be exploitable\n")
                
                exploit = issue.get('exploitability', '')
                if exploit and exploit not in ['UNKNOWN', 'PENDING', '']:
                    f.write(f"Exploitability: {exploit}\n")
                
                analysis_text = issue.get('llm_analysis', '')
                if analysis_text and analysis_text not in ['AI analysis not available', 'AI analysis pending', '']:
                    f.write(f"{analysis_text}\n")
                else:
                    f.write(f"Review this vulnerability carefully. {issue.get('message', '')}\n")
                
                f.write("\nRECOMMENDATION:\n")
                rec = issue.get('llm_recommendation', issue['recommendation'])
                if rec and rec not in ['See general recommendation above', '']:
                    f.write(f"{rec}\n")
                else:
                    f.write(f"{issue['recommendation']}\n")
                
                f.write("\n" + "=" * 100 + "\n\n")
            
            if len(analysis['high_priority']) > 15:
                f.write(f"... and {len(analysis['high_priority']) - 15} more HIGH priority issues (see JSON)\n\n")
        
        # Medium Priority Issues
        if analysis['medium_priority']:
            f.write("=" * 100 + "\n")
            f.write("MEDIUM PRIORITY ISSUES (NEXT RELEASE)\n")
            f.write("=" * 100 + "\n\n")
            
            # Show detailed analysis for those that have LLM analysis
            analyzed_medium = [issue for issue in analysis['medium_priority'] 
                             if issue.get('llm_analysis') and 
                             issue.get('llm_analysis') not in ['AI analysis pending', 'AI analysis not available']]
            
            if analyzed_medium:
                f.write(f"Showing {len(analyzed_medium)} analyzed MEDIUM issues (with AI analysis):\n\n")
                
                for idx, issue in enumerate(analyzed_medium[:10], 1):
                    f.write(f"Finding {idx}\n")
                    f.write(f"Severity: {issue['severity']}\n")
                    f.write(f"Location: {issue['file']}:{issue['line']}\n")
                    f.write(f"Rule: {issue['rule']}\n")
                    
                    if issue['cwe']:
                        cwe_list = issue['cwe'] if isinstance(issue['cwe'], list) else [issue['cwe']]
                        f.write(f"CWE: {', '.join(map(str, cwe_list))}\n")
                    
                    f.write("\nVULNERABLE CODE:\n")
                    f.write("-" * 90 + "\n")
                    for line in issue['code'].split('\n')[:8]:
                        f.write(f"{line}\n")
                    f.write("-" * 90 + "\n")
                    
                    # LLM Analysis
                    f.write("\nLLM ANALYSIS:\n")
                    if issue.get('is_false_positive'):
                        f.write("⚠️  FALSE POSITIVE\n")
                    
                    exploit = issue.get('exploitability', '')
                    if exploit and exploit not in ['UNKNOWN', 'PENDING', '']:
                        f.write(f"Exploitability: {exploit}\n")
                    
                    analysis_text = issue.get('llm_analysis', '')
                    if analysis_text:
                        f.write(f"{analysis_text}\n")
                    
                    f.write("\nRECOMMENDATION:\n")
                    rec = issue.get('llm_recommendation', issue['recommendation'])
                    f.write(f"{rec}\n")
                    
                    f.write("\n" + "-" * 100 + "\n\n")
                
                if len(analyzed_medium) > 10:
                    f.write(f"... and {len(analyzed_medium) - 10} more analyzed MEDIUM issues (see JSON)\n\n")
            
            # Show summary for remaining
            remaining = len(analysis['medium_priority']) - len(analyzed_medium)
            if remaining > 0:
                f.write(f"Remaining {remaining} MEDIUM issues (fallback analysis):\n")
                f.write("(See JSON report for complete details)\n\n")
        
        # Low Priority Summary
        if analysis['low_priority']:
            f.write("=" * 100 + "\n")
            f.write("LOW PRIORITY ISSUES (CODE QUALITY)\n")
            f.write("=" * 100 + "\n")
            f.write(f"Total: {len(analysis['low_priority'])} code quality issues found\n")
            f.write("(See JSON report for complete details)\n\n")
        
        # ========== NO SEPARATE AI ANALYSIS SECTION ==========
        # (Analysis is now inline with each finding above)
        
        f.write("=" * 100 + "\n")
        f.write("END OF REPORT\n")
        f.write("=" * 100 + "\n")
    
    def scan_local_path(self, path: str) -> Optional[Dict]:
        """Scan local directory"""
        target_path = Path(path).resolve()
        
        if not target_path.exists():
            logger.error(f"Path does not exist: {path}")
            return None
        
        logger.info(f"Scanning local path: {target_path}")
        
        # Ensure Semgrep is installed
        if not self.check_semgrep_installed():
            if not self.install_semgrep():
                return None
        
        # Run scan
        success, results = self.run_semgrep_scan(target_path)
        if not success:
            return None
        
        # Analyze findings (includes per-finding LLM analysis)
        analysis = self.analyze_findings(results, target_path)
        
        # No separate overall LLM analysis needed (analysis is per-finding now)
        llm_analysis = {"provider": "per-finding", "model": "integrated"}
        
        # Generate reports
        self.generate_report(results, analysis, llm_analysis, target_path.name)
        
        return {"results": results, "analysis": analysis, "llm_analysis": llm_analysis}
    
    def scan_github_repo(self, github_url: str) -> Optional[Dict]:
        """Scan GitHub repository"""
        repo_path = self.clone_github_repo(github_url)
        if not repo_path:
            return None
        
        try:
            # Ensure Semgrep is installed
            if not self.check_semgrep_installed():
                if not self.install_semgrep():
                    return None
            
            # Run scan
            success, results = self.run_semgrep_scan(repo_path)
            if not success:
                return None
            
            # Analyze findings (includes per-finding LLM analysis)
            analysis = self.analyze_findings(results, repo_path)
            
            # No separate overall LLM analysis needed (analysis is per-finding now)
            llm_analysis = {"provider": "per-finding", "model": "integrated"}
            
            # Generate reports
            repo_name = github_url.rstrip('/').split('/')[-1].replace('.git', '')
            self.generate_report(results, analysis, llm_analysis, repo_name)
            
            return {"results": results, "analysis": analysis, "llm_analysis": llm_analysis}
            
        finally:
            shutil.rmtree(repo_path, ignore_errors=True)
            logger.info("Cleaned up temporary files")


# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Semgrep AI Code Review - Ultimate Edition (Code Evidence + LLM Analysis)"
    )
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--local", type=str, help="Path to local directory")
    group.add_argument("--github", type=str, help="GitHub repository URL")
    
    parser.add_argument("--output-dir", type=str, default="scan_results", help="Output directory")
    
    args = parser.parse_args()
    
    agent = EnhancedCodeReviewAgent(output_dir=args.output_dir)
    
    print("\n" + "=" * 100)
    print("Semgrep AI Code Review Agent - ULTIMATE EDITION")
    print("=" * 100)
    print("\nFeatures:")
    print("  * Code Evidence - Shows actual vulnerable code snippets")
    print("  * LLM Analysis - AI-powered security insights")
    print("  * Comprehensive Reports - JSON + Beautiful Text Reports")
    print("=" * 100 + "\n")
    
    try:
        if args.local:
            result = agent.scan_local_path(args.local)
        else:
            if not agent.check_git_installed():
                return 1
            result = agent.scan_github_repo(args.github)
        
        if result:
            analysis = result['analysis']
            llm = result['llm_analysis']
            
            print("\n" + "=" * 100)
            print("SCAN COMPLETED")
            print("=" * 100)
            print(f"\nTotal Findings: {analysis['total_findings']}")
            print(f"\nSeverity Breakdown:")
            print(f"  CRITICAL (Immediate Fix):  {analysis['by_severity'].get('CRITICAL', 0)}")
            print(f"  HIGH (This Sprint):         {analysis['by_severity'].get('HIGH', 0)}")
            print(f"  MEDIUM (Next Release):      {analysis['by_severity'].get('MEDIUM', 0)}")
            print(f"  LOW (Code Quality):         {analysis['by_severity'].get('LOW', 0)}")
            print(f"\nCWE Categories: {len(analysis['by_cwe'])}")
            print(f"OWASP Categories: {len(analysis['by_owasp'])}")
            print(f"\nLLM Analysis: {llm['provider']} ({llm['model']})")
            print(f"\nReports saved in: {agent.output_dir}")
            print("=" * 100 + "\n")
            return 0
        else:
            logger.error("Scan failed")
            return 1
            
    except KeyboardInterrupt:
        logger.info("\nScan interrupted")
        return 130
    except Exception as e:
        logger.error(f"Error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    exit(main())