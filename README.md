# 🔒 AgenticAI Code Review Tool - Ultimate Edition

AI-powered security scanner that finds vulnerabilities and tells you if they're real or false positives.

## ✨ What Makes This Special

**🤖 AI Analysis for Every Finding**
- LLM analyzes each vulnerability individually
- Detects false positives automatically
- Provides specific fixes with code examples
- No more generic "review manually" messages

**📊 Smart Severity Classification**
- **CRITICAL**: Remote code execution, hardcoded secrets
- **HIGH**: XSS, authentication bypass, data exposure
- **MEDIUM**: Weak crypto, config issues
- **LOW**: Code quality, debug code

**💡 Real-World Analysis**
```
Finding 1
Severity: CRITICAL
Location: contributions.js:32

VULNERABLE CODE:
>>> 32 | const preTax = eval(req.body.preTax);

LLM ANALYSIS:
Exploitability: HIGH
This eval() call executes user input without sanitization,
allowing Remote Code Execution...

RECOMMENDATION:
Replace with parseFloat():
  const preTax = parseFloat(req.body.preTax) || 0;
```

**🎯 Comprehensive Coverage**
- ✅ All OWASP Top 10 vulnerabilities
- ✅ CWE Top 25 patterns
- ✅ 141+ vulnerability categories
- ✅ Framework-specific rules (Django, Flask, Express, React, etc.)

---

## 🚀 Quick Start

### 1. Install
```bash
pip install semgrep anthropic openai requests
```

### 2. Configure
Create `config.py`:
```python
# Choose your AI provider
LLM_PROVIDER = "anthropic"  # or "azure" or "openai"
ANTHROPIC_API_KEY = "your-key-here"
```

### 3. Run
```bash
# Windows users (important!)
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

# Scan GitHub repository
python code_review_agent_final.py --github https://github.com/OWASP/NodeGoat

# Or use the batch file (easier)
run_scan.bat --github https://github.com/OWASP/NodeGoat
```

### 4. Check Results
```
scan_results/security_scan_NodeGoat_[timestamp]_report.txt
```

---

## 📊 What You Get

### Executive Summary
```
Total Findings: 29
  CRITICAL (Immediate Fix):  7
  HIGH (This Sprint):        4
  MEDIUM (Next Release):    17
  LOW (Code Quality):        1

CWE Categories: 7
OWASP Coverage: 9/10
```

### Each Finding Shows
- ✅ Actual vulnerable code with line numbers
- ✅ AI analysis: Is it real or false positive?
- ✅ Exploitability rating (HIGH/MEDIUM/LOW)
- ✅ Specific fix with code example
- ✅ CWE and OWASP mappings

### False Positive Detection
```
Finding 5
Severity: HIGH

LLM ANALYSIS:
⚠️  FALSE POSITIVE
Exploitability: NOT_EXPLOITABLE
This uses eval() but only on build-time config,
not user input. Safe to ignore.
```

---

## 💻 Usage Examples

### Scan GitHub Repository
```bash
python code_review_agent_final.py --github https://github.com/username/repo
```

### Scan Local Code
```bash
python code_review_agent_final.py --local /path/to/code
```

### Custom Output Directory
```bash
python code_review_agent_final.py --local . --output-dir ./security-reports
```

### Windows Users (Easy Way)
```bash
run_scan.bat --github https://github.com/OWASP/NodeGoat
```

---

## 🎯 AI Providers

### Option 1: Anthropic Claude (Recommended)
```python
LLM_PROVIDER = "anthropic"
ANTHROPIC_API_KEY = "sk-ant-api03-..."
ANTHROPIC_MODEL = "claude-sonnet-4-20250514"
```

### Option 2: Azure OpenAI
```python
LLM_PROVIDER = "azure"
AZURE_OPENAI_API_KEY = "your-key"
AZURE_OPENAI_ENDPOINT = "https://your-instance.openai.azure.com/"
AZURE_OPENAI_DEPLOYMENT = "gpt-4"
AZURE_OPENAI_API_VERSION = "2024-12-01-preview"
```

### Option 3: OpenAI
```python
LLM_PROVIDER = "openai"
OPENAI_API_KEY = "sk-..."
OPENAI_MODEL = "gpt-4"
```

---

## 🔍 What It Detects

### CRITICAL Issues (7 types)
- Remote Code Execution (eval, exec, command injection)
- SQL Injection
- Hardcoded secrets and credentials
- Insecure deserialization
- XXE attacks

### HIGH Issues (23 types)
- Cross-Site Scripting (XSS)
- Authentication bypass
- Path traversal
- CSRF vulnerabilities
- Server-Side Request Forgery (SSRF)

### MEDIUM Issues (32 types)
- Weak cryptography (MD5, SHA1)
- Insecure cookies
- Missing security headers
- Information disclosure
- Race conditions

### LOW Issues (24 types)
- Debug code in production
- TODO/FIXME comments
- Missing input validation
- Console.log statements

**Total: 141+ vulnerability patterns**

---

## 🪟 Windows Users - Important!

Windows has encoding issues that break Semgrep. **Use one of these fixes:**

### Fix 1: Use Batch File (Easiest)
```bash
run_scan.bat --github https://github.com/OWASP/NodeGoat
```

### Fix 2: Set Environment Variables
```bash
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
python code_review_agent_final.py --github https://github.com/OWASP/NodeGoat
```

### Fix 3: Use PowerShell
```powershell
.\run_scan.ps1 --github https://github.com/OWASP/NodeGoat
```

**Without this fix, you'll only get 1-2 findings instead of 40+!**

---

## 🔧 CI/CD Integration

### GitHub Actions
```yaml
- name: Security Scan
  run: |
    pip install semgrep anthropic
    python code_review_agent_final.py --local . --config p/security-audit
```

### Block Deployment on Critical Issues
The scanner exits with code 1 if critical issues are found, automatically failing your CI/CD pipeline.

---

## 📋 Example Report

```
====================================================================================================
CRITICAL ISSUES (7 findings)
====================================================================================================

Finding 1
Severity: CRITICAL
Location: contributions.js:32
CWE: CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code
OWASP: A03:2021 - Injection

VULNERABLE CODE:
------------------------------------------------------------------------------------------
   30 | /*jslint evil: true */
   31 | // Insecure use of eval()
>>> 32 | const preTax = eval(req.body.preTax);
   33 | const afterTax = eval(req.body.afterTax);
------------------------------------------------------------------------------------------

LLM ANALYSIS:
Exploitability: HIGH
This eval() call directly executes user input from req.body without any sanitization.
An attacker can inject arbitrary JavaScript code to achieve Remote Code Execution.

Example attack: {"preTax": "require('child_process').exec('rm -rf /')"}

RECOMMENDATION:
1. Replace eval() with safe parsing:
   const preTax = parseFloat(req.body.preTax) || 0;

2. Add input validation:
   if (isNaN(preTax) || preTax < 0) {
     return res.status(400).json({error: 'Invalid input'});
   }

3. Use express-validator for robust validation:
   npm install express-validator

====================================================================================================

Finding 2
Severity: CRITICAL
Location: artifacts/cert/server.key:1

LLM ANALYSIS:
Exploitability: HIGH
Private RSA key committed to version control. Anyone with repo access can
impersonate your server or decrypt TLS traffic.

RECOMMENDATION:
1. Remove file from repo immediately: git rm artifacts/cert/server.key
2. Rotate certificates and keys NOW
3. Store keys in secure vault (AWS Secrets Manager, Azure Key Vault)
4. Add *.key to .gitignore

====================================================================================================
```

---

## 🎯 Use Cases

### Pre-Commit Check
Quick scan before committing code
```bash
python code_review_agent_final.py --local .
```

### Pull Request Review
Comprehensive scan for PRs
```bash
python code_review_agent_final.py --local . --config p/security-audit
```

### Security Audit
Deep analysis for production code
```bash
python code_review_agent_final.py --github https://github.com/company/app --config p/owasp-top-ten
```

### Compliance Check
Verify OWASP and CWE coverage
```bash
python code_review_agent_final.py --local /path/to/app
# Report shows OWASP Top 10 and CWE mapping
```

---

## ⚙️ Advanced Configuration

### Custom Severity Mapping
In `config.py`, add custom patterns:
```python
SEVERITY_LEVELS = {
    "my-company-pattern": "CRITICAL",
    "internal-rule": "HIGH",
}
```

### Scan Timeout
```python
SCAN_TIMEOUT = 600  # seconds (default)
```

### Multiple Ruleset Scan
The scanner automatically tries multiple Semgrep configs and picks the best result:
1. `--config=auto` (most comprehensive)
2. `security-audit + owasp + cwe` (combined)
3. Language-specific (JavaScript, Python, etc.)

---

## 🆘 Troubleshooting

### "Only finding 1-2 issues"
**Problem:** Windows encoding or network blocking Semgrep rules

**Fix:**
```bash
# Set UTF-8 encoding
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8

# Clear Semgrep cache
del /S /Q %USERPROFILE%\.semgrep\cache

# Run scan
python code_review_agent_final.py --github https://github.com/OWASP/NodeGoat
```

### "AI analysis not available"
**Problem:** API key missing or network issue

**Fix:** Check `config.py` has your API key and run diagnostic:
```bash
python semgrep_diagnostic.py
```

### "Semgrep not found"
**Fix:**
```bash
pip install --upgrade semgrep --break-system-packages
```

---

## 📚 Documentation

- **[WINDOWS_FIX.md](WINDOWS_FIX.md)** - Complete Windows setup guide
- **[NEW_FORMAT_GUIDE.md](NEW_FORMAT_GUIDE.md)** - Report format details
- **[LLM_ANALYSIS_FIX.md](LLM_ANALYSIS_FIX.md)** - How AI analysis works
- **[TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Common issues and solutions

---

## 🎉 Key Features

✅ **AI-Powered Analysis** - LLM reviews each finding
✅ **False Positive Detection** - Saves hours of manual review
✅ **Specific Recommendations** - Actual code fixes, not "review manually"
✅ **Comprehensive Coverage** - 141+ vulnerability types
✅ **Framework Support** - Django, Flask, Express, React, Spring, etc.
✅ **Windows Compatible** - Auto-fixes encoding issues
✅ **CI/CD Ready** - Blocks deployment on critical issues
✅ **OWASP Compliant** - Full Top 10 coverage
✅ **CWE Mapped** - All findings mapped to CWE IDs

---

## 📊 Expected Results

### NodeGoat (Deliberately Vulnerable App)
```
Total Findings: 29-42 (depending on Semgrep version)
  CRITICAL: 7-10 (eval, SQL injection, hardcoded secrets)
  HIGH: 4-8 (XSS, CSRF, path traversal)
  MEDIUM: 15-20 (crypto, cookies, headers)
  LOW: 1-4 (code quality)
```

If you're getting only 1-2 findings, see [Troubleshooting](#-troubleshooting).

---

## 🔒 Security Best Practices

1. **Never commit API keys** - Use environment variables
2. **Fix CRITICAL issues immediately** - Block deployment
3. **Review false positives** - AI helps but verify manually
4. **Update regularly** - Keep Semgrep rules current
5. **Rotate exposed secrets** - If scanner finds hardcoded credentials

---

## 📄 License

MIT License - Use freely in your projects!

---

## 🙏 Credits

Built with:
- **Semgrep** - Static analysis engine
- **Anthropic Claude** - AI security analysis
- **Azure OpenAI** - Alternative AI provider
- **OWASP** - Security standards
- **CWE** - Vulnerability classifications

---

## 💬 Support

**Having issues?**
1. Check [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
2. Run diagnostic: `python semgrep_diagnostic.py`
3. Read [WINDOWS_FIX.md](WINDOWS_FIX.md) if on Windows

**Questions?**
- Review documentation files
- Check example outputs
- Run test scan on NodeGoat

---

**Secure your code with AI-powered analysis! 🔒✨**

**Quick Start:**
```bash
pip install semgrep anthropic
# Create config.py with your API key
run_scan.bat --github https://github.com/OWASP/NodeGoat
```

**That's it! Check the generated report.** 🎉