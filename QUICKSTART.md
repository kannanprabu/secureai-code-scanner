# Quick Start Guide

Get SecureCodeAI running in 5 minutes!

---

## 🚀 Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure API Key
Edit `config.py` and add your Azure OpenAI credentials:
```python
LLM_PROVIDER = "azure"
AZURE_OPENAI_API_KEY = "your-key-here"
AZURE_OPENAI_ENDPOINT = "https://your-instance.openai.azure.com/"
AZURE_OPENAI_DEPLOYMENT = "gpt-4"
```

### 3. Run Your First Scan

**Windows (Important - Set UTF-8 first):**
```bash
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
```

**Scan Azure DevOps Repository:**
```bash
python code_review_agent_final.py --repo https://dev.azure.com/org/project/_git/repo
```

**Scan GitHub Repository:**
```bash
python code_review_agent_final.py --github https://github.com/OWASP/NodeGoat
```

**Scan Local Directory:**
```bash
python code_review_agent_final.py --local C:\path\to\your\code
```

### 4. View Results
```bash
# Results are saved in ./scan_results/
dir scan_results

# Open the report
notepad scan_results\security_scan_*_report.txt
```

---

## 📊 Example Output

```
====================================================================================================
SecureCodeAI - LLM-Enhanced Security Code Review
====================================================================================================

Total Findings: 65
  CRITICAL (Immediate Fix):  21
  HIGH (This Sprint):         8
  MEDIUM (Next Release):     32
  LOW (Code Quality):         4

✓ MERGED RESULTS: 65 unique findings from 4/4 configs
✓ Total LLM analyses completed: 65/65
✓ Coverage: 100% - All findings analyzed!

Reports saved in: scan_results/
====================================================================================================
```

**Report Shows:**
- Vulnerable code snippets
- AI analysis for each finding
- Exploitability ratings (HIGH/MEDIUM/LOW)
- Specific fix recommendations
- False positive detection
- CWE and OWASP mappings

---

## 📋 Common Commands

### Azure DevOps (Your Repos)
```bash
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
python code_review_agent_final.py --repo https://dev.azure.com/MicrosoftIT/OneITVSO/_git/PCTrax
```

### GitHub (Public Repos)
```bash
python code_review_agent_final.py --github https://github.com/username/repo
```

### Local Code (Current Directory)
```bash
python code_review_agent_final.py --local .
```

### Custom Output Location
```bash
python code_review_agent_final.py --repo [URL] --output-dir ./my-reports
```

---

## 🆘 Troubleshooting

### "Semgrep not found"
```bash
pip install semgrep --break-system-packages
```

### "Only finding 1-2 issues"
**Problem:** Windows encoding issue

**Fix:** Always set UTF-8 before scanning:
```bash
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
```

### "charmap codec error"
**Problem:** Unicode characters in Semgrep rules

**Fix:** Set UTF-8 (see above) or use provided batch file

### "config module not found"
**Problem:** Missing config.py

**Fix:** Create `config.py` with your API credentials

---

## 💡 Pro Tips

**For Best Results:**
- Always set UTF-8 encoding on Windows
- Scans take 5-7 minutes (tries multiple Semgrep configs for complete coverage)
- Review CRITICAL and HIGH issues first
- Check for FALSE POSITIVE warnings in LLM analysis
- All findings get AI analysis (even MEDIUM and LOW)

**What Gets Analyzed:**
- ✅ All CRITICAL issues → LLM analysis
- ✅ All HIGH issues → LLM analysis
- ✅ All MEDIUM issues → LLM analysis
- ✅ All LOW issues → LLM analysis
- ✅ 100% coverage with AI-powered insights

**Cost Per Scan:**
- Azure OpenAI GPT-4: ~$0.50-$1.50 per scan
- Depends on number of findings (typically 40-80)

---

## 📖 Available Options

```bash
python code_review_agent_final.py --help
```

**Options:**
- `--repo [URL]` - Scan any Git repository (Azure DevOps, GitLab, etc.)
- `--github [URL]` - Scan GitHub repository
- `--local [PATH]` - Scan local directory
- `--output-dir [PATH]` - Custom output directory (default: scan_results)

---

## 📝 What You Get

**Two Report Files:**

1. **JSON Report** (`security_scan_***.json`)
   - Complete structured data
   - All findings with full details
   - Machine-readable format

2. **Text Report** (`security_scan_***_report.txt`)
   - Human-readable format
   - Organized by severity
   - Code snippets included
   - AI analysis inline
   - Fix recommendations

**Report Sections:**
1. Executive Summary (findings count by severity)
2. AI Analysis Coverage (how many analyzed)
3. CWE and OWASP Mappings
4. CRITICAL Issues (all with full AI analysis)
5. HIGH Issues (all with full AI analysis)
6. MEDIUM Issues (all with full AI analysis)
7. LOW Issues (all with full AI analysis)

---

## ✅ Quick Checklist

Before your first scan:
- [ ] Install dependencies (`pip install -r requirements.txt`)
- [ ] Configure `config.py` with Azure OpenAI credentials
- [ ] Set UTF-8 encoding (`set PYTHONUTF8=1`)
- [ ] Run test scan on public repo

For each scan:
- [ ] Set UTF-8 (Windows)
- [ ] Run: `python code_review_agent_final.py --repo [URL]`
- [ ] Check `scan_results/` for reports
- [ ] Review CRITICAL issues first
- [ ] Follow AI recommendations

---

## 🎯 Next Steps

1. ✅ Run your first scan on a test repository
2. ✅ Review the generated reports
3. ✅ Scan your production code
4. ✅ Share results with your team
5. ✅ Fix CRITICAL and HIGH issues

---

**That's it! You're ready to scan.** 🚀

**Need help?** Check `README.md` or `USAGE.md` for detailed documentation.