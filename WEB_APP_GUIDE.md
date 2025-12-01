# 🌐 Web Interface - Simple Guide

## 🚀 Quick Start

### 1. Install Flask
```bash
pip install Flask
```

### 2. Start the Web Server
```bash
python web_app.py
```

### 3. Open Your Browser
```
http://localhost:5000
```

**That's it!** No more command line needed! 🎉

---

## 📱 How to Use

### **Step 1: Choose Scan Type**
- **Git Repository** - For Azure DevOps or GitHub repos
- **Local Directory** - For code on your computer

### **Step 2: Enter URL or Path**
**For Azure DevOps:**
```
https://dev.azure.com/yourrepo
```

**For GitHub:**
```
https://github.com/OWASP/NodeGoat
```

**For Local Code:**
```
C:\path\to\your\code
```

### **Step 3: Click "Start Security Scan"**
- Wait 5-10 minutes for scan to complete
- Progress shown on screen
- Results appear automatically

### **Step 4: View Results**
- See findings count (CRITICAL, HIGH, MEDIUM, LOW)
- Click "Download Report" for full details
- Click "View Results" to see complete report

---

## 💻 Screenshots (What You'll See)

### **Home Page:**
```
┌─────────────────────────────────────┐
│  🔒 SecureCodeAI                    │
│  LLM-Enhanced Security Code Review  │
├─────────────────────────────────────┤
│                                     │
│  Scan Type: [Git Repository ▼]     │
│                                     │
│  Repository URL:                    │
│  [________________________]         │
│                                     │
│  [🔍 Start Security Scan]           │
│  [📊 View Results]                  │
│                                     │
└─────────────────────────────────────┘
```

### **Scanning:**
```
┌─────────────────────────────────────┐
│  ⏳ Starting security scan...       │
│     This may take 5-10 minutes.     │
└─────────────────────────────────────┘
```

### **Results:**
```
┌──────────────────────────────────────┐
│  ✅ Scan completed successfully!     │
├──────────────────────────────────────┤
│  Scan Results                        │
│                                      │
│  ┌────┐  ┌────┐  ┌────┐  ┌────┐   │
│  │ 21 │  │  8 │  │ 32 │  │  4 │   │
│  │CRIT│  │HIGH│  │MED │  │LOW │   │
│  └────┘  └────┘  └────┘  └────┘   │
│                                      │
│         [📥 Download Report]         │
└──────────────────────────────────────┘
```

---

## ⚙️ Configuration

Before first scan, configure your API key in `config.py`:

```python
LLM_PROVIDER = "azure"
AZURE_OPENAI_API_KEY = "your-key-here"
AZURE_OPENAI_ENDPOINT = "https://your-instance.openai.azure.com/"
AZURE_OPENAI_DEPLOYMENT = "gpt-4"
```

---

## 🎯 Features

✅ **No Command Line** - Just click buttons
✅ **Real-time Progress** - See scan status
✅ **Visual Results** - Color-coded severity cards
✅ **Easy Download** - Get full report with one click
✅ **Clean Interface** - Simple and beautiful

---

## 📋 Common Tasks

### **Scan Your Azure DevOps Repo:**
1. Open http://localhost:5000
2. Select "Git Repository"
3. Paste: `https://dev.azure.com/...`
4. Click "Start Security Scan"
5. Wait for results
6. Download report

### **Scan Local Code:**
1. Open http://localhost:5000
2. Select "Local Directory"
3. Enter: `C:\code\myproject`
4. Click "Start Security Scan"
5. Wait for results
6. Download report

### **View Previous Scans:**
1. Click "View Results"
2. Opens latest report in new tab
3. Shows full detailed analysis

---

## 🆘 Troubleshooting

### **"Port 5000 already in use"**
**Fix:** Change port in `web_app.py`:
```python
app.run(debug=True, host='0.0.0.0', port=8080)  # Use 8080 instead
```
Then visit: http://localhost:8080

### **"Module not found: Flask"**
**Fix:**
```bash
pip install Flask
```

### **"Scan not starting"**
**Fix:** Check console where web_app.py is running for error messages

### **Can't access from other computers**
The server is accessible from other computers on your network at:
```
http://YOUR_IP_ADDRESS:5000
```

Find your IP:
```bash
# Windows
ipconfig

# Look for IPv4 Address
```

---

## 🔧 Starting/Stopping

### **Start Server:**
```bash
python web_app.py
```

**Output:**
```
============================================================
🔒 SecureCodeAI Web Interface
============================================================

📱 Open your browser and go to:

   http://localhost:5000

⚠️  Press Ctrl+C to stop the server
============================================================
```

### **Stop Server:**
Press `Ctrl+C` in the terminal

---

## 💡 Pro Tips

**For Your Team:**
- Share the URL: `http://YOUR_IP:5000`
- Everyone can access the scanner
- No need to install Python on each machine
- Centralized scanning

**Multiple Scans:**
- Wait for current scan to finish
- Then start another scan
- One scan at a time

**Faster Development:**
- Keep web server running
- Scan → View → Scan again
- No need to restart server

---

## ✅ Checklist

Before using web interface:
- [ ] Installed Flask (`pip install Flask`)
- [ ] Configured `config.py` with API key
- [ ] Started web server (`python web_app.py`)
- [ ] Opened browser to http://localhost:5000
- [ ] Tested with sample repo

---

## 📊 Comparison

| Feature | Command Line | Web Interface |
|---------|--------------|---------------|
| Ease of Use | ⭐⭐ | ⭐⭐⭐⭐⭐ |
| Setup | Copy commands | Just open browser |
| Progress | Console text | Visual progress bar |
| Results | Text file | Visual cards + download |
| Team Access | Everyone needs CLI | Share one URL |
| Learning Curve | High | Low |

---

**Web interface = Easier for everyone!** 🎉

**Just run `python web_app.py` and open your browser!** 🚀