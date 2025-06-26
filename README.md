# 🛡️ Phishing Link Scanner

A Python-based phishing link scanner designed to detect potentially malicious URLs using rule-based heuristics and optional integration with the VirusTotal API.

---

## 📌 Overview

Phishing attacks often rely on deceptive URLs to trick users into revealing sensitive information. This tool analyzes a given URL and flags suspicious characteristics to help identify potential phishing links.

---

## ✅ Features

- 🔍 Detects:
  - IP-based URLs
  - Suspicious subdomains
  - Use of `@` symbol
  - Long or obfuscated URLs
  - Unsecured (`http`) connections
  - Hyphenated domains
- 🧪 Optional: Scans URL with [VirusTotal API](https://virustotal.com/)
- 🧠 Basic scoring system to classify URLs as **safe**, **suspicious**, or **potential phishing**

---

## 🛠️ Requirements

Install required packages:

```bash
pip install requests tldextract
