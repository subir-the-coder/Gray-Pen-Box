# Gray-Pen-Box

**Recoded in Python** from the original vulntechx (GO) project with **enhanced evasion techniques** and bloody execution style.


## Features 🧰

- **8+ Advanced WAF Bypass Techniques**
  - Unicode Normalization
  - Case Mangling
  - Null Byte Injection
  - HTTP Parameter Pollution
  - JSON/XML Obfuscation
- **Multi-Vector Payloads**
  - XSS (`<script>alert('BLOOD')</script>`)
  - SQLi (`' OR 'blood'='blood'--`)
  - RCE (`;echo 'blood'`)
- **Cloudflare/Akamai/ModSecurity Evasion**
- **Bloody Terminal Output** 🩸

## Installation ⚙️


git clone https://github.com/subir-the-coder/gray-pen-box.git
cd gray-pen-box

## Usage 🎯

python3 penbox.py target.com -t xss
python3 penbox.py target.com -t sqli
python3 penbox.py target.com -t rce

## Sample Output 📜
<img width="1366" height="768" alt="image" src="https://github.com/user-attachments/assets/45d61fce-e79b-4b42-b932-ae4dfb8a547e" />

Legal ⚖️
⚠️ Use only on authorized targets
This tool is for educational and ethical testing purposes only.

Credits 🙏
Original Author: vulntechx (GO Version)

Python Recode: Subir (Gray Code)



