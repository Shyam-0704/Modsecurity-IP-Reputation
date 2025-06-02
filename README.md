

# ModSecurity with Python IP Reputation Check

This project integrates ModSecurity with Apache on Ubuntu, using a Python script to check IP reputation via VirusTotal and log or block malicious IPs.

## Architecture
User Request → ModSecurity WAF → Python Script (VirusTotal API) → Log or Block → Apache Server

## Prerequisites
- Ubuntu 20.04 or later
- Apache2
- ModSecurity v3
- Python 3.8+
- VirusTotal API key

## Installation
1. Install Apache2 and ModSecurity:
   ```bash
   sudo apt update
   sudo apt install apache2 libapache2-mod-security2
