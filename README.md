

# ModSecurity with Python IP Reputation Check

This project integrates ModSecurity with Apache on Ubuntu, using a Python script to check IP reputation via VirusTotal and log or block malicious IPs.

## Architecture
User Request → ModSecurity WAF → Python Script (VirusTotal API) → Log or Block → Apache Server

## Prerequisites
- Ubuntu 20.04 or later
- Apache2
- ModSecurity v2
- Python 3.8+
- VirusTotal API key + Alien Vault + Abuse IPDB
  
## One Step Installation:
      git clone https://github.com/Shyam-0704/Modsecurity-IP-Reputation.git
      cd Modescurity-IP-Reputation
      sudo pip3 install -r requirements.txt
      sh ./install.sh

##===============================================================================================================================================================##
      
## Manual Installation
# 1. Update the system
      $ sudo apt update
      $ sudo apt upgrade -y
# 1.1 Install all the requirements
      $ sudo pip3 install -r requirements.txt
      
# 2. Install Apache (if not installed)
      $ sudo apt install apache2 -y

# 3. Install Dependencies
      $ sudo apt install libapache2-mod-security2 -y

# 4. Enable ModSecurity
      $ sudo apachectl -M | grep security2_module

# 5. If you don’t see security2_module in the output, enable it manually:
      $ sudo a2enmod security2
      $ sudo systemctl restart apache2

# 6. Configure ModSecurity
    -> The default configuration file is:
         $ /etc/modsecurity/modsecurity.conf-recommended

    -> Copy it to:
         $ sudo cp /etc/modsecurity/modsecurity.conf-recommended /etc/modsecurity/modsecurity.conf

     -> Then edit the conf file:
         $ sudo nano /etc/modsecurity/modsecurity.conf

       => Find the line #SecRuleEngine
            SecRuleEngine DetectionOnly --> SecRuleEngine On

      # This switches from "detection only" mode to actively blocking malicious requests.

# 7. Test Configuration
      $ sudo apachectl configtest

   Output:
      Syntax OK

# 8. Verify Installation
         $ sudo systemctl reload apache2

   After:
      -> Open any browser and search http://localhost
      -> If the default page appears then the apache installed perfectly.

# 9. OWASP Rules configuration:

      The OWASP Core Rule Set (CRS) enhances ModSecurity's capabilities
      $ cd /usr/share
      $ sudo git clone https://github.com/coreruleset/coreruleset.git
      $ cd coreruleset
      $ sudo cp crs-setup.conf.example crs-setup.conf

# 10.  Edit the Apache configuration to include the CRS:
      $ sudo nano /etc/apache2/mods-enabled/security2.conf
      
# 11. Add these lines inside the <IfModule security2_module> block:

      $ IncludeOptional /usr/share/coreruleset/crs-setup.conf
      $ IncludeOptional /usr/share/coreruleset/rules/*.conf

# 12. Reload Apache:

      $ sudo systemctl reload apache2
      
# 13. ModSecurity v2 is now active on your Ubuntu system! You can check logs at:

       $ nano /var/log/apache2/modsec_audit.log


 





