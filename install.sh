#!/bin/bash

# Exit on any error
set -e

# Define paths
REPO_DIR="$(pwd)"
MODSEC_CONF_DIR="/etc/modsecurity"
MODSEC_RULES_DIR="/usr/share/modsecurity-crs/rules"
OWASP_CRS_DIR="/usr/share/modsecurity-crs"
APACHE_MODSEC_CONF="/etc/apache2/mods-available/security2.conf"
SCRIPT_DIR="/usr/local/bin"
HTML_DIR="/var/www/html"
CACHE_DIR="/var/cache/modsec-threat-monitor"
JSON_FILE1="$HTML_DIR/malicious_ips.json"
JSON_FILE2="$HTML_DIR/modsec_data.json"
JSON_FILE3="$CACHE_DIR/ip_banlist.json"
PYTHON_SCRIPT="ip_reputation_check.py"
PARSE_SCRIPT="parse_modsec.py"
RUN_PARSER_SCRIPT="run_parser.sh"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color


# Step 1: Update system and install dependencies
echo "Updating system and installing dependencies..."
sudo apt update
sudo apt install -y apache2 libapache2-mod-security2 python3 python3-pip git

# Step 2: Install Python dependencies
echo "Installing Python dependencies..."
sudo pip3 install requests



# Step 3: Install OWASP CRS
echo "Installing OWASP Core Rule Set in $OWASP_CRS_DIR..."
sudo mkdir -p "$OWASP_CRS_DIR"
if [ -d "$OWASP_CRS_DIR/.git" ]; then
    echo "OWASP CRS already exists, updating..."
    cd "$OWASP_CRS_DIR"
    sudo git pull origin master
    cd -
else
    sudo git clone https://github.com/coreruleset/coreruleset.git "$OWASP_CRS_DIR"
fi

echo "${GREEN}Installation completed successfully!${NC}"
echo "Apache2, ModSecurity, Python3, and OWASP CRS installed."
echo "OWASP CRS is located at $OWASP_CRS_DIR"

#step 4: copying the crs-setup.example as crs-setup.conf
echo "Copying the file $OWASP_CRS_DIR...."
sudo cp "$OWASP_CRS_DIR/crs-setup.conf.example" "$OWASP_CRS_DIR/crs-setup.conf"

#Step 5: Copying Modsec.conf file

echo "Copying modsecurity.conf.example to $MODSEC_CONF_DIR........"

sudo cp "$MODSEC_CONF_DIR/modsecurity.conf-recommended" "$MODSEC_CONF_DIR/modsecurity.conf"

# Step 10: Set permissions
echo "Setting file permissions..."


# Step 11: Configure Apache to include OWASP CRS
echo "Configuring Apache to include OWASP CRS..."
# writing files
sudo bash -c "cat > $APACHE_MODSEC_CONF << EOL
<IfModule security2_module>
	SecDataDir /var/cache/modsecurity
    Include $MODSEC_CONF_DIR/modsecurity.conf
    Include $OWASP_CRS_DIR/crs-setup.conf
    Include $MODSEC_RULES_DIR/*.conf	
</IfModule>
EOL"


# Step 12: Enable ModSecurity in Apache
echo "Enabling ModSecurity..."
sudo sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' "$MODSEC_CONF_DIR/modsecurity.conf"
sudo a2enmod security2

# Step 13: Test Apache configuration
echo "Testing Apache configuration..."
if sudo apachectl configtest; then
    echo "${GREEN}Apache configuration is valid.${NC}"
else
    echo "${RED}Apache configuration test failed. Please check the configuration files.${NC}"
    exit 1
fi

# Step 14: Restart Apache
echo "Restarting Apache..."
sudo systemctl restart apache2


# Step 13: Verifying installation

if [ -d "$OWASP_CRS_DIR" ]; then
    echo "${GREEN}OWASP CRS installed at $OWASP_CRS_DIR${NC}"
else
    echo "${RED}Error: OWASP CRS not found at $OWASP_CRS_DIR${NC}"
    exit 1
fi
