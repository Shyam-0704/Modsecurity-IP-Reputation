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
#python3 -m venv venv
#source venv/bin/activate
echo "Installing Python dependencies..."
#sudo pip3 install requests
#deactivate


# Step 3: Install OWASP CRS
echo "Installing OWASP Core Rule Set in $OWASP_CRS_DIR..."
rm -r -f /usr/share/modsecurity-crs

sudo git clone https://github.com/coreruleset/coreruleset.git "$OWASP_CRS_DIR"


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

#!/bin/bash


# Exit on any error
set -e

# Define paths
#REPO_DIR= "$(pwd)"
SCRIPT_DIR="/usr/local/bin"
HTML_DIR="/var/www/html"
PYTHON_SCRIPT="ip_reputation_check.py"
PARSE_SCRIPT="parse_modsec.py"
RUN_PARSER_SCRIPT="run_parser.sh"
CACHE_DIR="/var/cache/modsec-threat-monitor"
JSON_FILE1="$HTML_DIR/malicious_ips.json"
JSON_FILE2="$HTML_DIR/modsec_data.json"
JSON_FILE3="$CACHE_DIR/ip_banlist.json"




MODSEC_CONF_DIR="/etc/modsecurity"
MODSEC_RULES_DIR="/usr/share/modsecurity-crs/rules"
OWASP_CRS_DIR="/usr/share/modsecurity-crs"
APACHE_MODSEC_CONF="/etc/apache2/mods-available/security2.conf"
APACHE_HTTP2_CONF="/etc/apache2/mods-available/http2.load"
APACHE_SECURITY_CONF="/etc/apache2/mods-enabled/security2.load"
APACHE_DEFAULT_CONF="/etc/apache2/sites-available/000-default.conf"
APACHE_CONF="/etc/apache2/apache2.conf"
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

echo "Starting setup for ModSecurity with Python integration..."
echo "Copying scripts to $SCRIPT_DIR..."
sudo cp "$REPO_DIR/scripts/$PYTHON_SCRIPT" "$SCRIPT_DIR/$PYTHON_SCRIPT"
sudo cp "$REPO_DIR/scripts/$PARSE_SCRIPT" "$SCRIPT_DIR/$PARSE_SCRIPT"
sudo cp "$REPO_DIR/scripts/$RUN_PARSER_SCRIPT" "$SCRIPT_DIR/$RUN_PARSER_SCRIPT"


# Step 3: Copy HTML files
echo "Copying HTML files to $HTML_DIR..."
sudo cp "$REPO_DIR/dashboard.html" "$HTML_DIR/dashboard.html"
sudo cp "$REPO_DIR/blocked.html" "$HTML_DIR/blocked.html"


# Step 4: Create Json files
sudo mkdir /var/cache/modsec-threat-monitor
sudo touch "$JSON_FILE1"
sudo touch "$JSON_FILE2"
sudo touch "$JSON_FILE3"

# Step 5: Configure Apache modules
echo "Configuring Apache modules..."
# http2.load: Comment out existing content and add LoadModule
if [ -f "$APACHE_HTTP2_CONF" ]; then
    sudo sed -i 's/^/#/' "$APACHE_HTTP2_CONF"
fi
echo "LoadModule http2_module /usr/lib/apache2/modules/mod_http2.so" | sudo tee -a "$APACHE_HTTP2_CONF" > /dev/null

# security2.load: Overwrite with LoadModule
echo "LoadModule security2_module /usr/lib/apache2/modules/mod_security2.so" | sudo tee "$APACHE_SECURITY_CONF" > /dev/null

# Step 6: Configure ErrorDocument in 000-default.conf
echo "Configuring ErrorDocument in $APACHE_DEFAULT_CONF..."
if grep -q "ErrorDocument 403" "$APACHE_DEFAULT_CONF"; then
    sudo sed -i 's|ErrorDocument 403 .*|ErrorDocument 403 /blocked.html|' "$APACHE_DEFAULT_CONF"
else
    sudo sed -i '/<VirtualHost \*:80>/a\        ErrorDocument 403 /blocked.html' "$APACHE_DEFAULT_CONF"
fi

# Step 7: Add ServerName to apache2.conf
echo "Adding ServerName to $APACHE_CONF..."
if ! grep -q "ServerName localhost" "$APACHE_CONF"; then
    echo "ServerName localhost" | sudo tee -a "$APACHE_CONF" > /dev/null
fi

# Setting file permissions...
echo "Setting file permissions..."
sudo chown www-data:www-data "$SCRIPT_DIR/$PYTHON_SCRIPT" "$SCRIPT_DIR/$PARSE_SCRIPT" "$SCRIPT_DIR/$RUN_PARSER_SCRIPT" "$HTML_DIR/dashboard.html" "$HTML_DIR/blocked.html"
sudo chmod 644 "$HTML_DIR/dashboard.html" "$HTML_DIR/blocked.html"
sudo chmod +x "$SCRIPT_DIR/$RUN_PARSER_SCRIPT"

# Step 5: Set permissions for scripts and JSON files

# For PY Scripts
echo "Setting permissions for scripts and JSON files..."
for file in "$SCRIPT_DIR/$PYTHON_SCRIPT" "$SCRIPT_DIR/$PARSE_SCRIPT" "$SCRIPT_DIR/$RUN_PARSER_SCRIPT"; do
    if [ -f "$file" ]; then
        sudo chown www-data:www-data "$file"
        sudo chmod 755 "$file"
        echo "${GREEN}Set execute permissions for $file${NC}"
    else
        echo "${RED}Warning: $file not found, skipping permission setting${NC}"
    fi
done



# For JSON
for json_file in "$JSON_FILE1" "$JSON_FILE2" "$JSON_FILE3"; do
    if [ -f "$json_file" ]; then
        sudo chown www-data:www-data "$json_file"
        sudo chmod 664 "$json_file"
        echo "${GREEN}Set permissions for $json_file${NC}"
    else
        echo "${RED}Error: Failed to create $json_file${NC}"
        exit 1
    fi
done
sudo chown www-data:www-data "$CACHE_DIR"
sudo chmod 775 "$CACHE_DIR"
echo "${GREEN}Set permissions for $CACHE_DIR${NC}"

bash "$SCRIPT_DIR/$RUN_PARSER_SCRIPT"
# verification
echo "${GREEN}Installation and permission setup completed successfully!${NC}"
echo "Dependencies installed: Apache2, ModSecurity, Python3, git, requests"
echo "OWASP CRS installed at $OWASP_CRS_DIR"
echo "JSON files created at $JSON_FILE1, $JSON_FILE2, and $JSON_FILE3"
echo "Execute permissions set for scripts in $SCRIPT_DIR (if present)"

# Step 5: Verify setup
echo "Verifying setup..."
for file in "$SCRIPT_DIR/$PYTHON_SCRIPT" "$SCRIPT_DIR/$PARSE_SCRIPT" "$SCRIPT_DIR/$RUN_PARSER_SCRIPT" "$HTML_DIR/dashboard.html" "$HTML_DIR/blocked.html"; do
    if [ -f "$file" ]; then
        echo "${GREEN}Found $file${NC}"
    else
        echo "${RED}Error: $file not found${NC}"
        exit 1
    fi
done


# verification
echo "${GREEN}Installation and permission setup completed successfully!${NC}"
echo "Dependencies installed: Apache2, ModSecurity, Python3, git, requests"
echo "OWASP CRS installed at $OWASP_CRS_DIR"
echo "JSON files created at $JSON_FILE1, $JSON_FILE2, and $JSON_FILE3"
echo "Execute permissions set for scripts in $SCRIPT_DIR (if present)"
echo "${GREEN}Setup completed successfully!${NC}"
echo "Scripts placed in $SCRIPT_DIR"
echo "HTML files placed in $HTML_DIR"
