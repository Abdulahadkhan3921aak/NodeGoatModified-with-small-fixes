#!/bin/bash
# fail2ban-docker-setup.sh
# Script to set up fail2ban for NodeGoat in Docker environment

# Ensure script is run as root
if [ "$(id -u)" != "0" ]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

echo "Setting up fail2ban for NodeGoat Docker environment..."

# Install fail2ban if not already installed
echo "Checking if fail2ban is installed..."
if ! command -v fail2ban-server &> /dev/null; then
    echo "Installing fail2ban..."
    apt-get update
    apt-get install -y fail2ban
else
    echo "fail2ban is already installed."
fi

# Create necessary directories
APP_LOG_DIR="$(pwd)/logs"
echo "Creating log directory: $APP_LOG_DIR"
mkdir -p "$APP_LOG_DIR"
touch "$APP_LOG_DIR/failed-logins.log"
chmod 644 "$APP_LOG_DIR/failed-logins.log"

# Create filter for NodeGoat
echo "Creating NodeGoat filter..."
cat > /etc/fail2ban/filter.d/nodegoat.conf << EOL
# Fail2Ban filter for NodeGoat application
[Definition]
# Match logs that indicate failed login attempts
failregex = ^.*warn: .*failed login attempt.*username: <F-USER>.*</F-USER>, ip: <HOST>$
           ^.*warn: .*login failure.*user: <F-USER>.*</F-USER>.*ip: <HOST>$
ignoreregex = ^.*warn: IP <HOST> blocked due to excessive login failures for user: .*$
EOL

# Create jail for NodeGoat
echo "Creating NodeGoat jail..."
cat > /etc/fail2ban/jail.d/nodegoat.conf << EOL
[nodegoat]
enabled = true
port = 4000,8080
filter = nodegoat
logpath = $APP_LOG_DIR/failed-logins.log
maxretry = 5
findtime = 10m
bantime = 1h
action = iptables-multiport[name=nodegoat, port="4000,8080"]
         sendmail-whois[name=NodeGoat, dest=admin@example.com, sender=fail2ban@example.com]
EOL

# Restart fail2ban
echo "Restarting fail2ban..."
systemctl restart fail2ban

# Check status
echo "Checking fail2ban status..."
fail2ban-client status nodegoat

echo "Setup complete!"
echo "To test, you can run: fail2ban-regex $APP_LOG_DIR/failed-logins.log /etc/fail2ban/filter.d/nodegoat.conf"

# Add notes about Docker networking
echo ""
echo "IMPORTANT NOTES FOR DOCKER ENVIRONMENT:"
echo "1. fail2ban may see Docker's internal IPs rather than the actual client IPs."
echo "2. Consider configuring your Docker containers to use host networking or"
echo "   ensure they forward the real client IP in the logs."
echo ""
echo "You can test the effectiveness by attempting failed logins to your application."
