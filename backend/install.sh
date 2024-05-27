#!/bin/bash

# updated need packages
sudo apt-get update
sudo apt-get install -y nodejs npm iptables

# add global proccess manager
sudo npm install -g pm2

# Kopioidaan palvelun lähdekoodit ja asennetaan npm riippuvuudet
git clone https://github.com/codenamey/gatekeeper.git /opt/gatekeeper
cd /opt/gatekeeper
npm install

# Luodaan ympäristömuuttujat sisältävä tiedosto
cat <<EOT >> .env
DBHOST=your_db_host
DBUSER=your_db_user
DBPASSWORD=your_db_password
DBDATABASE=your_db_name
SENDGRID_API_KEY=your_sendgrid_api_key
jwtSecret=your_jwt_secret
allowedports=80,443
emailbearer=your_email_bearer
EOT

# Luodaan systemd-palveluyksikkötiedosto
sudo bash -c 'cat <<EOT > /etc/systemd/system/gatekeeper.service
[Unit]
Description=My Node.js App
After=network.target

[Service]
EnvironmentFile=/opt/gatekeeper/.env
ExecStart=/usr/bin/pm2 start /opt/gatekeeper/index.mjs --watch --env-file /opt/gatekeeper/.env --name gatekeeper
ExecReload=/usr/bin/pm2 reload all
ExecStop=/usr/bin/pm2 stop all
Restart=always
User=nobody
Group=nogroup
Environment=PATH=/usr/bin:/usr/local/bin
Environment=NODE_ENV=production
WorkingDirectory=/opt/gatekeeper

[Install]
WantedBy=multi-user.target
EOT'

# Käynnistetään palvelu ja asetetaan se käynnistymään automaattisesti
sudo systemctl daemon-reload
sudo systemctl start gatekeeper
sudo systemctl enable gatekeeper

echo "Asennus valmis ja palvelu käynnissä!"
