#!/bin/bash

# stop and disable the service
sudo systemctl stop gatekeeper
sudo systemctl disable gatekeeper

# remove systemd service file
sudo rm /etc/systemd/system/gatekeeper.service

# load systemd after removing the service file
sudo systemctl daemon-reload

# Remove the app code and related files
sudo rm -rf /opt/gatekeeper

echo "Service and related files are removed."
