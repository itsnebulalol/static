#!/bin/bash

# Upgrades and installs nessasary tools and installs docker
# Run with "curl https://static.itsnebula.net/firstinstall.sh | bash"

apt update
apt upgrade -y
apt install sudo git curl wget -y

curl https://get.docker.com | bash
curl https://static.itsnebula.net/compose.sh | bash
