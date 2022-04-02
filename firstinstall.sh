#!/bin/bash

# Upgrades and installs nessasary tools
# Run with "curl https://static.itsnebula.net/firstinstall.sh | bash"

apt update
apt upgrade -y
apt install sudo git curl wget -y

[[ "$(read -e -p 'Do you want to install Docker? [y/N]> '; echo $REPLY)" == [Yy]* ]] && (curl https://get.docker.com | bash) || (echo Not installing Docker && exit)

[[ "$(read -e -p 'Do you want to install Docker Compose v2? [y/N]> '; echo $REPLY)" == [Yy]* ]] && (curl https://static.itsnebula.net/compose.sh | bash) || (echo Not installing Docker Compose && exit)
