#!/bin/bash

# Upgrades and installs nessasary tools
# Run with "curl https://static.itsnebula.net/firstinstall.sh | bash"
# THIS WILL INSTALL DOCKER - THE CHOICES ARE BROKEN

apt update
apt upgrade -y
apt install sudo git curl wget -y

echo "Do you want to install Docker? [y/N]> " 
read docker
if [[ $docker == y* ]]; then
    curl https://get.docker.com | bash
else
    echo Not installing Docker
    exit
fi

echo "Do you want to install Docker Compose v2? [y/N]> " 
read dockerco
if [[ $dockerco == y* ]]; then
    curl https://static.itsnebula.net/compose.sh | bash
else
    echo Not installing Docker Compose
    exit
fi
