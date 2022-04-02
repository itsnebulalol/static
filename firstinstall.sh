#!/bin/bash

# Upgrades and installs nessasary tools
# Run with "curl https://static.itsnebula.net/firstinstall.sh | bash"

apt update
apt upgrade -y
apt install sudo git curl wget -y

while true; do
    read -p "Do you want to install Docker? (Y/N)" yn
    case $yn in
        [Yy]* ) curl https://get.docker.com | bash; break;;
        [Nn]* ) exit;;
        * ) echo "Please answer Y or N.";;
    esac
done

while true; do
    read -p "Do you want to install Docker Compose v2? (Y/N)" yn2
    case $yn2 in
        [Yy]* ) curl https://static.itsnebula.net/compose.sh | bash; break;;
        [Nn]* ) exit;;
        * ) echo "Please answer Y or N.";;
    esac
done
