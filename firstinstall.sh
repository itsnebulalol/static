#!/bin/bash

# Upgrades and installs nessasary tools
# Run with "curl https://static.itsnebula.net/firstinstall.sh | bash"

apt update
apt upgrade -y
apt install sudo git curl wget -y

read -r -p "Do you want to install Docker? [Y/n] " input
 
case $input in
      [yY][eE][sS]|[yY])
            curl https://get.docker.com | bash
            ;;
      [nN][oO]|[nN])
            exit
            ;;
      *)
            echo "Please answer Y or N."
            exit 1
            ;;
esac

read -r -p "Do you want to install Docker Compose v2? [Y/n] " input2
 
case $input2 in
      [yY][eE][sS]|[yY])
            curl https://static.itsnebula.net/compose.sh | bash
            ;;
      [nN][oO]|[nN])
            exit
            ;;
      *)
            echo "Please answer Y or N."
            exit 1
            ;;
esac
