#!/bin/bash

# Upgrades and installs nessasary tools
# Run with "curl https://static.itsnebula.net/firstinstall.sh | bash"

apt update
apt upgrade -y
apt install sudo git curl wget -y

while true
do
      read -r -p "Do you want to install Docker? [Y/n] " input
 
      case $input in
            [yY][eE][sS]|[yY])
                  curl https://get.docker.com | bash
                  break
                  ;;
            [nN][oO]|[nN])
                  break
                  ;;
            *)
                  echo "Please answer Y or N."
                  ;;
      esac      
done

while true
do
      read -r -p "Do you want to install Docker Compose v2? [Y/n] " input
 
      case $input in
            [yY][eE][sS]|[yY])
                  curl https://static.itsnebula.net/compose.sh | bash
                  break
                  ;;
            [nN][oO]|[nN])
                  break
                  ;;
            *)
                  echo "Please answer Y or N."
                  ;;
      esac      
done
