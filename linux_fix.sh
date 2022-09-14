#!/usr/bin/env bash

# Futurerestore/irecovery linux fix script made by @Cryptiiiic
# Supported Distros: archlinux, ubuntu, debian

set -e
pacman=0
aptget=0

if [ "$EUID" -ne 0 ]
  then
  echo "[-] Please run as root"
  exit -1
fi

echo "[*] Attemping linux usb fixes, please wait..."

if [[ $(command -v pacman) ]]
then
    pacman=1
elif [[ $(command -v apt-get) ]]
then
    aptget=1
else
    echo "[-] -2: Linux Distro not supported!"
    exit -2
fi

if [[ "$(expr $pacman)" -gt '0' ]]
then
    sudo pacman -Syy --needed --noconfirm >/dev/null 2>/dev/null
    sudo pacman -S --needed --noconfirm udev usbmuxd >/dev/null 2>/dev/null 
    sudo systemctl enable systemd-udevd usbmuxd --now 2>/dev/null
    if [[ -f "/etc/arch-release" ]]
    then
        echo "[*] Arch Linux Detected!"
        echo "QUNUSU9OPT0iYWRkIiwgU1VCU1lTVEVNPT0idXNiIiwgQVRUUntpZFZlbmRvcn09PSIwNWFjIiwgQVRUUntpZFByb2R1Y3R9PT0iMTIyWzI3XXwxMjhbMC0zXSIsIE9XTkVSPSJyb290IiwgR1JPVVA9InN0b3JhZ2UiLCBNT0RFPSIwNjYwIgoKQUNUSU9OPT0iYWRkIiwgU1VCU1lTVEVNPT0idXNiIiwgQVRUUntpZFZlbmRvcn09PSIwNWFjIiwgQVRUUntpZFByb2R1Y3R9PT0iMTMzOCIsIE9XTkVSPSJyb290IiwgR1JPVVA9InN0b3JhZ2UiLCBNT0RFPSIwNjYwIgo=" | base64 -d | sudo tee /usr/lib/udev/rules.d/39-libirecovery.rules >/dev/null
    else
        echo "[-] -3: Linux Distro not supported!"
        exit -3
    fi
else
    sudo apt-get update -qq >/dev/null 2>/dev/null
    sudo apt-get install -yqq usbmuxd udev >/dev/null 2>/dev/null
    sudo systemctl enable udev >/dev/null 2>/dev/null || true
    sudo systemctl enable systemd-udevd >/dev/null 2>/dev/null || true
    sudo systemctl enable usbmuxd >/dev/null 2>/dev/null || true
    sudo systemctl restart udev >/dev/null 2>/dev/null
    sudo systemctl restart systemd-udevd >/dev/null 2>/dev/null
    sudo systemctl restart usbmuxd >/dev/null 2>/dev/null
    if [[ -f "/etc/lsb-release" || -f "/etc/debian_version" ]]
    then
        echo "[*] Debian based distro detected!"
        echo "QUNUSU9OPT0iYWRkIiwgU1VCU1lTVEVNPT0idXNiIiwgQVRUUntpZFZlbmRvcn09PSIwNWFjIiwgQVRUUntpZFByb2R1Y3R9PT0iMTIyWzI3XXwxMjhbMC0zXSIsIE9XTkVSPSJ1c2JtdXgiLCBHUk9VUD0icGx1Z2RldiIsIE1PREU9IjA2NjAiCgpBQ1RJT049PSJhZGQiLCBTVUJTWVNURU09PSJ1c2IiLCBBVFRSe2lkVmVuZG9yfT09IjA1YWMiLCBBVFRSe2lkUHJvZHVjdH09PSIxMzM4IiwgT1dORVI9InVzYm11eCIsIEdST1VQPSJwbHVnZGV2IiwgTU9ERT0iMDY2MCIKCg==" | base64 -d | sudo tee /usr/lib/udev/rules.d/39-libirecovery.rules >/dev/null
    else
        echo "[-] -4: Linux Distro not supported!"
        exit -4
    fi
fi

sudo chown root:root /usr/lib/udev/rules.d/39-libirecovery.rules >/dev/null 2>/dev/null 
sudo chmod 0644 /usr/lib/udev/rules.d/39-libirecovery.rules >/dev/null 2>/dev/null 
sudo udevadm control --reload-rules >/dev/null 2>/dev/null 

echo ""
echo "[*] Done!"
echo "[*] Please unplug and replug your iDevice!"
