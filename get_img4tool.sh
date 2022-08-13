echo "img4tool downloader -- Originally from Deverser"
echo ""

if command -v img4tool >/dev/null; then
    echo "[!] img4tool is already installed at $(command -v img4tool)!"
    exit
else
    echo "[#] img4tool is not installed, do you want to download and install img4tool? (If no then the script will close, img4tool is needed)"
    echo "[*] Please enter 'Yes' or 'No':"
    read -r consent
    case $consent in
        [Yy]* )
            
            if which curl >/dev/null; then
                echo "[i] curl is installed!"
            else
                echo "[!] curl is required for this script to download img4tool."
                exit 2
            fi
            
            echo "[!] Downloading latest img4tool from tihmstar's repo..."
            
            latestBuild=$(curl --silent "https://api.github.com/repos/tihmstar/img4tool/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')
            link="https://github.com/tihmstar/img4tool/releases/download/${latestBuild}/buildroot_${OS}-latest.zip"
            curl -sLO "$link"
            IMG4TOOL_TEMP=$(mktemp -d 'img4tool.XXXXXXX')
            unzip -q img4tool-latest.zip -d "$IMG4TOOL_TEMP"
            echo "[*] Terminal may ask for permission to move the files into '/usr/local/bin' and '/usr/local/include', please enter your password if it does"
            sudo install -m755 "$IMG4TOOL_TEMP/buildroot_$OS-latest/usr/local/bin/img4tool" /usr/local/bin/img4tool
            sudo cp -R "$IMG4TOOL_TEMP/buildroot_$OS-latest/usr/local/include/img4tool" /usr/local/include
            if command -v img4tool >/dev/null; then
                echo "[!] img4tool is installed at $(command -v img4tool)!"
            fi
            rm -rf img4tool-latest.zip "$IMG4TOOL_TEMP"
        ;;
        * )
            echo "[#] img4tool was not installed"
            echo "[#] If you want to manually install it, you can download img4tool from 'https://github.com/tihmstar/img4tool/releases/latest' and manually move the files to the correct locations"
            exit
        ;;
    esac
fi
