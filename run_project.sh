#!/bin/bash
clear

while true; do
    echo "====================================================================="
    echo "               AVS Assessment Platform Control Panel"
    echo "====================================================================="
    echo ""
    echo "  [1] Start Secure Web Console Dashboard (HTTPS Local)"
    echo "  [2] Start Containerized Service (Docker Compose)"
    echo "  [3] Stop Containerized Service (Docker Down)"
    echo "  [4] Execute Headless Scanner CLI (cli.py)"
    echo "  [5] Exit"
    echo ""
    echo "====================================================================="
    read -p "Enter your choice (1-5): " choice

    case $choice in
        1)
            echo ""
            echo "[*] Verifying and installing requirements..."
            python3 -m pip install -r requirements.txt
            echo "[*] Starting local HTTPS web server on port 8080..."
            python3 report_viewer.py
            read -p "Press [Enter] to continue..."
            ;;
        2)
            echo ""
            echo "[*] Building and launching containerized AVS services..."
            docker-compose up --build
            read -p "Press [Enter] to continue..."
            ;;
        3)
            echo ""
            echo "[*] Stopping and removing containerized assets..."
            docker-compose down
            read -p "Press [Enter] to continue..."
            ;;
        4)
            echo ""
            read -p "Enter target hostname or IP address: " target
            read -p "Enter profile (quick/standard/deep/udp/hyper): " profile
            echo "[*] Running headless vulnerability scan against $target..."
            python3 cli.py -t "$target" --profile "$profile"
            read -p "Press [Enter] to continue..."
            ;;
        5)
            echo ""
            echo "Goodbye!"
            exit 0
            ;;
        *)
            echo "Invalid choice. Please select 1-5."
            sleep 1
            ;;
    esac
    clear
done
