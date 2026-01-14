# Network Scanner and Deauthenticator

This script is a simple tool for scanning a network to find devices and for sending deauthentication frames to a specific target.

## Features

-   **Network Scanning:** Performs an ARP scan to discover all devices on a given subnet.
-   **Deauthentication Attack:** Sends 802.11 deauthentication frames to a target device, disrupting its connection to the access point.

## Installation

1.  Clone the repository:
    ```bash
    git clone <https://github.com/goddamnittom/n3tw0rk_d3auth>
    cd <n3tw0rk_d3auth>
    ```

2.  Install the dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

To use the script, you need to run it with administrator/root privileges. You also need to know the name of your wireless interface.

1.  **Run the script:**
    ```bash
    sudo python network_scanner.py
    ```

2.  **Follow the prompts:**
    -   Enter the wireless interface to use (e.g., `wlan0mon`, `mon0`).
    -   The script will attempt to automatically detect your network's subnet. You can either accept it or enter a different one.
    -   Choose a target device from the list of discovered devices.
    -   Enter the MAC address (BSSID) of the access point (router).
    -   Specify the number of deauthentication frames to send.

## Disclaimer

This script is for educational purposes only. Do not use it on networks or devices you do not own or have permission to test. Unauthorized access to computer networks is illegal.
