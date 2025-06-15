# Android Application

This directory will contain the source code for the AzadiConnect Android application.

The application will be built using Android Studio and will consume the Go library bindings from the `../bridge` directory.

## Key Components:
- **MainActivity**: The main screen with the Connect/Disconnect button.
- **MainViewModel**: Handles the UI logic and communicates with the Go bridge.
- **VpnService**: Manages the device's VPN connection to route traffic through the local SOCKS5 proxy. 