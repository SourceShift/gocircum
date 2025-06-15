# iOS Application

This directory will contain the source code for the AzadiConnect iOS application.

The application will be built using Xcode and will consume the Go library bindings from the `../bridge` directory.

## Key Components:
- **ContentView.swift**: The main screen with the Connect/Disconnect button, built with SwiftUI.
- **ContentViewModel.swift**: An `ObservableObject` that handles the UI logic and communicates with the Go bridge.
- **PacketTunnelProvider.swift**: A `NEPacketTunnelProvider` subclass that manages the system VPN configuration to route traffic through the local SOCKS5 proxy. 