import Flutter
import NetworkExtension
import UIKit

@main
@objc class AppDelegate: FlutterAppDelegate {
    private let channelName = "org.vpngate.connect/vpn"
    private let tunnelBundleId = "org.vpngate.connect.PacketTunnel"
    private var vpnChannel: FlutterMethodChannel?
    private var activeManager: NETunnelProviderManager?
    private var statusObserver: NSObjectProtocol?

    override func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]?
    ) -> Bool {
        GeneratedPluginRegistrant.register(with: self)

        if let controller = window?.rootViewController as? FlutterViewController {
            let ch = FlutterMethodChannel(
                name: channelName,
                binaryMessenger: controller.binaryMessenger
            )
            vpnChannel = ch
            ch.setMethodCallHandler { [weak self] call, result in
                guard let self = self else { return }
                switch call.method {
                case "startIosOpenVpn":
                    guard let args = call.arguments as? [String: Any] else {
                        result(["ok": false, "error": "Invalid iOS tunnel arguments"])
                        return
                    }
                    self.startPacketTunnel(args: args, result: result)
                case "stopIosOpenVpn":
                    self.activeManager?.connection.stopVPNTunnel()
                    result(nil)
                default:
                    result(FlutterMethodNotImplemented)
                }
            }
        }

        statusObserver = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] notif in
            guard
                let self = self,
                let session = notif.object as? NETunnelProviderSession
            else { return }
            if session.status == .disconnected || session.status == .invalid {
                self.vpnChannel?.invokeMethod("onNativeVpnDisconnected", arguments: nil)
            }
        }

        return super.application(application, didFinishLaunchingWithOptions: launchOptions)
    }

    private func startPacketTunnel(args: [String: Any], result: @escaping FlutterResult) {
        let ovpnConfig = (args["ovpnConfig"] as? String) ?? ""
        let serverIp = (args["serverIp"] as? String) ?? ""
        let countryShort = (args["countryShort"] as? String) ?? "VPN"
        let dnsServers = (args["dnsServers"] as? [String]) ?? ["1.1.1.1", "1.0.0.1"]
        let timeoutSecs = Double((args["timeoutSecs"] as? Int) ?? 22)

        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, loadErr in
            guard let self = self else { return }
            if let loadErr = loadErr {
                result(["ok": false, "error": "Failed loading VPN preferences: \(loadErr.localizedDescription)"])
                return
            }

            let manager = managers?.first ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = self.tunnelBundleId
            proto.serverAddress = serverIp
            proto.providerConfiguration = [
                "ovpn": ovpnConfig,
                "dns": dnsServers,
            ]
            proto.disconnectOnSleep = false

            manager.protocolConfiguration = proto
            manager.localizedDescription = "VPNGate Connect (\(countryShort))"
            manager.isEnabled = true

            manager.saveToPreferences { saveErr in
                if let saveErr = saveErr {
                    result(["ok": false, "error": "VPN preference save denied: \(saveErr.localizedDescription)"])
                    return
                }
                manager.loadFromPreferences { reloadErr in
                    if let reloadErr = reloadErr {
                        result(["ok": false, "error": "VPN preference reload error: \(reloadErr.localizedDescription)"])
                        return
                    }
                    self.activeManager = manager
                    do {
                        try manager.connection.startVPNTunnel()
                    } catch {
                        result(["ok": false, "error": "startVPNTunnel threw: \(error.localizedDescription)"])
                        return
                    }

                    self.waitForConnected(
                        connection: manager.connection,
                        timeoutSecs: timeoutSecs,
                        result: result
                    )
                }
            }
        }
    }

    private func waitForConnected(
        connection: NEVPNConnection,
        timeoutSecs: Double,
        result: @escaping FlutterResult
    ) {
        let deadline = Date().addingTimeInterval(timeoutSecs)
        Timer.scheduledTimer(withTimeInterval: 0.3, repeats: true) { timer in
            switch connection.status {
            case .connected:
                timer.invalidate()
                result(["ok": true, "assignedIp": ""])
            case .disconnected, .invalid:
                if Date() > deadline.addingTimeInterval(-timeoutSecs + 2.0) {
                    timer.invalidate()
                    result(["ok": false, "error": "iOS PacketTunnel disconnected during handshake"])
                }
            default:
                if Date() >= deadline {
                    timer.invalidate()
                    connection.stopVPNTunnel()
                    result(["ok": false, "error": "iOS PacketTunnel timed out after \(Int(timeoutSecs))s"])
                }
            }
        }
    }
}
