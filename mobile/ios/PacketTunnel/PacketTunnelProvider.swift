import Foundation
import NetworkExtension
import OpenVPNAdapter

extension NEPacketTunnelFlow: OpenVPNAdapterPacketFlow {}

/// Lightweight `<15 MB` iOS `NEPacketTunnelProvider` running `MobileCore3`-patched OpenVPN UDP/TCP.
final class PacketTunnelProvider: NEPacketTunnelProvider {
    private lazy var vpnAdapter: OpenVPNAdapter = {
        let adapter = OpenVPNAdapter()
        adapter.delegate = self
        return adapter
    }()

    private var startHandler: ((Error?) -> Void)?
    private var stopHandler: (() -> Void)?
    private var dnsOverride: [String] = ["1.1.1.1", "1.0.0.1"]

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        guard
            let proto = protocolConfiguration as? NETunnelProviderProtocol,
            let conf = proto.providerConfiguration,
            let ovpnString = conf["ovpn"] as? String,
            let ovpnData = ovpnString.data(using: .utf8)
        else {
            completionHandler(
                NSError(
                    domain: "org.vpngate.connect.PacketTunnel",
                    code: 1,
                    userInfo: [NSLocalizedDescriptionKey: "Missing MobileCore3 .ovpn configuration"]
                )
            )
            return
        }

        if let customDns = conf["dns"] as? [String], !customDns.isEmpty {
            dnsOverride = customDns
        }

        let configuration = OpenVPNConfiguration()
        configuration.fileContent = ovpnData
        configuration.tunPersist = false

        let evaluation: OpenVPNConfigurationEvaluation
        do {
            evaluation = try vpnAdapter.apply(configuration: configuration)
        } catch {
            completionHandler(error)
            return
        }

        if !evaluation.autologin {
            let credentials = OpenVPNCredentials()
            credentials.username = "vpn"
            credentials.password = "vpn"
            do {
                try vpnAdapter.provide(credentials: credentials)
            } catch {
                completionHandler(error)
                return
            }
        }

        startHandler = completionHandler
        vpnAdapter.connect(using: packetFlow)
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        stopHandler = completionHandler
        vpnAdapter.disconnect()
    }
}

extension PacketTunnelProvider: OpenVPNAdapterDelegate {
    func openVPNAdapter(
        _ openVPNAdapter: OpenVPNAdapter,
        configureTunnelWithNetworkSettings networkSettings: NEPacketTunnelNetworkSettings?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        if let settings = networkSettings {
            let dnsSettings = NEDNSSettings(servers: dnsOverride)
            dnsSettings.matchDomains = [""]
            settings.dnsSettings = dnsSettings

            // Sinkhole IPv6 inside utun so dual-stack iOS carriers never leak IPv6 outside OpenVPN
            let ipv6 = NEIPv6Settings(addresses: ["fd00:7670:6e67::1"], networkPrefixLengths: [128])
            ipv6.includedRoutes = [NEIPv6Route.default()]
            settings.ipv6Settings = ipv6
        }
        setTunnelNetworkSettings(networkSettings, completionHandler: completionHandler)
    }

    func openVPNAdapter(_ openVPNAdapter: OpenVPNAdapter, handleEvent event: OpenVPNAdapterEvent, message: String?) {
        switch event {
        case .connected:
            startHandler?(nil)
            startHandler = nil
        case .disconnected:
            if let stop = stopHandler {
                stopHandler = nil
                stop()
            }
        default:
            break
        }
    }

    func openVPNAdapter(_ openVPNAdapter: OpenVPNAdapter, handleError error: Error) {
        if let start = startHandler {
            startHandler = nil
            start(error)
            return
        }
        cancelTunnelWithError(error)
    }
}
