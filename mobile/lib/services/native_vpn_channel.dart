import 'dart:async';
import 'dart:io';

import 'package:flutter/services.dart';
import 'package:openvpn_flutter/openvpn_flutter.dart';
import 'package:path_provider/path_provider.dart';
import 'package:share_plus/share_plus.dart';

import '../models/vpn_models.dart';

/// Unified native OS VPN driver facade bridging Dart `TunnelController` to:
/// - Android `VpnGateVpnService` (pure-Rust user-space `IKEv1 + ESPinUDP + L2TPv2 + PPP/IPCP`)
/// - Android `ics-openvpn` (`openvpn_flutter`) for `OpenVPN UDP` & `OpenVPN TCP`
/// - iOS `NETunnelProviderManager` (`PacketTunnelProvider`) for `OpenVPN UDP/TCP` + `.mobileconfig` L2TP export.
class NativeVpnChannel {
  NativeVpnChannel({
    required this.onStageText,
    required this.onTrafficStats,
    required this.onNativeDisconnect,
  });

  static const MethodChannel _channel = MethodChannel(
    'org.vpngate.connect/vpn',
  );

  final void Function(String stageLabel) onStageText;
  final void Function(int txBytes, int rxBytes) onTrafficStats;
  final void Function() onNativeDisconnect;

  OpenVPN? _androidOvpn;
  VPNStage _ovpnStage = VPNStage.disconnected;
  Completer<bool>? _ovpnConnectCompleter;
  String? _activeDriver; // 'userspace_l2tp' | 'android_ovpn' | 'ios_tunnel'

  Future<void> initialize() async {
    _channel.setMethodCallHandler((call) async {
      if (call.method == 'onNativeVpnRevoked' ||
          call.method == 'onNativeVpnDisconnected') {
        _activeDriver = null;
        onNativeDisconnect();
      }
      return null;
    });

    if (Platform.isAndroid) {
      _androidOvpn = OpenVPN(
        onVpnStatusChanged: (VpnStatus? status) {
          if (status == null) return;
          final tx = int.tryParse(status.byteOut ?? '0') ?? 0;
          final rx = int.tryParse(status.byteIn ?? '0') ?? 0;
          onTrafficStats(tx, rx);
        },
        onVpnStageChanged: (VPNStage stage, String rawStage) {
          _ovpnStage = stage;
          onStageText('OpenVPN: ${stage.name}');
          if (stage == VPNStage.connected) {
            if (_ovpnConnectCompleter != null &&
                !_ovpnConnectCompleter!.isCompleted) {
              _ovpnConnectCompleter!.complete(true);
            }
          } else if (stage == VPNStage.error ||
              stage == VPNStage.denied ||
              stage == VPNStage.disconnected) {
            if (_ovpnConnectCompleter != null &&
                !_ovpnConnectCompleter!.isCompleted) {
              _ovpnConnectCompleter!.complete(false);
            } else if (_activeDriver == 'android_ovpn' &&
                stage == VPNStage.disconnected) {
              _activeDriver = null;
              onNativeDisconnect();
            }
          }
        },
      );
      await _androidOvpn!.initialize(
        groupIdentifier: 'group.org.vpngate.connect',
        providerBundleIdentifier: 'org.vpngate.connect.PacketTunnel',
        localizedDescription: 'VPN Gate Connect',
      );
    }
  }

  /// Engages a prepared candidate (`l2tp`, `udp`, or `tcp`) with strict timeout.
  Future<Map<String, String>> connectPrepared(
    PreparedAttemptModel prep, {
    int timeoutSecs = 22,
  }) async {
    await disconnect();

    if (prep.protocol == 'l2tp') {
      if (!Platform.isAndroid) {
        throw UnsupportedError(
          'In-app user-space L2TP TUN requires Android VpnService; use Export .mobileconfig on iOS.',
        );
      }
      onStageText(
        'Negotiating IKEv1 + ESPinUDP + L2TP/PPP (${prep.server.ip})...',
      );
      final res = await _channel.invokeMapMethod<String, dynamic>(
        'startUserspaceL2tp',
        <String, dynamic>{
          'serverIp': prep.server.ip,
          'countryShort': prep.server.countryShort,
          'countryLong': prep.server.countryLong,
          'dnsServers': prep.dnsServers.join(','),
          'timeoutSecs': timeoutSecs,
        },
      );
      if (res == null || res['ok'] != true) {
        throw Exception(
          (res?['error'] as String?) ?? 'Android VpnService L2TP failed',
        );
      }
      _activeDriver = 'userspace_l2tp';
      return <String, String>{
        'assignedIp': (res['assignedIp'] as String?) ?? '',
        'cipher': (res['espCipher'] as String?) ?? 'aes256',
      };
    }

    // OpenVPN UDP / TCP
    final ovpnText = prep.ovpnConfig;
    if (ovpnText == null || ovpnText.trim().isEmpty) {
      throw Exception('Missing patched .ovpn payload for ${prep.server.ip}');
    }

    if (Platform.isAndroid) {
      final engine = _androidOvpn;
      if (engine == null) {
        throw StateError('Android OpenVPN engine not initialized');
      }
      _ovpnConnectCompleter = Completer<bool>();
      _activeDriver = 'android_ovpn';
      engine.connect(
        ovpnText,
        'VPN Gate ${prep.server.countryShort} (${prep.server.ip})',
        username: 'vpn',
        password: 'vpn',
        certIsRequired: false,
      );
      final connected = await _ovpnConnectCompleter!.future.timeout(
        Duration(seconds: timeoutSecs),
        onTimeout: () => false,
      );
      _ovpnConnectCompleter = null;
      if (!connected || _ovpnStage != VPNStage.connected) {
        engine.disconnect();
        _activeDriver = null;
        throw Exception(
          'OpenVPN ${prep.protocol.toUpperCase()} handshake timed out on ${prep.server.ip}:${prep.endpointPort}',
        );
      }
      return <String, String>{
        'assignedIp': '',
        'cipher': 'AES-GCM/CBC',
      };
    }

    if (Platform.isIOS) {
      onStageText(
        'Starting iOS NEPacketTunnelProvider (${prep.protocol.toUpperCase()} ${prep.server.ip}:${prep.endpointPort})...',
      );
      final res = await _channel.invokeMapMethod<String, dynamic>(
        'startIosOpenVpn',
        <String, dynamic>{
          'ovpnConfig': ovpnText,
          'serverIp': prep.server.ip,
          'port': prep.endpointPort,
          'protocol': prep.protocol,
          'countryShort': prep.server.countryShort,
          'dnsServers': prep.dnsServers,
          'timeoutSecs': timeoutSecs,
        },
      );
      if (res == null || res['ok'] != true) {
        throw Exception(
          (res?['error'] as String?) ??
              'iOS NEPacketTunnelProvider connection failed',
        );
      }
      _activeDriver = 'ios_tunnel';
      return <String, String>{
        'assignedIp': (res['assignedIp'] as String?) ?? '',
        'cipher': 'AES-GCM/CBC',
      };
    }

    throw UnsupportedError('Mobile VPN driver requires Android or iOS');
  }

  /// Tears down whichever tunnel engine is currently active.
  Future<void> disconnect() async {
    final drv = _activeDriver;
    _activeDriver = null;
    if (drv == 'userspace_l2tp' || Platform.isAndroid) {
      try {
        await _channel.invokeMethod<void>('stopUserspaceL2tp');
      } catch (_) {}
      try {
        _androidOvpn?.disconnect();
      } catch (_) {}
    }
    if (drv == 'ios_tunnel' || Platform.isIOS) {
      try {
        await _channel.invokeMethod<void>('stopIosOpenVpn');
      } catch (_) {}
    }
  }

  /// Exports and opens the Apple `.mobileconfig` L2TP/IPsec (`PSK = "vpn"`) profile installer sheet.
  Future<void> exportAppleL2tpMobileconfig(
    VpnServerModel server,
    String xmlContent,
  ) async {
    final tmpDir = await getTemporaryDirectory();
    final safeCountry = server.countryShort.toLowerCase();
    final safeIp = server.ip.replaceAll('.', '-');
    final file = File('${tmpDir.path}/vpngate-$safeCountry-$safeIp.mobileconfig');
    await file.writeAsString(xmlContent, flush: true);
    await Share.shareXFiles(
      <XFile>[
        XFile(
          file.path,
          mimeType: 'application/x-apple-aspen-config',
          name: 'vpngate-$safeCountry-$safeIp.mobileconfig',
        ),
      ],
      subject: 'VPN Gate L2TP/IPsec (${server.countryLong} — ${server.ip})',
    );
  }
}
