// Immutable Dart models matching `crates/vpngate-bridge` JSON payloads 1-to-1.

enum TunnelStage {
  disconnected,
  discovering,
  connecting,
  connected,
  reconnecting,
  error,
}

class VpnServerModel {
  const VpnServerModel({
    required this.hostname,
    required this.ip,
    required this.score,
    required this.pingMs,
    required this.speedBps,
    required this.countryLong,
    required this.countryShort,
    required this.sessions,
    required this.uptimeMs,
    required this.operatorName,
    required this.l2tp,
    required this.openvpn,
    required this.tcpPort,
    required this.udpPort,
    required this.ovpnB64,
    required this.ovpnDlQuery,
  });

  factory VpnServerModel.fromJson(Map<String, dynamic> j) => VpnServerModel(
        hostname: (j['hostname'] as String?) ?? '',
        ip: (j['ip'] as String?) ?? '',
        score: (j['score'] as num?)?.toInt() ?? 0,
        pingMs: (j['ping_ms'] as num?)?.toInt() ?? 0,
        speedBps: (j['speed_bps'] as num?)?.toInt() ?? 0,
        countryLong: (j['country_long'] as String?) ?? 'Unknown',
        countryShort: (j['country_short'] as String?) ?? '??',
        sessions: (j['sessions'] as num?)?.toInt() ?? 0,
        uptimeMs: (j['uptime_ms'] as num?)?.toInt() ?? 0,
        operatorName: (j['operator'] as String?) ?? '',
        l2tp: (j['l2tp'] as bool?) ?? false,
        openvpn: (j['openvpn'] as bool?) ?? false,
        tcpPort: (j['tcp_port'] as num?)?.toInt() ?? 0,
        udpPort: (j['udp_port'] as num?)?.toInt() ?? 0,
        ovpnB64: (j['ovpn_b64'] as String?) ?? '',
        ovpnDlQuery: (j['ovpn_dl_query'] as String?) ?? '',
      );

  final String hostname;
  final String ip;
  final int score;
  final int pingMs;
  final int speedBps;
  final String countryLong;
  final String countryShort;
  final int sessions;
  final int uptimeMs;
  final String operatorName;
  final bool l2tp;
  final bool openvpn;
  final int tcpPort;
  final int udpPort;
  final String ovpnB64;
  final String ovpnDlQuery;

  double get speedMbps => speedBps / 1000000.0;

  bool get supportsUdp =>
      openvpn && (udpPort > 0 || (ovpnB64.isNotEmpty && tcpPort == 0));

  bool get supportsTcp =>
      openvpn && (tcpPort > 0 || (ovpnB64.isNotEmpty && udpPort == 0));

  Map<String, dynamic> toJson() => <String, dynamic>{
        'hostname': hostname,
        'ip': ip,
        'score': score,
        'ping_ms': pingMs,
        'speed_bps': speedBps,
        'country_long': countryLong,
        'country_short': countryShort,
        'sessions': sessions,
        'uptime_ms': uptimeMs,
        'operator': operatorName,
        'l2tp': l2tp,
        'openvpn': openvpn,
        'tcp_port': tcpPort,
        'udp_port': udpPort,
        'ovpn_b64': ovpnB64,
        'ovpn_dl_query': ovpnDlQuery,
      };
}

class CountrySummaryModel {
  const CountrySummaryModel({
    required this.countryShort,
    required this.countryLong,
    required this.totalServers,
    required this.l2tpCount,
    required this.openvpnUdpCount,
    required this.openvpnTcpCount,
    required this.maxSpeedBps,
    required this.bestPingMs,
  });

  factory CountrySummaryModel.fromJson(Map<String, dynamic> j) =>
      CountrySummaryModel(
        countryShort: (j['country_short'] as String?) ?? '??',
        countryLong: (j['country_long'] as String?) ?? 'Unknown',
        totalServers: (j['total_servers'] as num?)?.toInt() ?? 0,
        l2tpCount: (j['l2tp_count'] as num?)?.toInt() ?? 0,
        openvpnUdpCount: (j['openvpn_udp_count'] as num?)?.toInt() ?? 0,
        openvpnTcpCount: (j['openvpn_tcp_count'] as num?)?.toInt() ?? 0,
        maxSpeedBps: (j['max_speed_bps'] as num?)?.toInt() ?? 0,
        bestPingMs: (j['best_ping_ms'] as num?)?.toInt() ?? 9999,
      );

  final String countryShort;
  final String countryLong;
  final int totalServers;
  final int l2tpCount;
  final int openvpnUdpCount;
  final int openvpnTcpCount;
  final int maxSpeedBps;
  final int bestPingMs;

  double get maxSpeedMbps => maxSpeedBps / 1000000.0;
}

class OfficialMirrorModel {
  const OfficialMirrorModel({
    required this.baseUrl,
    required this.portalUrl,
    required this.location,
    required this.source,
  });

  factory OfficialMirrorModel.fromJson(Map<String, dynamic> j) =>
      OfficialMirrorModel(
        baseUrl: (j['base_url'] as String?) ?? '',
        portalUrl: (j['portal_url'] as String?) ?? '',
        location: (j['location'] as String?) ?? 'Mirror',
        source: (j['source'] as String?) ?? 'cached',
      );

  final String baseUrl;
  final String portalUrl;
  final String location;
  final String source;
}

class MirrorProbeModel {
  const MirrorProbeModel({
    required this.mirror,
    required this.reachable,
    required this.rttMs,
    required this.serversCount,
  });

  factory MirrorProbeModel.fromJson(Map<String, dynamic> j) => MirrorProbeModel(
        mirror: OfficialMirrorModel.fromJson(
          (j['mirror'] as Map<String, dynamic>?) ?? const <String, dynamic>{},
        ),
        reachable: (j['reachable'] as bool?) ?? false,
        rttMs: (j['rtt_ms'] as num?)?.toInt(),
        serversCount: (j['servers_count'] as num?)?.toInt() ?? 0,
      );

  final OfficialMirrorModel mirror;
  final bool reachable;
  final int? rttMs;
  final int serversCount;
}

class DiscoverPayloadModel {
  const DiscoverPayloadModel({
    required this.servers,
    required this.countries,
    required this.cachedMirrors,
    required this.totalPool,
    required this.cacheAgeSecs,
    required this.activeCooldowns,
    required this.watchdogEnabled,
  });

  factory DiscoverPayloadModel.fromJson(Map<String, dynamic> j) =>
      DiscoverPayloadModel(
        servers: ((j['servers'] as List<dynamic>?) ?? const <dynamic>[])
            .whereType<Map<String, dynamic>>()
            .map(VpnServerModel.fromJson)
            .toList(),
        countries: ((j['countries'] as List<dynamic>?) ?? const <dynamic>[])
            .whereType<Map<String, dynamic>>()
            .map(CountrySummaryModel.fromJson)
            .toList(),
        cachedMirrors:
            ((j['cached_mirrors'] as List<dynamic>?) ?? const <dynamic>[])
                .whereType<Map<String, dynamic>>()
                .map(OfficialMirrorModel.fromJson)
                .toList(),
        totalPool: (j['total_pool'] as num?)?.toInt() ?? 0,
        cacheAgeSecs: (j['cache_age_secs'] as num?)?.toInt(),
        activeCooldowns: (j['active_cooldowns'] as num?)?.toInt() ?? 0,
        watchdogEnabled: (j['watchdog_enabled'] as bool?) ?? false,
      );

  final List<VpnServerModel> servers;
  final List<CountrySummaryModel> countries;
  final List<OfficialMirrorModel> cachedMirrors;
  final int totalPool;
  final int? cacheAgeSecs;
  final int activeCooldowns;
  final bool watchdogEnabled;
}

class PlannedAttemptModel {
  const PlannedAttemptModel({
    required this.server,
    required this.protocol,
    required this.protocolLabel,
  });

  factory PlannedAttemptModel.fromJson(Map<String, dynamic> j) =>
      PlannedAttemptModel(
        server: VpnServerModel.fromJson(
          (j['server'] as Map<String, dynamic>?) ?? const <String, dynamic>{},
        ),
        protocol: (j['protocol'] as String?) ?? 'udp',
        protocolLabel: (j['protocol_label'] as String?) ?? 'OpenVPN UDP',
      );

  final VpnServerModel server;
  final String protocol;
  final String protocolLabel;
}

class PreparedAttemptModel {
  const PreparedAttemptModel({
    required this.server,
    required this.protocol,
    required this.endpointIp,
    required this.endpointPort,
    required this.dnsServers,
    required this.ovpnConfig,
    required this.appleMobileconfig,
  });

  factory PreparedAttemptModel.fromJson(Map<String, dynamic> j) =>
      PreparedAttemptModel(
        server: VpnServerModel.fromJson(
          (j['server'] as Map<String, dynamic>?) ?? const <String, dynamic>{},
        ),
        protocol: (j['protocol'] as String?) ?? 'udp',
        endpointIp: (j['endpoint_ip'] as String?) ?? '',
        endpointPort: (j['endpoint_port'] as num?)?.toInt() ?? 0,
        dnsServers: ((j['dns_servers'] as List<dynamic>?) ?? const <dynamic>[])
            .map((e) => e.toString())
            .toList(),
        ovpnConfig: j['ovpn_config'] as String?,
        appleMobileconfig: j['apple_mobileconfig'] as String?,
      );

  final VpnServerModel server;
  final String protocol;
  final String endpointIp;
  final int endpointPort;
  final List<String> dnsServers;
  final String? ovpnConfig;
  final String? appleMobileconfig;
}

class PublicIpTraceModel {
  const PublicIpTraceModel({required this.ip, required this.loc});

  factory PublicIpTraceModel.fromJson(Map<String, dynamic> j) =>
      PublicIpTraceModel(
        ip: (j['ip'] as String?) ?? '',
        loc: (j['loc'] as String?) ?? '??',
      );

  final String ip;
  final String loc;
}

class UserspaceL2tpStatsModel {
  const UserspaceL2tpStatsModel({
    required this.active,
    required this.serverIp,
    required this.assignedIp,
    required this.espCipher,
    required this.txBytes,
    required this.rxBytes,
    required this.error,
  });

  factory UserspaceL2tpStatsModel.fromJson(Map<String, dynamic> j) =>
      UserspaceL2tpStatsModel(
        active: (j['active'] as bool?) ?? false,
        serverIp: (j['server_ip'] as String?) ?? '',
        assignedIp: (j['assigned_ip'] as String?) ?? '',
        espCipher: (j['esp_cipher'] as String?) ?? '',
        txBytes: (j['tx_bytes'] as num?)?.toInt() ?? 0,
        rxBytes: (j['rx_bytes'] as num?)?.toInt() ?? 0,
        error: (j['error'] as String?) ?? '',
      );

  final bool active;
  final String serverIp;
  final String assignedIp;
  final String espCipher;
  final int txBytes;
  final int rxBytes;
  final String error;
}

class ConsoleProgressLine {
  const ConsoleProgressLine({
    required this.prefix,
    required this.message,
    required this.isWarning,
    required this.isSuccess,
  });

  final String prefix;
  final String message;
  final bool isWarning;
  final bool isSuccess;
}

/// Converts ISO-3166 alpha-2 code (`JP`, `KR`, `US`) to regional indicator flag emoji.
String countryFlagEmoji(String code) {
  final upper = code.trim().toUpperCase();
  if (upper.length != 2) return '🌐';
  final a = upper.codeUnitAt(0);
  final b = upper.codeUnitAt(1);
  if (a < 65 || a > 90 || b < 65 || b > 90) return '🌐';
  return String.fromCharCode(0x1F1E6 + (a - 65)) +
      String.fromCharCode(0x1F1E6 + (b - 65));
}
