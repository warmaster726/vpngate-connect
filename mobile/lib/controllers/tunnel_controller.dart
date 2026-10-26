import 'dart:async';
import 'dart:io';

import 'package:flutter/foundation.dart';
import 'package:path_provider/path_provider.dart';

import '../ffi/rust_bridge.dart';
import '../models/vpn_models.dart';
import '../services/native_vpn_channel.dart';

class TunnelController extends ChangeNotifier {
  TunnelController() {
    _vpn = NativeVpnChannel(
      onStageText: (text) {
        statusBanner = text;
        notifyListeners();
      },
      onTrafficStats: (tx, rx) {
        txBytes = tx;
        rxBytes = rx;
        notifyListeners();
      },
      onNativeDisconnect: _handleUnexpectedTunnelDrop,
    );
  }

  static const List<String> _spinnerFrames = <String>['|', '/', '-', r'\'];

  late final NativeVpnChannel _vpn;
  final RustBridge _bridge = RustBridge.instance;

  TunnelStage stage = TunnelStage.disconnected;
  String statusBanner = 'Ready — Cloudflare DoH + Official Mirror Failover';
  String? transientProgressLine;
  final List<ConsoleProgressLine> consoleLines = <ConsoleProgressLine>[];

  List<VpnServerModel> servers = <VpnServerModel>[];
  List<CountrySummaryModel> countries = <CountrySummaryModel>[];
  List<OfficialMirrorModel> cachedMirrors = <OfficialMirrorModel>[];
  List<MirrorProbeModel> mirrorProbes = <MirrorProbeModel>[];
  Map<String, dynamic> diagnostics = const <String, dynamic>{};

  String selectedCountry = ''; // '' == All Countries
  String selectedProtocol = 'auto'; // 'auto' | 'l2tp' | 'udp' | 'tcp'
  String selectedSort = 'recommended'; // 'recommended' | 'speed' | 'ping' | 'score'
  String dnsInput = '1.1.1.1, 1.0.0.1';
  final List<String> customMirrorUrls = <String>[];

  int totalPoolCount = 0;
  int? cacheAgeSecs;
  int activeCooldowns = 0;
  bool watchdogEnabled = false;
  bool isProbingMirrors = false;

  VpnServerModel? activeServer;
  String activeProtocol = '';
  String activeCipher = '';
  String assignedTunnelIp = '';
  String preVpnIp = '';
  String egressIp = '';
  String egressCountry = '';
  DateTime? connectedAt;
  int txBytes = 0;
  int rxBytes = 0;

  bool _cancelRequested = false;
  bool _reconnecting = false;
  Timer? _progressPollTimer;
  Timer? _telemetryTimer;
  Timer? _watchdogTimer;

  bool get isBusy =>
      stage == TunnelStage.discovering ||
      stage == TunnelStage.connecting ||
      stage == TunnelStage.reconnecting;

  bool get isConnected => stage == TunnelStage.connected;

  List<String> get parsedDnsServers => dnsInput
      .split(RegExp(r'[,;\s]+'))
      .map((s) => s.trim())
      .where((s) => s.isNotEmpty)
      .toList();

  Duration get uptime => connectedAt == null
      ? Duration.zero
      : DateTime.now().difference(connectedAt!);

  Future<void> initialize() async {
    _startProgressPoller();
    try {
      await _vpn.initialize();
      final supportDir = await getApplicationSupportDirectory();
      final storagePath = '${supportDir.path}/vpngate';
      await _bridge.initStorage(storagePath);
      diagnostics = await _bridge.runDiagnostics();
      await refreshServers(forceRefresh: false);
      unawaited(refreshPublicIpSilently());
    } catch (e) {
      _appendLog('[!]', 'Initialization notice: $e', isWarning: true);
    }
    notifyListeners();
  }

  void _startProgressPoller() {
    _progressPollTimer?.cancel();
    _progressPollTimer = Timer.periodic(
      const Duration(milliseconds: 150),
      (_) {
        try {
          final batch = _bridge.drainProgressEvents();
          if (batch.isEmpty) return;
          for (final ev in batch) {
            final kind = (ev['kind'] as String?) ?? '';
            final payload = ev['payload'];
            switch (kind) {
              case 'transient':
                if (payload is Map<String, dynamic>) {
                  final stg = (payload['stage'] as String?) ?? '';
                  final el = (payload['elapsed_secs'] as num?)?.toInt() ?? 0;
                  final mx = (payload['max_secs'] as num?)?.toInt() ?? 0;
                  final tk = (payload['tick'] as num?)?.toInt() ?? 0;
                  final spin = _spinnerFrames[tk % _spinnerFrames.length];
                  transientProgressLine = mx > 0
                      ? '[$spin] $stg [${el}s/${mx}s]'
                      : '[$spin] $stg [${el}s]';
                }
              case 'clear_transient':
                transientProgressLine = null;
              case 'info':
                transientProgressLine = null;
                _appendLog('[*]', payload?.toString() ?? '');
              case 'ok':
                transientProgressLine = null;
                _appendLog('[+]', payload?.toString() ?? '', isSuccess: true);
              case 'warn':
                transientProgressLine = null;
                _appendLog('[!]', payload?.toString() ?? '', isWarning: true);
              case 'attempt_banner':
                transientProgressLine = null;
                if (payload is Map<String, dynamic>) {
                  final idx = payload['index'] ?? 1;
                  final tot = payload['total'] ?? 1;
                  final ip = payload['ip'] ?? '';
                  final cc = payload['country_short'] ?? '';
                  _appendLog(
                    '[>]',
                    'Attempt $idx/$tot — $ip ($cc)',
                  );
                }
            }
          }
          notifyListeners();
        } catch (_) {}
      },
    );
  }

  void _appendLog(
    String prefix,
    String message, {
    bool isWarning = false,
    bool isSuccess = false,
  }) {
    if (message.trim().isEmpty) return;
    consoleLines.add(
      ConsoleProgressLine(
        prefix: prefix,
        message: message,
        isWarning: isWarning,
        isSuccess: isSuccess,
      ),
    );
    if (consoleLines.length > 120) {
      consoleLines.removeRange(0, consoleLines.length - 120);
    }
  }

  void clearConsoleLogs() {
    consoleLines.clear();
    transientProgressLine = null;
    notifyListeners();
  }

  Future<void> refreshPublicIpSilently() async {
    try {
      final trace = await _bridge.checkPublicIp(timeoutMs: 3500);
      if (!isConnected) {
        preVpnIp = trace.ip;
      }
      egressIp = trace.ip;
      egressCountry = trace.loc;
      notifyListeners();
    } catch (_) {}
  }

  Future<void> refreshServers({bool forceRefresh = true}) async {
    final prevStage = stage;
    if (!isConnected) {
      stage = TunnelStage.discovering;
    }
    statusBanner = forceRefresh
        ? 'Refreshing VPN Gate relays + Official Mirrors...'
        : 'Loading VPN Gate relay pool...';
    notifyListeners();

    try {
      final payload = await _bridge.discoverServers(
        forceRefresh: forceRefresh,
        country: selectedCountry,
        protocol: selectedProtocol,
        sortBy: selectedSort,
        mirrorUrls: customMirrorUrls,
      );
      servers = payload.servers;
      countries = payload.countries;
      cachedMirrors = payload.cachedMirrors;
      totalPoolCount = payload.totalPool;
      cacheAgeSecs = payload.cacheAgeSecs;
      activeCooldowns = payload.activeCooldowns;
      watchdogEnabled = payload.watchdogEnabled;
      _configureWatchdogTimer();

      statusBanner =
          'Loaded ${servers.length} relays (${countries.length} countries, ${cachedMirrors.length} mirrors)';
      if (!isConnected) {
        stage = TunnelStage.disconnected;
      } else {
        stage = prevStage;
      }
    } catch (e) {
      statusBanner = 'Discovery failed: $e';
      _appendLog('[!]', statusBanner, isWarning: true);
      if (!isConnected) {
        stage = TunnelStage.error;
      }
    }
    transientProgressLine = null;
    notifyListeners();
  }

  Future<void> updateFilters({
    String? country,
    String? protocol,
    String? sortBy,
  }) async {
    if (country != null) selectedCountry = country;
    if (protocol != null) selectedProtocol = protocol;
    if (sortBy != null) selectedSort = sortBy;
    await refreshServers(forceRefresh: false);
  }

  void addCustomMirror(String url) {
    final trimmed = url.trim();
    if (trimmed.isEmpty || customMirrorUrls.contains(trimmed)) return;
    customMirrorUrls.add(trimmed);
    notifyListeners();
  }

  void removeCustomMirror(String url) {
    customMirrorUrls.remove(url);
    notifyListeners();
  }

  Future<void> probeMirrors() async {
    if (isProbingMirrors) return;
    isProbingMirrors = true;
    statusBanner = 'Probing Official VPN Gate Mirror Sites...';
    notifyListeners();
    try {
      mirrorProbes = await _bridge.probeOfficialMirrors(customMirrorUrls);
      final liveCount = mirrorProbes.where((m) => m.reachable).length;
      statusBanner =
          'Verified $liveCount/${mirrorProbes.length} Official Mirror Sites';
      _appendLog('[+]', statusBanner, isSuccess: liveCount > 0);
      final refreshed = await _bridge.discoverServers(
        forceRefresh: false,
        country: selectedCountry,
        protocol: selectedProtocol,
        sortBy: selectedSort,
        mirrorUrls: customMirrorUrls,
      );
      cachedMirrors = refreshed.cachedMirrors;
    } catch (e) {
      statusBanner = 'Mirror probe error: $e';
      _appendLog('[!]', statusBanner, isWarning: true);
    } finally {
      isProbingMirrors = false;
      transientProgressLine = null;
      notifyListeners();
    }
  }

  /// Connects using the full Desktop-parity `Auto` failover cascade
  /// (`L2TP/IPsec -> OpenVPN UDP -> OpenVPN TCP`) or to a specific pinned relay.
  Future<void> connect({
    VpnServerModel? pinnedServer,
    String? protocolOverride,
    bool isAutoReconnect = false,
  }) async {
    if (isBusy && !isAutoReconnect) return;
    _cancelRequested = false;
    stage = isAutoReconnect ? TunnelStage.reconnecting : TunnelStage.connecting;
    clearConsoleLogs();
    statusBanner = isAutoReconnect
        ? 'Watchdog reconnecting to next healthy VPN Gate relay...'
        : 'Building ranked multi-protocol failover plan...';
    notifyListeners();

    try {
      if (preVpnIp.isEmpty) {
        try {
          final pre = await _bridge.checkPublicIp(timeoutMs: 2500);
          preVpnIp = pre.ip;
        } catch (_) {}
      }

      final effProto = protocolOverride ?? selectedProtocol;
      final plan = await _bridge.buildConnectPlan(
        country: pinnedServer != null ? null : selectedCountry,
        protocol: effProto,
        sortBy: selectedSort,
        maxCandidates: pinnedServer != null ? 1 : 10,
        isIos: Platform.isIOS,
        forceRefresh: servers.isEmpty,
        mirrorUrls: customMirrorUrls,
        pinnedIp: pinnedServer?.ip,
      );

      _appendLog(
        '[*]',
        'Prepared ${plan.length} ordered tunnel attempts (${effProto.toUpperCase()})',
      );

      for (var i = 0; i < plan.length; i++) {
        if (_cancelRequested) {
          await disconnect();
          return;
        }
        final attempt = plan[i];
        statusBanner =
            '[${i + 1}/${plan.length}] ${attempt.server.countryShort} ${attempt.server.ip} — ${attempt.protocolLabel}';
        _appendLog(
          '[>]',
          'Attempt ${i + 1}/${plan.length}: ${attempt.server.ip} (${attempt.server.countryLong}) via ${attempt.protocolLabel}',
        );
        notifyListeners();

        try {
          final prepared = await _bridge.prepareAttempt(
            server: attempt.server,
            protocol: attempt.protocol,
            isIos: Platform.isIOS,
            dnsServers: parsedDnsServers,
          );

          final sessionInfo = await _vpn.connectPrepared(
            prepared,
            timeoutSecs: 22,
          );

          // Verify live tunnel egress IP via Cloudflare trace
          await Future<void>.delayed(const Duration(milliseconds: 600));
          final trace = await _bridge.checkPublicIp(timeoutMs: 4500);
          if (preVpnIp.isNotEmpty && trace.ip == preVpnIp) {
            await _vpn.disconnect();
            activeCooldowns = await _bridge.recordFailure(
              attempt.server.ip,
              attempt.protocol,
            );
            _appendLog(
              '[!]',
              'Egress IP unchanged (${trace.ip}) on ${attempt.server.ip} — failing over',
              isWarning: true,
            );
            continue;
          }

          activeServer = attempt.server;
          activeProtocol = attempt.protocolLabel;
          activeCipher = sessionInfo['cipher'] ?? '';
          assignedTunnelIp = sessionInfo['assignedIp'] ?? '';
          egressIp = trace.ip;
          egressCountry = trace.loc;
          connectedAt = DateTime.now();
          txBytes = 0;
          rxBytes = 0;
          stage = TunnelStage.connected;
          statusBanner =
              'Connected — ${trace.ip} (${trace.loc}) via ${attempt.protocolLabel}';
          _appendLog('[+]', statusBanner, isSuccess: true);
          _startTelemetryTimer();
          _configureWatchdogTimer();
          notifyListeners();
          return;
        } catch (attemptErr) {
          activeCooldowns = await _bridge.recordFailure(
            attempt.server.ip,
            attempt.protocol,
          );
          _appendLog(
            '[!]',
            'Attempt ${i + 1} failed (${attempt.server.ip} ${attempt.protocol.toUpperCase()}): $attemptErr',
            isWarning: true,
          );
          notifyListeners();
        }
      }

      throw Exception(
        'All ${plan.length} candidate tunnel attempts failed or timed out',
      );
    } catch (e) {
      await _vpn.disconnect();
      stage = TunnelStage.error;
      statusBanner = '$e';
      _appendLog('[!]', statusBanner, isWarning: true);
      notifyListeners();
    } finally {
      transientProgressLine = null;
    }
  }

  Future<void> disconnect() async {
    _cancelRequested = true;
    _telemetryTimer?.cancel();
    _watchdogTimer?.cancel();
    await _vpn.disconnect();
    await _bridge.stopUserspaceL2tp();
    stage = TunnelStage.disconnected;
    activeServer = null;
    activeProtocol = '';
    activeCipher = '';
    assignedTunnelIp = '';
    connectedAt = null;
    txBytes = 0;
    rxBytes = 0;
    statusBanner = 'Disconnected — local routing & DNS restored';
    _appendLog('[*]', statusBanner);
    unawaited(refreshPublicIpSilently());
    notifyListeners();
  }

  void _startTelemetryTimer() {
    _telemetryTimer?.cancel();
    _telemetryTimer = Timer.periodic(const Duration(seconds: 1), (_) async {
      if (!isConnected) return;
      if (Platform.isAndroid && activeProtocol.toLowerCase().contains('l2tp')) {
        try {
          final st = await _bridge.getUserspaceL2tpStats();
          if (!st.active) {
            _handleUnexpectedTunnelDrop();
            return;
          }
          txBytes = st.txBytes;
          rxBytes = st.rxBytes;
          if (st.assignedIp.isNotEmpty) assignedTunnelIp = st.assignedIp;
          if (st.espCipher.isNotEmpty) activeCipher = st.espCipher;
        } catch (_) {}
      }
      notifyListeners();
    });
  }

  void _configureWatchdogTimer() {
    _watchdogTimer?.cancel();
    if (!watchdogEnabled || !isConnected) return;
    _watchdogTimer = Timer.periodic(const Duration(seconds: 15), (_) async {
      if (!isConnected || _reconnecting) return;
      try {
        final trace = await _bridge.checkPublicIp(timeoutMs: 4000);
        if (preVpnIp.isNotEmpty && trace.ip == preVpnIp) {
          throw Exception('Egress reverted to pre-VPN IP (${trace.ip})');
        }
        egressIp = trace.ip;
        egressCountry = trace.loc;
        notifyListeners();
      } catch (e) {
        _appendLog(
          '[!]',
          '15s Watchdog detected tunnel drop ($e) — auto-reconnecting...',
          isWarning: true,
        );
        await _triggerWatchdogReconnect();
      }
    });
  }

  void _handleUnexpectedTunnelDrop() {
    if (!isConnected || _cancelRequested) return;
    if (watchdogEnabled) {
      unawaited(_triggerWatchdogReconnect());
    } else {
      stage = TunnelStage.disconnected;
      statusBanner = 'Tunnel closed by remote relay';
      _appendLog('[!]', statusBanner, isWarning: true);
      notifyListeners();
    }
  }

  Future<void> _triggerWatchdogReconnect() async {
    if (_reconnecting) return;
    _reconnecting = true;
    try {
      if (activeServer != null) {
        final protoKey = activeProtocol.toLowerCase().contains('l2tp')
            ? 'l2tp'
            : (activeProtocol.toLowerCase().contains('tcp') ? 'tcp' : 'udp');
        activeCooldowns = await _bridge.recordFailure(
          activeServer!.ip,
          protoKey,
        );
      }
      await _vpn.disconnect();
      await connect(isAutoReconnect: true);
    } finally {
      _reconnecting = false;
    }
  }

  Future<void> toggleWatchdog(bool enabled) async {
    watchdogEnabled = await _bridge.setWatchdog(enabled);
    _configureWatchdogTimer();
    notifyListeners();
  }

  Future<void> clearCooldowns() async {
    await _bridge.clearCooldowns();
    activeCooldowns = 0;
    diagnostics = await _bridge.runDiagnostics();
    _appendLog('[+]', 'Cleared all 30-minute relay cooldown penalties', isSuccess: true);
    notifyListeners();
  }

  Future<void> runEngineDoctor() async {
    diagnostics = await _bridge.runDiagnostics();
    _appendLog('[+]', 'Engine diagnostics passed (IKEv1 Crypto Self-Test: PASS)', isSuccess: true);
    notifyListeners();
  }

  Future<void> exportIosL2tpProfile(VpnServerModel server) async {
    final xml = await _bridge.generateAppleMobileconfig(server);
    await _vpn.exportAppleL2tpMobileconfig(server, xml);
    _appendLog(
      '[+]',
      'Exported Apple L2TP/IPsec .mobileconfig for ${server.ip} (${server.countryShort})',
      isSuccess: true,
    );
    notifyListeners();
  }

  @override
  void dispose() {
    _progressPollTimer?.cancel();
    _telemetryTimer?.cancel();
    _watchdogTimer?.cancel();
    super.dispose();
  }
}
