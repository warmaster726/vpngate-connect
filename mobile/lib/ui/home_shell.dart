import 'dart:io';

import 'package:flutter/material.dart';

import '../controllers/tunnel_controller.dart';
import '../models/vpn_models.dart';

const Color kBgObsidian = Color(0xFF0A0F1A);
const Color kCardSlate = Color(0xFF131C2E);
const Color kBorderSubtle = Color(0xFF22304A);
const Color kAccentCyan = Color(0xFF38BDF8);
const Color kEmeraldUp = Color(0xFF10B981);
const Color kAmberWarn = Color(0xFFF59E0B);
const Color kCoralErr = Color(0xFFF43F5E);

String _formatBytes(int bytes) {
  if (bytes < 1024) return '$bytes B';
  if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
  if (bytes < 1024 * 1024 * 1024) {
    return '${(bytes / (1024 * 1024)).toStringAsFixed(2)} MB';
  }
  return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
}

String _formatDuration(Duration d) {
  final h = d.inHours.toString().padLeft(2, '0');
  final m = (d.inMinutes % 60).toString().padLeft(2, '0');
  final s = (d.inSeconds % 60).toString().padLeft(2, '0');
  return '$h:$m:$s';
}

class HomeShell extends StatefulWidget {
  const HomeShell({super.key, required this.controller});
  final TunnelController controller;

  @override
  State<HomeShell> createState() => _HomeShellState();
}

class _HomeShellState extends State<HomeShell> {
  int _tabIndex = 0;
  String _relaySearch = '';
  final TextEditingController _mirrorInputCtrl = TextEditingController();
  late final TextEditingController _dnsCtrl;

  @override
  void initState() {
    super.initState();
    _dnsCtrl = TextEditingController(text: widget.controller.dnsInput);
  }

  @override
  void dispose() {
    _mirrorInputCtrl.dispose();
    _dnsCtrl.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return ListenableBuilder(
      listenable: widget.controller,
      builder: (context, _) {
        final c = widget.controller;
        return Scaffold(
          backgroundColor: kBgObsidian,
          appBar: AppBar(
            backgroundColor: kBgObsidian,
            surfaceTintColor: Colors.transparent,
            title: Row(
              children: <Widget>[
                Icon(
                  c.isConnected ? Icons.verified_user : Icons.shield_outlined,
                  color: c.isConnected ? kEmeraldUp : kAccentCyan,
                  size: 22,
                ),
                const SizedBox(width: 10),
                const Text(
                  'VPNGate Connect',
                  style: TextStyle(
                    fontWeight: FontWeight.w700,
                    fontSize: 18,
                    letterSpacing: 0.3,
                  ),
                ),
              ],
            ),
            actions: <Widget>[
              if (c.watchdogEnabled)
                const Padding(
                  padding: EdgeInsets.only(right: 6),
                  child: Chip(
                    visualDensity: VisualDensity.compact,
                    backgroundColor: Color(0xFF0E2923),
                    side: BorderSide(color: kEmeraldUp, width: 0.8),
                    label: Text(
                      '15s Watchdog',
                      style: TextStyle(fontSize: 11, color: kEmeraldUp),
                    ),
                  ),
                ),
              IconButton(
                tooltip: 'Refresh Server Pool',
                onPressed: c.isBusy
                    ? null
                    : () => c.refreshServers(forceRefresh: true),
                icon: const Icon(Icons.refresh_rounded),
              ),
            ],
          ),
          body: IndexedStack(
            index: _tabIndex,
            children: <Widget>[
              _buildConnectTab(c),
              _buildRelaysTab(c),
              _buildMirrorsTab(c),
              _buildSettingsTab(c),
            ],
          ),
          bottomNavigationBar: NavigationBar(
            selectedIndex: _tabIndex,
            backgroundColor: kCardSlate,
            indicatorColor: kAccentCyan.withValues(alpha: 0.18),
            onDestinationSelected: (idx) => setState(() => _tabIndex = idx),
            destinations: <NavigationDestination>[
              const NavigationDestination(
                icon: Icon(Icons.power_settings_new_rounded),
                label: 'Connect',
              ),
              NavigationDestination(
                icon: Badge(
                  isLabelVisible: c.servers.isNotEmpty,
                  label: Text('${c.servers.length}'),
                  child: const Icon(Icons.dns_rounded),
                ),
                label: 'Relays',
              ),
              NavigationDestination(
                icon: Badge(
                  isLabelVisible: c.cachedMirrors.isNotEmpty,
                  label: Text('${c.cachedMirrors.length}'),
                  child: const Icon(Icons.hub_rounded),
                ),
                label: 'Mirrors',
              ),
              const NavigationDestination(
                icon: Icon(Icons.tune_rounded),
                label: 'Doctor',
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildConnectTab(TunnelController c) {
    final ringColor = switch (c.stage) {
      TunnelStage.connected => kEmeraldUp,
      TunnelStage.connecting ||
      TunnelStage.reconnecting ||
      TunnelStage.discovering =>
        kAmberWarn,
      TunnelStage.error => kCoralErr,
      TunnelStage.disconnected => kAccentCyan,
    };

    return ListView(
      padding: const EdgeInsets.fromLTRB(16, 12, 16, 28),
      children: <Widget>[
        // Hero Connect Card
        Container(
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: kCardSlate,
            borderRadius: BorderRadius.circular(20),
            border: Border.all(color: ringColor.withValues(alpha: 0.45)),
            boxShadow: <BoxShadow>[
              BoxShadow(
                color: ringColor.withValues(alpha: 0.12),
                blurRadius: 24,
                spreadRadius: 2,
              ),
            ],
          ),
          child: Column(
            children: <Widget>[
              GestureDetector(
                onTap: () {
                  if (c.isConnected || c.isBusy) {
                    c.disconnect();
                  } else {
                    c.connect();
                  }
                },
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 280),
                  width: 118,
                  height: 118,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: ringColor.withValues(alpha: 0.14),
                    border: Border.all(color: ringColor, width: 3),
                  ),
                  child: Center(
                    child: c.isBusy
                        ? CircularProgressIndicator(
                            color: ringColor,
                            strokeWidth: 3,
                          )
                        : Icon(
                            c.isConnected
                                ? Icons.lock_rounded
                                : Icons.power_settings_new_rounded,
                            size: 48,
                            color: ringColor,
                          ),
                  ),
                ),
              ),
              const SizedBox(height: 14),
              Text(
                switch (c.stage) {
                  TunnelStage.connected => 'TUNNEL PROTECTED',
                  TunnelStage.connecting => 'CONNECTING (AUTO FAILOVER)...',
                  TunnelStage.reconnecting => 'WATCHDOG RECONNECTING...',
                  TunnelStage.discovering => 'DISCOVERING RELAYS...',
                  TunnelStage.error => 'CONNECTION FAILED',
                  TunnelStage.disconnected => 'DISCONNECTED',
                },
                style: TextStyle(
                  color: ringColor,
                  fontWeight: FontWeight.w800,
                  fontSize: 13,
                  letterSpacing: 1.1,
                ),
              ),
              const SizedBox(height: 6),
              Text(
                c.statusBanner,
                textAlign: TextAlign.center,
                style: const TextStyle(color: Colors.white70, fontSize: 13),
              ),
              const SizedBox(height: 16),
              SizedBox(
                width: double.infinity,
                child: FilledButton.icon(
                  style: FilledButton.styleFrom(
                    backgroundColor: c.isConnected || c.isBusy
                        ? kCoralErr
                        : kEmeraldUp,
                    foregroundColor: Colors.black,
                    padding: const EdgeInsets.symmetric(vertical: 13),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(12),
                    ),
                  ),
                  onPressed: () {
                    if (c.isConnected || c.isBusy) {
                      c.disconnect();
                    } else {
                      c.connect();
                    }
                  },
                  icon: Icon(
                    c.isConnected || c.isBusy
                        ? Icons.stop_circle_outlined
                        : Icons.bolt_rounded,
                  ),
                  label: Text(
                    c.isConnected
                        ? 'Disconnect Tunnel'
                        : (c.isBusy
                            ? 'Cancel Attempt'
                            : 'Quick Connect (${c.selectedProtocol.toUpperCase()})'),
                    style: const TextStyle(fontWeight: FontWeight.w700),
                  ),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 14),

        // Region + Protocol + Sort Controls
        Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: kCardSlate,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: kBorderSubtle),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              ListTile(
                contentPadding: EdgeInsets.zero,
                leading: Text(
                  c.selectedCountry.isEmpty
                      ? '🌐'
                      : countryFlagEmoji(c.selectedCountry),
                  style: const TextStyle(fontSize: 24),
                ),
                title: Text(
                  c.selectedCountry.isEmpty
                      ? 'All Regions (${c.totalPoolCount} relays)'
                      : 'Region: ${c.selectedCountry.toUpperCase()} (${c.servers.length} relays)',
                  style: const TextStyle(
                    fontWeight: FontWeight.w600,
                    fontSize: 14,
                  ),
                ),
                subtitle: const Text(
                  'Tap to filter by ISO country',
                  style: TextStyle(fontSize: 12, color: Colors.white54),
                ),
                trailing: const Icon(Icons.chevron_right_rounded),
                onTap: () => _showCountryPicker(context, c),
              ),
              const Divider(color: kBorderSubtle, height: 14),
              const Text(
                'PROTOCOL CASCADE',
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  color: Colors.white54,
                  letterSpacing: 0.9,
                ),
              ),
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                runSpacing: 8,
                children: <MapEntry<String, String>>[
                  const MapEntry('auto', 'Auto (L2TP → UDP → TCP)'),
                  const MapEntry('l2tp', 'L2TP/IPsec'),
                  const MapEntry('udp', 'OpenVPN UDP'),
                  const MapEntry('tcp', 'OpenVPN TCP'),
                ].map((entry) {
                  final active = c.selectedProtocol == entry.key;
                  return ChoiceChip(
                    label: Text(entry.value),
                    selected: active,
                    selectedColor: kAccentCyan.withValues(alpha: 0.24),
                    onSelected: (_) => c.updateFilters(protocol: entry.key),
                  );
                }).toList(),
              ),
              const SizedBox(height: 12),
              const Text(
                'RANKING STRATEGY',
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  color: Colors.white54,
                  letterSpacing: 0.9,
                ),
              ),
              const SizedBox(height: 8),
              Wrap(
                spacing: 8,
                children: <String>[
                  'recommended',
                  'speed',
                  'ping',
                  'score',
                ].map((sKey) {
                  return ChoiceChip(
                    label: Text(
                      sKey[0].toUpperCase() + sKey.substring(1),
                    ),
                    selected: c.selectedSort == sKey,
                    selectedColor: kAccentCyan.withValues(alpha: 0.24),
                    onSelected: (_) => c.updateFilters(sortBy: sKey),
                  );
                }).toList(),
              ),
            ],
          ),
        ),
        const SizedBox(height: 14),

        // Live Egress Telemetry Card
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: kCardSlate,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: kBorderSubtle),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              const Text(
                'LIVE EGRESS TELEMETRY',
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  color: Colors.white54,
                  letterSpacing: 0.9,
                ),
              ),
              const SizedBox(height: 10),
              Row(
                children: <Widget>[
                  Expanded(
                    child: _metricTile(
                      'Public IP',
                      c.egressIp.isEmpty ? '—' : c.egressIp,
                    ),
                  ),
                  Expanded(
                    child: _metricTile(
                      'Country',
                      c.egressCountry.isEmpty
                          ? '—'
                          : '${countryFlagEmoji(c.egressCountry)} ${c.egressCountry}',
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 10),
              Row(
                children: <Widget>[
                  Expanded(
                    child: _metricTile(
                      'Transport',
                      c.activeProtocol.isEmpty ? 'Direct' : c.activeProtocol,
                    ),
                  ),
                  Expanded(
                    child: _metricTile(
                      'Uptime',
                      c.isConnected ? _formatDuration(c.uptime) : '00:00:00',
                    ),
                  ),
                ],
              ),
              if (c.isConnected) ...<Widget>[
                const SizedBox(height: 10),
                Row(
                  children: <Widget>[
                    Expanded(
                      child: _metricTile('TX Sent', _formatBytes(c.txBytes)),
                    ),
                    Expanded(
                      child: _metricTile('RX Recv', _formatBytes(c.rxBytes)),
                    ),
                  ],
                ),
              ],
            ],
          ),
        ),
        const SizedBox(height: 14),

        // Live PY-Style Console Progress Feed
        Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: const Color(0xFF070B12),
            borderRadius: BorderRadius.circular(14),
            border: Border.all(color: kBorderSubtle),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: <Widget>[
                  const Text(
                    'LIVE ENGINE PROGRESS',
                    style: TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 11,
                      fontWeight: FontWeight.w700,
                      color: kAccentCyan,
                    ),
                  ),
                  TextButton(
                    onPressed: c.clearConsoleLogs,
                    child: const Text('Clear', style: TextStyle(fontSize: 12)),
                  ),
                ],
              ),
              if (c.transientProgressLine != null)
                Padding(
                  padding: const EdgeInsets.only(bottom: 6),
                  child: Text(
                    '[*] ${c.transientProgressLine!}',
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 12,
                      color: kAmberWarn,
                    ),
                  ),
                ),
              if (c.consoleLines.isEmpty && c.transientProgressLine == null)
                const Text(
                  '[*] Idle — ready for anti-censorship discovery or tunnel connect.',
                  style: TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                    color: Colors.white54,
                  ),
                )
              else
                ...c.consoleLines.reversed.take(10).map((ln) {
                  final color = ln.isWarning
                      ? kAmberWarn
                      : (ln.isSuccess ? kEmeraldUp : Colors.white70);
                  return Padding(
                    padding: const EdgeInsets.symmetric(vertical: 2),
                    child: Text(
                      '${ln.prefix} ${ln.message}',
                      style: TextStyle(
                        fontFamily: 'monospace',
                        fontSize: 11.5,
                        color: color,
                      ),
                    ),
                  );
                }),
            ],
          ),
        ),
      ],
    );
  }

  Widget _metricTile(String label, String value) {
    return Container(
      margin: const EdgeInsets.only(right: 8),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: kBgObsidian,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: kBorderSubtle),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: <Widget>[
          Text(
            label,
            style: const TextStyle(fontSize: 11, color: Colors.white54),
          ),
          const SizedBox(height: 3),
          Text(
            value,
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
            style: const TextStyle(
              fontFamily: 'monospace',
              fontWeight: FontWeight.w700,
              fontSize: 13,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildRelaysTab(TunnelController c) {
    final q = _relaySearch.trim().toLowerCase();
    final visible = q.isEmpty
        ? c.servers
        : c.servers.where((s) {
            return s.ip.contains(q) ||
                s.countryShort.toLowerCase().contains(q) ||
                s.countryLong.toLowerCase().contains(q) ||
                s.hostname.toLowerCase().contains(q);
          }).toList();

    return Column(
      children: <Widget>[
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 10, 16, 8),
          child: TextField(
            decoration: InputDecoration(
              hintText: 'Search country, ISO code, IP, or hostname...',
              prefixIcon: const Icon(Icons.search_rounded),
              filled: true,
              fillColor: kCardSlate,
              border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(12),
                borderSide: const BorderSide(color: kBorderSubtle),
              ),
            ),
            onChanged: (v) => setState(() => _relaySearch = v),
          ),
        ),
        Expanded(
          child: ListView.builder(
            padding: const EdgeInsets.fromLTRB(16, 4, 16, 20),
            itemCount: visible.length,
            itemBuilder: (context, idx) {
              final s = visible[idx];
              return Card(
                color: kCardSlate,
                margin: const EdgeInsets.only(bottom: 10),
                shape: RoundedRectangleBorder(
                  borderRadius: BorderRadius.circular(14),
                  side: const BorderSide(color: kBorderSubtle),
                ),
                child: Padding(
                  padding: const EdgeInsets.all(12),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      Row(
                        children: <Widget>[
                          Text(
                            countryFlagEmoji(s.countryShort),
                            style: const TextStyle(fontSize: 22),
                          ),
                          const SizedBox(width: 10),
                          Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: <Widget>[
                                Text(
                                  '${s.countryLong} (${s.countryShort})',
                                  style: const TextStyle(
                                    fontWeight: FontWeight.w700,
                                    fontSize: 14,
                                  ),
                                ),
                                Text(
                                  '${s.ip} • ${s.speedMbps.toStringAsFixed(1)} Mbps • ${s.pingMs} ms',
                                  style: const TextStyle(
                                    fontFamily: 'monospace',
                                    fontSize: 12,
                                    color: Colors.white70,
                                  ),
                                ),
                              ],
                            ),
                          ),
                          FilledButton.tonal(
                            onPressed: c.isBusy
                                ? null
                                : () {
                                    setState(() => _tabIndex = 0);
                                    c.connect(pinnedServer: s);
                                  },
                            child: const Text('Connect'),
                          ),
                        ],
                      ),
                      const SizedBox(height: 8),
                      Wrap(
                        spacing: 6,
                        runSpacing: 6,
                        children: <Widget>[
                          if (s.l2tp)
                            _protoBadge('L2TP PSK=vpn', kEmeraldUp),
                          if (s.supportsUdp)
                            _protoBadge(
                              'UDP:${s.udpPort > 0 ? s.udpPort : 1194}',
                              kAccentCyan,
                            ),
                          if (s.supportsTcp)
                            _protoBadge(
                              'TCP:${s.tcpPort > 0 ? s.tcpPort : 443}',
                              Colors.purpleAccent,
                            ),
                          if (s.l2tp && (Platform.isIOS || Platform.isMacOS))
                            ActionChip(
                              visualDensity: VisualDensity.compact,
                              avatar: const Icon(Icons.ios_share, size: 14),
                              label: const Text(
                                '.mobileconfig',
                                style: TextStyle(fontSize: 11),
                              ),
                              onPressed: () => c.exportIosL2tpProfile(s),
                            ),
                        ],
                      ),
                    ],
                  ),
                ),
              );
            },
          ),
        ),
      ],
    );
  }

  Widget _protoBadge(String text, Color color) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.14),
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: color.withValues(alpha: 0.5)),
      ),
      child: Text(
        text,
        style: TextStyle(
          fontFamily: 'monospace',
          fontSize: 11,
          fontWeight: FontWeight.w600,
          color: color,
        ),
      ),
    );
  }

  Widget _buildMirrorsTab(TunnelController c) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: <Widget>[
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: kCardSlate,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: kBorderSubtle),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              const Text(
                'Official VPN Gate Mirror Failover',
                style: TextStyle(fontWeight: FontWeight.w700, fontSize: 15),
              ),
              const SizedBox(height: 6),
              const Text(
                'Automatically harvests & caches live Official Mirror Sites (sites.aspx + daily mirror feeds + Cloudflare DoH) when primary vpngate.net is blocked.',
                style: TextStyle(fontSize: 12.5, color: Colors.white70),
              ),
              const SizedBox(height: 12),
              Row(
                children: <Widget>[
                  Expanded(
                    child: TextField(
                      controller: _mirrorInputCtrl,
                      decoration: InputDecoration(
                        hintText: 'http://host:port/en/',
                        isDense: true,
                        filled: true,
                        fillColor: kBgObsidian,
                        border: OutlineInputBorder(
                          borderRadius: BorderRadius.circular(10),
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  FilledButton(
                    onPressed: () {
                      c.addCustomMirror(_mirrorInputCtrl.text);
                      _mirrorInputCtrl.clear();
                    },
                    child: const Text('Add'),
                  ),
                ],
              ),
              if (c.customMirrorUrls.isNotEmpty) ...<Widget>[
                const SizedBox(height: 10),
                Wrap(
                  spacing: 6,
                  children: c.customMirrorUrls
                      .map(
                        (u) => InputChip(
                          label: Text(u, style: const TextStyle(fontSize: 11)),
                          onDeleted: () => c.removeCustomMirror(u),
                        ),
                      )
                      .toList(),
                ),
              ],
              const SizedBox(height: 12),
              SizedBox(
                width: double.infinity,
                child: FilledButton.icon(
                  onPressed: c.isProbingMirrors ? null : c.probeMirrors,
                  icon: c.isProbingMirrors
                      ? const SizedBox(
                          width: 16,
                          height: 16,
                          child: CircularProgressIndicator(strokeWidth: 2),
                        )
                      : const Icon(Icons.radar_rounded),
                  label: Text(
                    c.isProbingMirrors
                        ? 'Probing Official Mirrors...'
                        : 'Probe & Cache Official Mirror Sites',
                  ),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 14),
        if (c.mirrorProbes.isNotEmpty)
          ...c.mirrorProbes.map((mp) {
            final color = mp.reachable ? kEmeraldUp : kCoralErr;
            return Card(
              color: kCardSlate,
              margin: const EdgeInsets.only(bottom: 8),
              child: ListTile(
                leading: Icon(
                  mp.reachable ? Icons.check_circle : Icons.cancel,
                  color: color,
                ),
                title: Text(
                  mp.mirror.portalUrl,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12.5),
                ),
                subtitle: Text(
                  '${mp.mirror.location} • ${mp.mirror.source}',
                  style: const TextStyle(fontSize: 12),
                ),
                trailing: Text(
                  mp.reachable
                      ? '${mp.rttMs ?? 0} ms\n${mp.serversCount} relays'
                      : 'DOWN',
                  textAlign: TextAlign.right,
                  style: TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 11,
                    color: color,
                  ),
                ),
              ),
            );
          })
        else
          ...c.cachedMirrors.map(
            (m) => Card(
              color: kCardSlate,
              margin: const EdgeInsets.only(bottom: 8),
              child: ListTile(
                leading: const Icon(Icons.public, color: kAccentCyan),
                title: Text(
                  m.portalUrl,
                  style: const TextStyle(fontFamily: 'monospace', fontSize: 12.5),
                ),
                subtitle: Text('${m.location} (${m.source})'),
              ),
            ),
          ),
      ],
    );
  }

  Widget _buildSettingsTab(TunnelController c) {
    return ListView(
      padding: const EdgeInsets.all(16),
      children: <Widget>[
        Card(
          color: kCardSlate,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(16),
            side: const BorderSide(color: kBorderSubtle),
          ),
          child: Column(
            children: <Widget>[
              SwitchListTile(
                title: const Text('15-Second Auto-Reconnect Watchdog'),
                subtitle: const Text(
                  'Checks live tunnel egress via 1.1.1.1/cdn-cgi/trace every 15s and fails over automatically on drop',
                ),
                value: c.watchdogEnabled,
                onChanged: c.toggleWatchdog,
              ),
              const Divider(color: kBorderSubtle, height: 1),
              Padding(
                padding: const EdgeInsets.all(14),
                child: TextField(
                  controller: _dnsCtrl,
                  decoration: const InputDecoration(
                    labelText: 'Tunnel DNS Servers (IPv4 comma-separated)',
                    helperText: 'Default: Cloudflare 1.1.1.1, 1.0.0.1 (leak-protected)',
                  ),
                  onChanged: (v) => c.dnsInput = v,
                ),
              ),
              const Divider(color: kBorderSubtle, height: 1),
              ListTile(
                leading: const Icon(Icons.timer_off_outlined, color: kAmberWarn),
                title: Text('30-Minute Relay Cooldowns (${c.activeCooldowns} active)'),
                subtitle: const Text('Clear temporary penalties on dead or timed-out relays'),
                trailing: OutlinedButton(
                  onPressed: c.clearCooldowns,
                  child: const Text('Clear'),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 14),
        Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: kCardSlate,
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: kBorderSubtle),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: <Widget>[
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: <Widget>[
                  const Text(
                    'RUST ENGINE DOCTOR (vpngate-bridge)',
                    style: TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w700,
                      color: kAccentCyan,
                    ),
                  ),
                  TextButton.icon(
                    onPressed: c.runEngineDoctor,
                    icon: const Icon(Icons.medical_services_outlined, size: 16),
                    label: const Text('Re-test'),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              ...c.diagnostics.entries.map(
                (e) => Padding(
                  padding: const EdgeInsets.symmetric(vertical: 3),
                  child: Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: <Widget>[
                      SizedBox(
                        width: 155,
                        child: Text(
                          e.key,
                          style: const TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 12,
                            color: Colors.white54,
                          ),
                        ),
                      ),
                      Expanded(
                        child: Text(
                          '${e.value}',
                          style: const TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 12,
                            color: kEmeraldUp,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  void _showCountryPicker(BuildContext context, TunnelController c) {
    showModalBottomSheet<void>(
      context: context,
      backgroundColor: kCardSlate,
      isScrollControlled: true,
      builder: (ctx) {
        return DraggableScrollableSheet(
          expand: false,
          initialChildSize: 0.72,
          builder: (_, scrollCtrl) {
            return ListView(
              controller: scrollCtrl,
              children: <Widget>[
                ListTile(
                  leading: const Text('🌐', style: TextStyle(fontSize: 22)),
                  title: Text('All Countries (${c.totalPoolCount} relays)'),
                  trailing: c.selectedCountry.isEmpty
                      ? const Icon(Icons.check, color: kEmeraldUp)
                      : null,
                  onTap: () {
                    Navigator.pop(ctx);
                    c.updateFilters(country: '');
                  },
                ),
                const Divider(color: kBorderSubtle, height: 1),
                ...c.countries.map(
                  (cs) => ListTile(
                    leading: Text(
                      countryFlagEmoji(cs.countryShort),
                      style: const TextStyle(fontSize: 22),
                    ),
                    title: Text('${cs.countryLong} (${cs.countryShort})'),
                    subtitle: Text(
                      '${cs.totalServers} relays • L2TP:${cs.l2tpCount} UDP:${cs.openvpnUdpCount} TCP:${cs.openvpnTcpCount} • ${cs.maxSpeedMbps.toStringAsFixed(0)} Mbps',
                      style: const TextStyle(fontSize: 11.5),
                    ),
                    trailing: c.selectedCountry == cs.countryShort
                        ? const Icon(Icons.check, color: kEmeraldUp)
                        : null,
                    onTap: () {
                      Navigator.pop(ctx);
                      c.updateFilters(country: cs.countryShort);
                    },
                  ),
                ),
              ],
            );
          },
        );
      },
    );
  }
}
