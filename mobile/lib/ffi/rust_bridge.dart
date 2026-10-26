import 'dart:convert';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'package:ffi/ffi.dart';

import '../models/vpn_models.dart';

typedef _NativeJsonCall = Pointer<Utf8> Function(
  Pointer<Utf8> method,
  Pointer<Utf8> paramsJson,
);
typedef _DartJsonCall = Pointer<Utf8> Function(
  Pointer<Utf8> method,
  Pointer<Utf8> paramsJson,
);

typedef _NativeDrainProgress = Pointer<Utf8> Function();
typedef _DartDrainProgress = Pointer<Utf8> Function();

typedef _NativeFreeString = Void Function(Pointer<Utf8> ptr);
typedef _DartFreeString = void Function(Pointer<Utf8> ptr);

DynamicLibrary _openBridgeLibrary() {
  if (Platform.isIOS || Platform.isMacOS) {
    // Statically linked into Runner binary via -force_load libvpngate_bridge.a
    return DynamicLibrary.process();
  }
  if (Platform.isAndroid || Platform.isLinux) {
    return DynamicLibrary.open('libvpngate_bridge.so');
  }
  if (Platform.isWindows) {
    return DynamicLibrary.open('vpngate_bridge.dll');
  }
  throw UnsupportedError(
    'Unsupported host platform: ${Platform.operatingSystem}',
  );
}

/// Top-level synchronous FFI invocation safe to run inside `Isolate.run(...)`.
Map<String, dynamic> _invokeRustRpcSync(String method, String paramsJson) {
  final lib = _openBridgeLibrary();
  final callFn =
      lib.lookupFunction<_NativeJsonCall, _DartJsonCall>('vpngate_json_call');
  final freeFn = lib.lookupFunction<_NativeFreeString, _DartFreeString>(
    'vpngate_free_string',
  );

  final methodPtr = method.toNativeUtf8();
  final paramsPtr = paramsJson.toNativeUtf8();
  Pointer<Utf8> resPtr = nullptr;
  try {
    resPtr = callFn(methodPtr, paramsPtr);
    if (resPtr == nullptr) {
      throw StateError('vpngate_json_call returned null pointer');
    }
    final raw = resPtr.toDartString();
    final envelope = jsonDecode(raw) as Map<String, dynamic>;
    if (envelope['ok'] != true) {
      throw Exception((envelope['error'] as String?) ?? 'Rust FFI call failed');
    }
    final data = envelope['data'];
    if (data is Map<String, dynamic>) {
      return data;
    }
    return <String, dynamic>{'items': data};
  } finally {
    malloc.free(methodPtr);
    malloc.free(paramsPtr);
    if (resPtr != nullptr) {
      freeFn(resPtr);
    }
  }
}

/// Zero-codegen `dart:ffi` client wrapping `crates/vpngate-bridge`.
class RustBridge {
  RustBridge._();
  static final RustBridge instance = RustBridge._();

  DynamicLibrary? _mainLib;
  _DartDrainProgress? _drainFn;
  _DartFreeString? _freeFn;

  void _ensureMainIsolateBindings() {
    if (_mainLib != null) return;
    final lib = _openBridgeLibrary();
    _drainFn = lib.lookupFunction<_NativeDrainProgress, _DartDrainProgress>(
      'vpngate_drain_progress_json',
    );
    _freeFn = lib.lookupFunction<_NativeFreeString, _DartFreeString>(
      'vpngate_free_string',
    );
    _mainLib = lib;
  }

  /// Executes a `vpngate-bridge` RPC method on a background Dart worker isolate.
  Future<Map<String, dynamic>> rpc(
    String method, [
    Map<String, dynamic> params = const <String, dynamic>{},
  ]) {
    final encoded = jsonEncode(params);
    return Isolate.run(() => _invokeRustRpcSync(method, encoded));
  }

  /// Non-blocking poll of live `ProgressEvent`s from Rust discovery / IKEv1 engine.
  List<Map<String, dynamic>> drainProgressEvents() {
    _ensureMainIsolateBindings();
    final resPtr = _drainFn!();
    if (resPtr == nullptr) return const <Map<String, dynamic>>[];
    try {
      final raw = resPtr.toDartString();
      final decoded = jsonDecode(raw) as Map<String, dynamic>;
      if (decoded['ok'] != true) return const <Map<String, dynamic>>[];
      final list = (decoded['data'] as List<dynamic>?) ?? const <dynamic>[];
      return list.whereType<Map<String, dynamic>>().toList();
    } finally {
      _freeFn!(resPtr);
    }
  }

  Future<String> initStorage(String dirPath) async {
    final data = await rpc('init_storage', <String, dynamic>{'dir': dirPath});
    return (data['storage_dir'] as String?) ?? dirPath;
  }

  Future<Map<String, dynamic>> runDiagnostics() => rpc('diagnostics');

  Future<DiscoverPayloadModel> discoverServers({
    bool forceRefresh = false,
    String? country,
    String protocol = 'auto',
    String sortBy = 'recommended',
    List<String> mirrorUrls = const <String>[],
  }) async {
    final data = await rpc('discover_servers', <String, dynamic>{
      'force_refresh': forceRefresh,
      'country': (country == null || country.isEmpty) ? null : country,
      'protocol': protocol,
      'sort_by': sortBy,
      'mirror_urls': mirrorUrls,
    });
    return DiscoverPayloadModel.fromJson(data);
  }

  Future<List<MirrorProbeModel>> probeOfficialMirrors([
    List<String> extraMirrors = const <String>[],
  ]) async {
    final data = await rpc('probe_mirrors', <String, dynamic>{
      'mirror_urls': extraMirrors,
    });
    final items = (data['items'] as List<dynamic>?) ?? const <dynamic>[];
    return items
        .whereType<Map<String, dynamic>>()
        .map(MirrorProbeModel.fromJson)
        .toList();
  }

  Future<List<PlannedAttemptModel>> buildConnectPlan({
    String? country,
    String protocol = 'auto',
    String sortBy = 'recommended',
    int maxCandidates = 10,
    required bool isIos,
    bool forceRefresh = false,
    List<String> mirrorUrls = const <String>[],
    String? pinnedIp,
  }) async {
    final data = await rpc('build_connect_plan', <String, dynamic>{
      'country': (country == null || country.isEmpty) ? null : country,
      'protocol': protocol,
      'sort_by': sortBy,
      'max_candidates': maxCandidates,
      'is_ios': isIos,
      'force_refresh': forceRefresh,
      'mirror_urls': mirrorUrls,
      'pinned_ip': pinnedIp,
    });
    final items = (data['items'] as List<dynamic>?) ?? const <dynamic>[];
    return items
        .whereType<Map<String, dynamic>>()
        .map(PlannedAttemptModel.fromJson)
        .toList();
  }

  Future<PreparedAttemptModel> prepareAttempt({
    required VpnServerModel server,
    required String protocol,
    required bool isIos,
    required List<String> dnsServers,
  }) async {
    final data = await rpc('prepare_attempt', <String, dynamic>{
      'server': server.toJson(),
      'protocol': protocol,
      'is_ios': isIos,
      'dns_servers': dnsServers,
    });
    return PreparedAttemptModel.fromJson(data);
  }

  Future<int> recordFailure(String ip, String protocol) async {
    final data = await rpc('record_failure', <String, dynamic>{
      'ip': ip,
      'protocol': protocol,
    });
    return (data['active_cooldowns'] as num?)?.toInt() ?? 0;
  }

  Future<void> clearCooldowns() async {
    await rpc('clear_cooldowns');
  }

  Future<bool> setWatchdog(bool enabled) async {
    final data = await rpc('set_watchdog', <String, dynamic>{
      'enabled': enabled,
    });
    return (data['watchdog_enabled'] as bool?) ?? enabled;
  }

  Future<PublicIpTraceModel> checkPublicIp({int timeoutMs = 3500}) async {
    final data = await rpc('check_public_ip', <String, dynamic>{
      'timeout_ms': timeoutMs,
    });
    return PublicIpTraceModel.fromJson(data);
  }

  Future<String> generateAppleMobileconfig(VpnServerModel server) async {
    final data = await rpc('generate_apple_mobileconfig', <String, dynamic>{
      'server': server.toJson(),
    });
    return (data['mobileconfig'] as String?) ?? '';
  }

  Future<UserspaceL2tpStatsModel> getUserspaceL2tpStats() async {
    final data = await rpc('l2tp_status');
    return UserspaceL2tpStatsModel.fromJson(data);
  }

  Future<void> stopUserspaceL2tp() async {
    await rpc('l2tp_stop');
  }
}
