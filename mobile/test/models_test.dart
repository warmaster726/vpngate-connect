import 'package:flutter_test/flutter_test.dart';
import 'package:vpngate_mobile/models/vpn_models.dart';

void main() {
  test('parses VpnServerModel and computes protocol capability flags', () {
    final srv = VpnServerModel.fromJson(<String, dynamic>{
      'hostname': 'public-vpn-101',
      'ip': '219.100.37.1',
      'score': 2850000,
      'ping_ms': 14,
      'speed_bps': 425000000,
      'country_long': 'Japan',
      'country_short': 'JP',
      'sessions': 42,
      'uptime_ms': 86400000,
      'operator': 'Daiyuu Nobori',
      'l2tp': true,
      'openvpn': true,
      'tcp_port': 443,
      'udp_port': 1195,
      'ovpn_b64': 'Y2xpZW50Cg==',
      'ovpn_dl_query': '',
    });

    expect(srv.countryShort, 'JP');
    expect(srv.l2tp, isTrue);
    expect(srv.supportsUdp, isTrue);
    expect(srv.supportsTcp, isTrue);
    expect(srv.speedMbps, closeTo(425.0, 0.01));
    expect(countryFlagEmoji('JP'), '🇯🇵');
  });
}
