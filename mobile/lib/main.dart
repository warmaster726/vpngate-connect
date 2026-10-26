import 'package:flutter/material.dart';

import 'controllers/tunnel_controller.dart';
import 'ui/home_shell.dart';

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  final controller = TunnelController()..initialize();
  runApp(VpnGateMobileApp(controller: controller));
}

class VpnGateMobileApp extends StatelessWidget {
  const VpnGateMobileApp({super.key, required this.controller});

  final TunnelController controller;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'VPNGate Connect',
      debugShowCheckedModeBanner: false,
      themeMode: ThemeMode.dark,
      darkTheme: ThemeData(
        brightness: Brightness.dark,
        useMaterial3: true,
        colorSchemeSeed: const Color(0xFF38BDF8),
        scaffoldBackgroundColor: kBgObsidian,
      ),
      home: HomeShell(controller: controller),
    );
  }
}
