package org.vpngate.connect

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import id.laskarmedia.openvpn_flutter.OpenVPNFlutterPlugin
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    companion object {
        private const val CHANNEL = "org.vpngate.connect/vpn"
        private const val REQ_VPN_CONSENT = 9042
    }

    private var methodChannel: MethodChannel? = null
    private var pendingL2tpArgs: Map<*, *>? = null
    private var pendingResult: MethodChannel.Result? = null

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            when (intent?.action) {
                VpnGateVpnService.ACTION_L2TP_RESULT -> {
                    val res = pendingResult ?: return
                    pendingResult = null
                    val ok = intent.getBooleanExtra("ok", false)
                    if (ok) {
                        res.success(
                            mapOf(
                                "ok" to true,
                                "assignedIp" to (intent.getStringExtra("assignedIp") ?: ""),
                                "espCipher" to (intent.getStringExtra("espCipher") ?: "aes256"),
                            ),
                        )
                    } else {
                        res.success(
                            mapOf(
                                "ok" to false,
                                "error" to (intent.getStringExtra("error") ?: "L2TP handshake failed"),
                            ),
                        )
                    }
                }
                VpnGateVpnService.ACTION_VPN_REVOKED -> {
                    methodChannel?.invokeMethod("onNativeVpnRevoked", null)
                }
            }
        }
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        val filter = IntentFilter().apply {
            addAction(VpnGateVpnService.ACTION_L2TP_RESULT)
            addAction(VpnGateVpnService.ACTION_VPN_REVOKED)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(statusReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(statusReceiver, filter)
        }

        methodChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).also { ch ->
            ch.setMethodCallHandler { call, result ->
                when (call.method) {
                    "startUserspaceL2tp" -> {
                        val args = call.arguments as? Map<*, *>
                        if (args == null) {
                            result.error("INVALID_ARGS", "Expected map arguments", null)
                            return@setMethodCallHandler
                        }
                        val prepareIntent = VpnService.prepare(this)
                        if (prepareIntent != null) {
                            pendingL2tpArgs = args
                            pendingResult = result
                            startActivityForResult(prepareIntent, REQ_VPN_CONSENT)
                        } else {
                            pendingResult = result
                            launchL2tpService(args)
                        }
                    }
                    "stopUserspaceL2tp" -> {
                        val stopIntent = Intent(this, VpnGateVpnService::class.java).apply {
                            action = VpnGateVpnService.ACTION_DISCONNECT
                        }
                        startService(stopIntent)
                        result.success(null)
                    }
                    else -> result.notImplemented()
                }
            }
        }
    }

    private fun launchL2tpService(args: Map<*, *>) {
        val svcIntent = Intent(this, VpnGateVpnService::class.java).apply {
            action = VpnGateVpnService.ACTION_CONNECT
            putExtra("serverIp", args["serverIp"]?.toString() ?: "")
            putExtra("countryShort", args["countryShort"]?.toString() ?: "")
            putExtra("countryLong", args["countryLong"]?.toString() ?: "")
            putExtra("dnsServers", args["dnsServers"]?.toString() ?: "1.1.1.1,1.0.0.1")
            putExtra("timeoutSecs", (args["timeoutSecs"] as? Number)?.toInt() ?: 22)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(svcIntent)
        } else {
            startService(svcIntent)
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == REQ_VPN_CONSENT) {
            val args = pendingL2tpArgs
            pendingL2tpArgs = null
            if (resultCode == Activity.RESULT_OK && args != null) {
                launchL2tpService(args)
            } else {
                val res = pendingResult
                pendingResult = null
                res?.success(mapOf("ok" to false, "error" to "Android VPN permission denied by user"))
            }
            return
        }
        if (requestCode == 24) {
            OpenVPNFlutterPlugin.connectWhileGranted(resultCode == Activity.RESULT_OK)
        }
        super.onActivityResult(requestCode, resultCode, data)
    }

    override fun onDestroy() {
        try {
            unregisterReceiver(statusReceiver)
        } catch (_: Exception) {}
        super.onDestroy()
    }
}
