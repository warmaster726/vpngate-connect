package org.vpngate.connect

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.system.OsConstants
import androidx.annotation.Keep
import org.json.JSONObject

class VpnGateVpnService : VpnService() {
    companion object {
        const val ACTION_CONNECT = "org.vpngate.connect.ACTION_CONNECT"
        const val ACTION_DISCONNECT = "org.vpngate.connect.ACTION_DISCONNECT"
        const val ACTION_L2TP_RESULT = "org.vpngate.connect.ACTION_L2TP_RESULT"
        const val ACTION_VPN_REVOKED = "org.vpngate.connect.ACTION_VPN_REVOKED"
        private const val NOTIF_CHANNEL_ID = "vpngate_tunnel_channel"
        private const val NOTIF_ID = 7260

        init {
            System.loadLibrary("vpngate_bridge")
            System.loadLibrary("vpngate_jni")
        }
    }

    private var activeCountry: String = ""
    private var activeServerIp: String = ""

    private external fun nativeStartL2tp(
        serverIp: String,
        dnsCsv: String,
        timeoutSecs: Int,
    ): String

    private external fun nativeStopL2tp()

    /** Invoked synchronously from Rust IKEv1/ESP socket setup via `vpngate_jni.c`. */
    @Keep
    fun protectSocket(fd: Int): Boolean {
        return protect(fd)
    }

    /**
     * Invoked synchronously from Rust once IKEv1 + ESPinUDP + L2TPv2 + PPP/IPCP negotiates IPv4.
     * Detaches the raw `TUN` file descriptor so Rust owns and closes it on teardown.
     */
    @Keep
    fun establishL2tpTun(
        assignedIp: String,
        peerIp: String,
        dns1: String,
        dns2: String,
        mtu: Int,
    ): Int {
        val builder = Builder()
            .setSession("VPN Gate $activeCountry ($activeServerIp)")
            .setMtu(mtu.coerceIn(1280, 1460))
            .addAddress(assignedIp, 32)
            .addRoute("0.0.0.0", 0)
            // Sinkhole IPv6 inside TUN so dual-stack networks never leak IPv6 outside ESP
            .addAddress("fd00:7670:6e67::1", 128)
            .addRoute("::", 0)
            .allowFamily(OsConstants.AF_INET)
            .allowFamily(OsConstants.AF_INET6)
            .setBlocking(false)

        if (dns1.isNotBlank()) builder.addDnsServer(dns1)
        if (dns2.isNotBlank() && dns2 != dns1) builder.addDnsServer(dns2)

        val pfd = builder.establish() ?: return -2
        return pfd.detachFd()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                Thread {
                    nativeStopL2tp()
                    stopForeground(STOP_FOREGROUND_REMOVE)
                    stopSelf()
                }.start()
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                val serverIp = intent.getStringExtra("serverIp") ?: ""
                val countryShort = intent.getStringExtra("countryShort") ?: "VPN"
                val dnsCsv = intent.getStringExtra("dnsServers") ?: "1.1.1.1,1.0.0.1"
                val timeoutSecs = intent.getIntExtra("timeoutSecs", 22)
                activeServerIp = serverIp
                activeCountry = countryShort

                ensureNotificationChannel()
                startForeground(
                    NOTIF_ID,
                    buildNotification("Connecting L2TP/IPsec to $serverIp ($countryShort)..."),
                )

                Thread({
                    val rawJson = nativeStartL2tp(serverIp, dnsCsv, timeoutSecs)
                    val parsed = runCatching { JSONObject(rawJson) }.getOrNull()
                    val ok = parsed?.optBoolean("ok", false) == true
                    if (ok) {
                        val data = parsed?.optJSONObject("data")
                        val assignedIp = data?.optString("assigned_ip", "") ?: ""
                        val espCipher = data?.optString("esp_cipher", "aes256") ?: "aes256"
                        val nm = getSystemService(NotificationManager::class.java)
                        nm?.notify(
                            NOTIF_ID,
                            buildNotification("Protected • $countryShort ($serverIp) • L2TP/$espCipher"),
                        )
                        sendBroadcast(
                            Intent(ACTION_L2TP_RESULT).setPackage(packageName).apply {
                                putExtra("ok", true)
                                putExtra("assignedIp", assignedIp)
                                putExtra("espCipher", espCipher)
                            },
                        )
                    } else {
                        val err = parsed?.optString("error", "L2TP negotiation failed")
                            ?: "L2TP negotiation failed"
                        sendBroadcast(
                            Intent(ACTION_L2TP_RESULT).setPackage(packageName).apply {
                                putExtra("ok", false)
                                putExtra("error", err)
                            },
                        )
                        stopForeground(STOP_FOREGROUND_REMOVE)
                        stopSelf()
                    }
                }, "vpngate-l2tp-handshake").start()
                return START_STICKY
            }
        }
        return START_NOT_STICKY
    }

    override fun onRevoke() {
        Thread {
            nativeStopL2tp()
            sendBroadcast(Intent(ACTION_VPN_REVOKED).setPackage(packageName))
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }.start()
        super.onRevoke()
    }

    override fun onDestroy() {
        nativeStopL2tp()
        super.onDestroy()
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = getSystemService(NotificationManager::class.java)
            val channel = NotificationChannel(
                NOTIF_CHANNEL_ID,
                "VPNGate Tunnel Status",
                NotificationManager.IMPORTANCE_LOW,
            )
            mgr?.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val openAppIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val disconnectIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, VpnGateVpnService::class.java).apply { action = ACTION_DISCONNECT },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, NOTIF_CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle("VPNGate Connect")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(openAppIntent)
            .setOngoing(true)
            .addAction(
                Notification.Action.Builder(
                    null,
                    "Disconnect",
                    disconnectIntent,
                ).build(),
            )
            .build()
    }
}
