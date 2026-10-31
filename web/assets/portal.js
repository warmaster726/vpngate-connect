
(function () {
  "use strict";

  var verifyGen = 0;
  var walkAbort = null;
  var state = {
    tab: "connect",
    servers: [],
    countries: [],
    mirrors: [],
    counts: { total: 0, l2tp: 0, openvpn: 0, countries: 0, mirrors: 0 },
    country: "ALL",
    proto: "auto",
    compat: "mobile3",
    dns: "1.1.1.1,1.0.0.1",
    connectSort: "recommended",
    selectedIndex: 0,
    relaySearch: "",
    relayProto: "all",
    relaySort: "recommended",
    relayLimit: 40,
    customMirror: "",
    device: detectDevice(),
    verifying: false,
    testingIp: "",
    testingIps: {},
    verifyLabel: "",
    verified: null,
    attempts: [],
    step: "pool",
    elapsedTimer: 0,
    walkStartedAt: 0,
    hopStartedAt: 0,
    walkSlot: 0,
    walkTotal: 0,
    walkHops: [],
    walkHeadJob: 0
  };

  function detectDevice() {
    var ua = navigator.userAgent || "";
    var isIOS = /iPad|iPhone|iPod/.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
    var isAndroid = /Android/i.test(ua);
    var isMac = !isIOS && /Macintosh|Mac OS X/i.test(ua);
    var isWin = /Windows/i.test(ua);
    if (isIOS) return { id: "ios", label: "iOS / iPadOS · Safari native profile", apple: true, mobile: true };
    if (isAndroid) return { id: "android", label: "Android · OpenVPN Connect / for Android", apple: false, mobile: true };
    if (isMac) return { id: "macos", label: "macOS · Native L2TP + OpenVPN 2.6", apple: true, mobile: false };
    if (isWin) return { id: "windows", label: "Windows 11 · Patched .ovpn + native CLI", apple: false, mobile: false };
    return { id: "linux", label: "Linux · Patched .ovpn + native CLI", apple: false, mobile: false };
  }

  var EDGE = (typeof location !== "undefined" && location.origin) ? location.origin : "";
  var INSTALL_SH = EDGE ? (EDGE + "/install.sh") : "https://cdn.jsdelivr.net/gh/warmaster726/vpngate-connect@main/install-vpngate.sh";
  var INSTALL_PS1 = EDGE ? (EDGE + "/install.ps1") : "https://cdn.jsdelivr.net/gh/warmaster726/vpngate-connect@main/install-vpngate.ps1";
  var INSTALL_CMDS = {
    linux: {
      hint: "Linux / macOS · POSIX sh",
      install: "curl -fsSL " + INSTALL_SH + " | sh -s --",
      uninstall: "curl -fsSL " + INSTALL_SH + " | sh -s -- --uninstall"
    },
    windows: {
      hint: "Windows 11 · Administrator PowerShell",
      install: "irm " + INSTALL_PS1 + " | iex",
      uninstall: "irm " + INSTALL_PS1 + " -OutFile $env:TEMP\\install-vpngate.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\\install-vpngate.ps1 --uninstall"
    }
  };

  function defaultInstallOs() {
    return (state.device && state.device.id === "windows") ? "windows" : "linux";
  }

  function applyInstallOs(os) {
    if (os !== "windows") os = "linux";
    state.installOs = os;
    var cmds = INSTALL_CMDS[os];
    var hint = document.getElementById("install-os-hint");
    var installBtn = document.getElementById("install-copy");
    var uninstallBtn = document.getElementById("uninstall-copy");
    if (hint) hint.textContent = cmds.hint;
    if (installBtn) {
      installBtn.textContent = cmds.install;
      installBtn.setAttribute("data-cmd", cmds.install);
      installBtn.setAttribute("title", cmds.install);
    }
    if (uninstallBtn) {
      uninstallBtn.textContent = cmds.uninstall;
      uninstallBtn.setAttribute("data-cmd", cmds.uninstall);
      uninstallBtn.setAttribute("title", cmds.uninstall);
    }
    document.querySelectorAll("#install-os-pills .chip").forEach(function (c) {
      c.classList.toggle("active", c.getAttribute("data-install-os") === os);
    });
  }

  function copyDesktopCommand(btn, okMsg) {
    var cmd = "";
    if (btn) cmd = (btn.getAttribute("data-cmd") || btn.textContent || "").trim();
    if (!cmd) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(cmd).then(function () {
        appendLog("ok", okMsg);
      }).catch(function () {
        appendLog("warn", "Copy failed — select the command manually.");
      });
    } else {
      appendLog("info", cmd);
    }
  }

  function flagEmoji(cc) {
    if (!cc || cc.length !== 2 || cc === "XX") return "🌐";
    var up = cc.toUpperCase();
    var a = up.charCodeAt(0) - 65 + 0x1F1E6;
    var b = up.charCodeAt(1) - 65 + 0x1F1E6;
    if (a < 0x1F1E6 || a > 0x1F1FF || b < 0x1F1E6 || b > 0x1F1FF) return "🌐";
    return String.fromCodePoint(a, b);
  }

  function esc(s) {
    return String(s == null ? "" : s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function stripMarkup(s) {
    return String(s == null ? "" : s)
      .replace(/<[^>]*>/g, " ")
      .replace(/&nbsp;|&#160;/gi, " ")
      .replace(/&amp;/g, "&")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&quot;/g, "\"")
      .replace(/&#39;|&apos;/g, "'")
      .replace(/<[^>]*>/g, " ")
      .replace(/\s+/g, " ")
      .trim();
  }

  function fmtMbps(bps) {
    return ((Number(bps) || 0) / 1000000).toFixed(1) + " Mbps";
  }

  function fmtScore(n) {
    return (Number(n) || 0).toLocaleString();
  }

  function hostLabel(srv) {
    var h = stripMarkup((srv && srv.hostname) || "");
    var ip = String((srv && srv.ip) || "");
    if (!h || h === ip) return ip;
    if (/\.opengw\.net$/i.test(h)) return h;
    if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(h)) return h;
    return h + ".opengw.net";
  }

  function appendLog(level, msg) {
    var box = document.getElementById("console-log");
    if (!box) return;
    var ts = new Date().toLocaleTimeString([], { hour12: false });
    var tag = level === "ok" ? "[+]" : level === "warn" ? "[!]" : level === "err" ? "[-]" : "[*]";
    var cls = level === "ok" ? "log-ok" : level === "warn" ? "log-warn" : level === "err" ? "log-err" : "log-info";
    var div = document.createElement("div");
    div.className = "log-line " + cls;
    div.textContent = ts + " " + tag + " " + msg;
    box.appendChild(div);
    box.scrollTop = box.scrollHeight;
  }

  function setStatusPill(mode, text) {
    var pill = document.getElementById("status-pill");
    var txt = document.getElementById("status-text");
    if (!pill || !txt) return;
    pill.className = "status-pill" + (mode ? " " + mode : "");
    txt.textContent = text;
  }

  function setStepper(step) {
    state.step = step;
    var nodes = document.querySelectorAll("[data-step]");
    var order = ["pool", "probe", "handshake", "profile"];
    var idx = order.indexOf(step);
    for (var i = 0; i < nodes.length; i++) {
      var id = nodes[i].getAttribute("data-step");
      var n = order.indexOf(id);
      nodes[i].classList.remove("on", "ok", "bad");
      if (step === "fail" && n >= 1) nodes[i].classList.add("bad");
      else if (n < idx) nodes[i].classList.add("ok");
      else if (n === idx) nodes[i].classList.add("on");
    }
  }

  function matchCountry(srv, query) {
    if (!query || query === "ALL") return true;
    var q = query.trim();
    if (!q || q.toLowerCase() === "all" || q.toLowerCase() === "any") return true;
    var up = q.toUpperCase();
    if (q.length === 2 && /^[A-Za-z]{2}$/.test(q)) {
      var iso = up === "UK" ? "GB" : up;
      return (srv.country_short || "").toUpperCase() === iso;
    }
    var low = q.toLowerCase();
    return (
      (srv.country_short || "").toUpperCase() === up ||
      (srv.country_long || "").toLowerCase().indexOf(low) !== -1
    );
  }

  function matchRelayQuery(srv, query) {
    if (!query) return true;
    if (matchCountry(srv, query)) return true;
    var low = query.trim().toLowerCase();
    return (
      (srv.hostname || "").toLowerCase().indexOf(low) !== -1 ||
      (srv.ip || "").indexOf(low) !== -1
    );
  }

  function supportsUdp(srv) {
    return Boolean(srv.openvpn && (srv.udp_port > 0 || (srv.has_ovpn_cert && srv.tcp_port === 0)));
  }

  function supportsTcp(srv) {
    return Boolean(srv.openvpn && (srv.tcp_port > 0 || (srv.has_ovpn_cert && srv.udp_port === 0)));
  }

  function matchProto(srv, proto) {
    if (!proto || proto === "auto" || proto === "all") return srv.l2tp || srv.openvpn;
    if (proto === "l2tp") return Boolean(srv.l2tp);
    if (proto === "openvpn" || proto === "ovpn") return Boolean(srv.openvpn);
    if (proto === "udp") return supportsUdp(srv);
    if (proto === "tcp") return supportsTcp(srv);
    return true;
  }

  function sortList(list, sortKey, protoFilter) {
    return list.slice().sort(function (a, b) {
      var tierA = a.l2tp ? 0 : (supportsUdp(a) ? 1 : 2);
      var tierB = b.l2tp ? 0 : (supportsUdp(b) ? 1 : 2);
      var tierDiff = 0;
      if (protoFilter === "auto" || protoFilter === "all" || !protoFilter) tierDiff = tierA - tierB;
      else if (protoFilter === "openvpn") tierDiff = (supportsUdp(b) ? 1 : 0) - (supportsUdp(a) ? 1 : 0);
      var pingA = (!a.ping_ms || a.ping_ms >= 9999) ? 999999 : a.ping_ms;
      var pingB = (!b.ping_ms || b.ping_ms >= 9999) ? 999999 : b.ping_ms;
      if (sortKey === "speed") return (b.speed_bps - a.speed_bps) || tierDiff || (b.score - a.score);
      if (sortKey === "ping") return (pingA - pingB) || tierDiff || (b.speed_bps - a.speed_bps);
      if (sortKey === "score") return tierDiff || (b.score - a.score) || (b.speed_bps - a.speed_bps);
      return tierDiff || (b.score - a.score) || (b.speed_bps - a.speed_bps) || (pingA - pingB);
    });
  }

  function buildMobileconfigHref(srv) {
    var cc = (srv.country_short || "XX").toUpperCase();
    var q = new URLSearchParams({
      ip: srv.ip,
      cc: cc,
      country: srv.country_long || "Relay",
      dns: state.dns
    });
    return "/profiles/vpngate-" + encodeURIComponent(cc) + "-" + encodeURIComponent(srv.ip) + ".mobileconfig?" + q.toString();
  }

  function buildOvpnHref(srv, transport) {
    var cc = (srv.country_short || "XX").toUpperCase();
    var q = new URLSearchParams({
      ip: srv.ip,
      cc: cc,
      proto: transport,
      compat: state.compat,
      dns: state.dns,
      udp: String(srv.udp_port || 0),
      tcp: String(srv.tcp_port || 0)
    });
    return "/profiles/vpngate-" + encodeURIComponent(cc) + "-" + encodeURIComponent(srv.ip) + "-" + transport + ".ovpn?" + q.toString();
  }

  function ovpnFileName(srv, transport) {
    var cc = (srv.country_short || "XX").toUpperCase();
    return "vpngate-" + cc + "-" + srv.ip + "-" + transport + ".ovpn";
  }

  function ovpnExportLabel(transport, compact) {
    var t = String(transport || "").toUpperCase();
    if (state.device && state.device.mobile) {
      return compact ? ("OpenVPN " + t) : ("Open in OpenVPN Connect · " + t);
    }
    return compact ? ("OVPN " + t) : ("Export OpenVPN " + t + " (.ovpn)");
  }

  function openVpnConnectLink(absHttps) {
    if (state.device && state.device.id === "android") {
      return "intent://import-profile/" + absHttps +
        "#Intent;scheme=openvpn;package=net.openvpn.openvpn;S.browser_fallback_url=" +
        encodeURIComponent("https://play.google.com/store/apps/details?id=net.openvpn.openvpn") +
        ";end";
    }
    return "openvpn://import-profile/" + absHttps;
  }

  function downloadOvpnBlob(buf, fileName) {
    var file;
    try {
      file = new File([buf], fileName, { type: "application/x-openvpn-profile" });
    } catch (e1) {
      file = new Blob([buf], { type: "application/x-openvpn-profile" });
    }
    if (typeof File !== "undefined" && file instanceof File && navigator.canShare && navigator.canShare({ files: [file] })) {
      return navigator.share({ files: [file], title: fileName, text: "Open in OpenVPN Connect" }).then(function () {
        appendLog("ok", "Shared " + fileName + " — choose OpenVPN Connect.");
      }).catch(function (shareErr) {
        if (shareErr && shareErr.name === "AbortError") {
          appendLog("info", "Export cancelled.");
          return;
        }
        throw shareErr;
      });
    }
    var url = URL.createObjectURL(file);
    var a = document.createElement("a");
    a.href = url;
    a.download = fileName;
    a.rel = "noopener";
    a.style.display = "none";
    document.body.appendChild(a);
    a.click();
    setTimeout(function () {
      URL.revokeObjectURL(url);
      if (a.parentNode) a.parentNode.removeChild(a);
    }, 2500);
    appendLog("ok", "Downloaded " + fileName + ". Open it with OpenVPN Connect.");
    return Promise.resolve();
  }

  async function exportOvpnFile(href, fileName) {
    if (!href || !fileName) return;
    var abs = new URL(href, window.location.href).href;
    var mobile = Boolean(state.device && state.device.mobile);
    if (mobile) {
      appendLog("info", "Opening OpenVPN Connect to import " + fileName + "…");
      var handed = false;
      function onHide() {
        if (document.hidden) handed = true;
      }
      document.addEventListener("visibilitychange", onHide);
      try {
        window.location.href = openVpnConnectLink(abs);
      } catch (e0) {}
      window.setTimeout(function () {
        document.removeEventListener("visibilitychange", onHide);
        if (handed || document.hidden) {
          appendLog("ok", "Handed " + fileName + " to OpenVPN Connect.");
          return;
        }
        appendLog("warn", "OpenVPN Connect did not open. Install it, then try again — falling back to share/download.");
        fetch(href, { headers: { Accept: "application/x-openvpn-profile" } }).then(function (resp) {
          if (!resp.ok) throw new Error("Export refused (" + resp.status + ")");
          return resp.arrayBuffer();
        }).then(function (buf) {
          return downloadOvpnBlob(buf, fileName);
        }).catch(function (e) {
          appendLog("err", "Export failed: " + (e && e.message ? e.message : String(e)));
        });
      }, 1600);
      return;
    }
    appendLog("info", "Exporting " + fileName + "…");
    try {
      var resp = await fetch(href, { headers: { Accept: "application/x-openvpn-profile" } });
      if (!resp.ok) {
        var err = "Export refused (" + resp.status + ")";
        try {
          var j = await resp.json();
          if (j && j.error) err = j.error;
        } catch (e0) {}
        appendLog("err", err);
        return;
      }
      var buf = await resp.arrayBuffer();
      await downloadOvpnBlob(buf, fileName);
    } catch (e) {
      appendLog("err", "Export failed: " + (e && e.message ? e.message : String(e)));
    }
  }

  var DEAD_PENALTY_MS = 15 * 60 * 1000;

  function prunePenalties() {
    var now = Date.now();
    for (var i = 0; i < state.servers.length; i++) {
      var s = state.servers[i];
      if (s.verify_state === "dead" && s.dead_until && now >= s.dead_until) {
        s.verify_state = "untested";
        s.dead_until = 0;
      }
    }
  }

  function protoNeeds(proto) {
    if (!proto || proto === "auto" || proto === "all") return null;
    if (proto === "l2tp") return ["l2tp"];
    if (proto === "udp") return ["udp"];
    if (proto === "tcp") return ["tcp"];
    if (proto === "openvpn" || proto === "ovpn") return ["udp", "tcp"];
    return null;
  }

  function satisfiesProto(unlocked, proto) {
    if (!unlocked || !unlocked.length) return false;
    var need = protoNeeds(proto);
    if (!need) return true;
    for (var i = 0; i < need.length; i++) {
      if (unlocked.indexOf(need[i]) !== -1) return true;
    }
    return false;
  }

  function lockReason(kind, srv) {
    var locked = [];
    if (state.verified && srv && state.verified.ip === srv.ip && Array.isArray(state.verified.locked)) {
      locked = state.verified.locked;
    } else if (srv && Array.isArray(srv.locked)) {
      locked = srv.locked;
    }
    for (var i = 0; i < locked.length; i++) {
      if (locked[i] && locked[i].kind === kind && locked[i].reason) return locked[i].reason;
    }
    return "";
  }

  function lockedLabel(kind, fallback, srv) {
    var why = lockReason(kind, srv);
    return why ? (fallback + " — " + why) : fallback;
  }

  function isPenalized(srv) {
    if (!srv || srv.verify_state !== "dead") return false;
    if (srv.dead_until && Date.now() >= srv.dead_until) {
      srv.verify_state = "untested";
      srv.dead_until = 0;
      return false;
    }
    return true;
  }

  function fmtPenaltyLeft(srv) {
    var left = Math.max(0, (srv.dead_until || 0) - Date.now());
    if (left <= 0) return "";
    var mins = Math.ceil(left / 60000);
    return mins <= 1 ? "<1m" : mins + "m";
  }

  function fmtElapsed(ms) {
    var s = Math.max(0, ms) / 1000;
    if (s < 60) return s.toFixed(1) + "s";
    var m = Math.floor(s / 60);
    var r = Math.floor(s % 60);
    return m + "m " + (r < 10 ? "0" : "") + r + "s";
  }

  function paintElapsed() {
    var hop = fmtElapsed(Date.now() - (state.hopStartedAt || Date.now()));
    var total = fmtElapsed(Date.now() - (state.walkStartedAt || Date.now()));
    var hopEl = document.getElementById("verify-elapsed");
    var hopStat = document.getElementById("hero-hop-elapsed");
    var txt = document.getElementById("status-text");
    if (hopEl) hopEl.textContent = hop + " this hop · " + total + " total";
    if (hopStat) hopStat.textContent = hop;
    var hopEls = document.querySelectorAll(".hop-elapsed");
    for (var hi = 0; hi < hopEls.length; hi++) {
      var started = Number(hopEls[hi].getAttribute("data-hop-start") || 0);
      hopEls[hi].textContent = fmtElapsed(Date.now() - (started || Date.now()));
    }
    if (txt && state.verifying && state.walkTotal) {
      var nFlight = 0;
      if (state.testingIps) {
        for (var ipk in state.testingIps) {
          if (state.testingIps[ipk]) nFlight += 1;
        }
      }
      txt.textContent = state.walkSlot + "/" + state.walkTotal + " · " + hop +
        (nFlight > 1 ? (" · " + nFlight + " hops") : "");
    }
  }

  function startElapsedTicker() {
    if (state.elapsedTimer) clearInterval(state.elapsedTimer);
    paintElapsed();
    state.elapsedTimer = setInterval(paintElapsed, 100);
  }

  function stopElapsedTicker() {
    if (state.elapsedTimer) {
      clearInterval(state.elapsedTimer);
      state.elapsedTimer = 0;
    }
  }

  function renderBadges(srv) {
    var out = "";
    if (state.verifying && (state.testingIp === srv.ip || (state.testingIps && state.testingIps[srv.ip]))) {
      out += '<span class="badge badge-wait">TESTING</span>';
    } else if (srv.verify_state === "live") {
      out += '<span class="badge badge-live">LIVE HANDSHAKE</span>';
    } else if (srv.verify_state === "partial") {
      out += '<span class="badge badge-partial">PARTIAL</span>';
    } else if (isPenalized(srv)) {
      var left = fmtPenaltyLeft(srv);
      out += '<span class="badge badge-err">DEAD' + (left ? " · " + left : "") + "</span>";
    } else if (srv.verify_state === "dead") {
      out += '<span class="badge badge-err">DEAD</span>';
    }
    if (srv.l2tp) out += '<span class="badge badge-l2tp">L2TP PSK=vpn</span>';
    if (srv.openvpn && srv.udp_port > 0) {
      out += '<span class="badge badge-udp">OVPN UDP:' + srv.udp_port + "</span>";
    }
    if (srv.openvpn && srv.tcp_port > 0) {
      out += '<span class="badge badge-tcp">OVPN TCP:' + srv.tcp_port + "</span>";
    }
    return out;
  }

  function renderCountryControls() {
    var sel = document.getElementById("connect-country");
    var pills = document.getElementById("quick-country-pills");
    if (!sel || !pills) return;

    var opts = '<option value="ALL">🌐 All Countries (' + state.counts.total + " relays)</option>";
    for (var i = 0; i < state.countries.length; i++) {
      var c = state.countries[i];
      var selected = state.country === c.country_short ? " selected" : "";
      opts += '<option value="' + esc(c.country_short) + '"' + selected + ">" +
        flagEmoji(c.country_short) + " " + esc(c.country_long) + " (" + esc(c.country_short) + ") — " +
        c.total_servers + " (" + c.l2tp_count + " L2TP)</option>";
    }
    sel.innerHTML = opts;
    if (state.country && state.country !== "ALL") sel.value = state.country;

    var topCodes = ["ALL"];
    var hasCurrent = state.country === "ALL";
    for (var j = 0; j < Math.min(6, state.countries.length); j++) {
      topCodes.push(state.countries[j].country_short);
      if (state.countries[j].country_short === state.country) hasCurrent = true;
    }
    if (!hasCurrent && state.country) topCodes.splice(1, 0, state.country);
    var pillHtml = "";
    for (var k = 0; k < topCodes.length; k++) {
      var code = topCodes[k];
      var act = state.country === code ? " active" : "";
      var lbl = code === "ALL" ? "🌐 ALL" : (flagEmoji(code) + " " + code);
      pillHtml += '<button type="button" class="chip' + act + '" data-cc="' + esc(code) + '">' + lbl + "</button>";
    }
    pills.innerHTML = pillHtml;
  }

  function getConnectCandidates() {
    prunePenalties();
    var filtered = state.servers.filter(function (s) {
      return matchCountry(s, state.country) && matchProto(s, state.proto);
    });
    return sortList(filtered, state.connectSort, state.proto);
  }

  function applyVerifiedToServers(verified, attempts) {
    var dead = {};
    var liveIp = verified && verified.ip;
    if (Array.isArray(attempts)) {
      for (var i = 0; i < attempts.length; i++) {
        if (!attempts[i].ok) dead[attempts[i].ip] = true;
      }
    }
    for (var j = 0; j < state.servers.length; j++) {
      var s = state.servers[j];
      if (liveIp && s.ip === liveIp) {
        s.verify_state = "live";
        s.verified_port = verified.port;
        s.verified_rtt_ms = verified.rtt_ms;
      } else if (dead[s.ip]) {
        s.verify_state = "dead";
      }
    }
  }

  function unlockedFor(srv) {
    if (state.verified && srv && state.verified.ip === srv.ip && Array.isArray(state.verified.unlocked)) {
      return state.verified.unlocked;
    }
    return (srv && srv.unlocked) || [];
  }

  function hopStatusBadge(status) {
    if (status === "live") return '<span class="badge badge-live">LIVE</span>';
    if (status === "partial") return '<span class="badge badge-partial">PARTIAL</span>';
    if (status === "dead") return '<span class="badge badge-err">DEAD</span>';
    return '<span class="badge badge-wait">TESTING</span>';
  }

  function adoptWalkHop(ip) {
    if (!state.verifying) return;
    var hops = state.walkHops || [];
    var hop = null;
    for (var i = 0; i < hops.length; i++) {
      if (hops[i].ip === ip) { hop = hops[i]; break; }
    }
    if (!hop || (hop.status !== "live" && hop.status !== "partial") || !hop.payload) return;
    verifyGen += 1;
    if (walkAbort) walkAbort.abort();
    state.verifying = false;
    state.testingIp = "";
    state.testingIps = {};
    state.walkHops = [];
    stopElapsedTicker();
    state.selectedIndex = hop.index;
    state.verified = hop.payload;
    markServerState(hop.ip, {
      ok: true,
      port: hop.payload.port,
      rtt_ms: hop.payload.rtt_ms,
      unlocked: hop.payload.unlocked || [],
      locked: hop.payload.locked || []
    });
    setStepper("profile");
    setStatusPill("", "LIVE · #" + (hop.index + 1));
    appendLog("ok", "Selected listed slot [" + (hop.index + 1) + "/" + state.walkTotal + "] " + hop.ip +
      " · walk stopped.");
    renderConnectHero();
    renderRelaysTab();
  }

  function renderWalkHopsHtml() {
    var hops = state.walkHops || [];
    if (!state.verifying || !hops.length) return "";
    var html = '<div class="hop-grid" aria-label="Prefetch handshake hops">';
    for (var i = 0; i < hops.length; i++) {
      var h = hops[i];
      var selectable = (h.status === "live" || h.status === "partial") && h.payload;
      var cls = "hop-card " + (h.status || "testing");
      if (selectable) cls += " selectable";
      var ping = (!h.ping_ms || h.ping_ms >= 9999) ? "—" : (h.ping_ms + " ms");
      html += '<div class="' + cls + '" data-walk-ip="' + esc(h.ip) + '" data-selectable="' + (selectable ? "1" : "0") + '"' +
        (selectable ? ' role="button" tabindex="0" title="Use this live relay and stop scanning"' : "") + ">" +
        '<div class="hop-card-top">' +
          '<div class="hop-card-title">' + flagEmoji(h.country_short) + " " + esc(h.country_long || "Relay") +
            ' <span class="hop-slot">[' + (h.index + 1) + "/" + state.walkTotal + "]</span></div>" +
          hopStatusBadge(h.status) +
        "</div>" +
        '<div class="hop-card-host">' + esc(h.host) + " · " + esc(h.ip) + "</div>" +
        '<div class="hop-card-meta">' + fmtMbps(h.speed_bps) + " · " + ping +
          ' · <span class="hop-elapsed" data-hop-start="' + (h.startedAt || 0) + '">0.0s</span></div>' +
      "</div>";
    }
    html += "</div>";
    html += '<div class="hop-hint">Four prefetch hops — not the hero above. Tap LIVE to use that listed slot and stop the scan.</div>';
    return html;
  }

  function renderConnectHero() {
    var wrap = document.getElementById("hero-container");
    if (!wrap) return;
    var candidates = getConnectCandidates();
    if (candidates.length === 0) {
      wrap.innerHTML = '<div class="card"><div class="card-title">No matching relays</div>' +
        '<div class="card-subtitle">Switch country to ALL, protocol to Auto, or refresh the pool.</div></div>';
      return;
    }

    if (state.selectedIndex < 0) state.selectedIndex = 0;
    if (state.selectedIndex >= candidates.length) state.selectedIndex = candidates.length - 1;
    var srv = candidates[state.selectedIndex];

    var unlocked = unlockedFor(srv);
    var canL2tp = unlocked.indexOf("l2tp") !== -1;
    var canUdp = unlocked.indexOf("udp") !== -1;
    var canTcp = unlocked.indexOf("tcp") !== -1;
    var anyLive = canL2tp || canUdp || canTcp;
    var someLocked = (srv.l2tp && !canL2tp)
      || (srv.openvpn && srv.udp_port > 0 && !canUdp)
      || (srv.openvpn && srv.tcp_port > 0 && !canTcp);
    var heroClass = "hero-relay";
    if (state.verifying) heroClass += " testing";
    else if (anyLive && !someLocked) heroClass += " live";
    else if (anyLive) heroClass += " partial";
    else if (srv.verify_state === "dead") heroClass += " dead";

    var handshakeMs;
    if (state.verifying) handshakeMs = '<span id="hero-hop-elapsed">0.0s</span>';
    else if (state.verified && state.verified.ip === srv.ip && state.verified.rtt_ms)
      handshakeMs = state.verified.rtt_ms + " ms";
    else if (srv.verified_rtt_ms) handshakeMs = srv.verified_rtt_ms + " ms";
    else handshakeMs = "—";

    var lockHtml;
    if (state.verifying) {
      lockHtml = '<div class="progress-track"><div class="progress-fill"></div></div>' +
        '<div class="progress-label">' + esc(state.verifyLabel || "Testing live path") +
        ' · <span id="verify-elapsed">0.0s this hop · 0.0s total</span></div>' +
        renderWalkHopsHtml();
    } else if (anyLive && !someLocked) {
      lockHtml = '<div class="lock-note ok">Live path on ' +
        esc(srv.ip) + (state.verified && state.verified.port ? (":" + esc(state.verified.port)) : "") +
        " · advertised profiles unlocked for this relay only.</div>";
    } else if (anyLive) {
      var openBits = [];
      if (canL2tp) openBits.push("Apple L2TP");
      if (canUdp) openBits.push("OpenVPN UDP");
      if (canTcp) openBits.push("OpenVPN TCP");
      var shutBits = [];
      if (srv.l2tp && !canL2tp) shutBits.push("Apple L2TP" + (lockReason("l2tp", srv) ? " (" + lockReason("l2tp", srv) + ")" : ""));
      if (srv.openvpn && srv.udp_port > 0 && !canUdp) shutBits.push("OpenVPN UDP" + (lockReason("udp", srv) ? " (" + lockReason("udp", srv) + ")" : ""));
      if (srv.openvpn && srv.tcp_port > 0 && !canTcp) shutBits.push("OpenVPN TCP" + (lockReason("tcp", srv) ? " (" + lockReason("tcp", srv) + ")" : ""));
      lockHtml = '<div class="lock-note partial">Unlocked: ' + esc(openBits.join(", ") || "none") +
        ". Locked: " + esc(shutBits.join(", ") || "none") + ".</div>";
    } else {
      lockHtml = '<div class="lock-note">Profiles stay locked until this edge proves a live path. Dead listings are never exported.</div>';
    }

    var profileBtns = "";
    if (canL2tp) {
      profileBtns += '<a class="btn btn-emerald" href="' + esc(buildMobileconfigHref(srv)) + '"> Install Apple L2TP (.mobileconfig)</a>';
    } else if (srv.l2tp) {
      profileBtns += '<span class="btn btn-lock">' + esc(lockedLabel("l2tp", "Locked · Apple L2TP", srv)) + "</span>";
    }
    if (canUdp) {
      profileBtns += '<button type="button" class="btn btn-primary" data-ovpn-href="' + esc(buildOvpnHref(srv, "udp")) +
        '" data-ovpn-name="' + esc(ovpnFileName(srv, "udp")) + '">' + esc(ovpnExportLabel("udp", false)) + "</button>";
    } else if (srv.openvpn && srv.udp_port > 0) {
      profileBtns += '<span class="btn btn-lock">' + esc(lockedLabel("udp", "Locked · OpenVPN UDP", srv)) + "</span>";
    }
    if (canTcp) {
      profileBtns += '<button type="button" class="btn" data-ovpn-href="' + esc(buildOvpnHref(srv, "tcp")) +
        '" data-ovpn-name="' + esc(ovpnFileName(srv, "tcp")) + '">' + esc(ovpnExportLabel("tcp", false)) + "</button>";
    } else if (srv.openvpn && srv.tcp_port > 0) {
      profileBtns += '<span class="btn btn-lock">' + esc(lockedLabel("tcp", "Locked · OpenVPN TCP", srv)) + "</span>";
    }
    if (!profileBtns) {
      profileBtns = '<span class="btn btn-lock">No profile until a live handshake exists</span>';
    }

    var html = '<div class="' + heroClass + '">' +
      '<div class="relay-top">' +
        "<div>" +
          '<div class="relay-country">' + flagEmoji(srv.country_short) + " " + esc(srv.country_long) +
            ' <span style="color:var(--muted);font-size:12px;font-family:var(--mono)">[' + (state.selectedIndex + 1) + "/" + candidates.length + "]</span></div>" +
          '<div class="relay-host">' + esc(hostLabel(srv)) + " · " + esc(srv.ip) + "</div>" +
        "</div>" +
        '<div class="badges">' + renderBadges(srv) + "</div>" +
      "</div>" +
      '<div class="stats-strip">' +
        '<div class="stat-box"><div class="stat-k">Throughput</div><div class="stat-v">' + fmtMbps(srv.speed_bps) + "</div></div>" +
        '<div class="stat-box"><div class="stat-k">Listed ping</div><div class="stat-v">' + (srv.ping_ms >= 9999 ? "—" : srv.ping_ms + " ms") + "</div></div>" +
        '<div class="stat-box"><div class="stat-k">Handshake</div><div class="stat-v">' + handshakeMs + "</div></div>" +
        '<div class="stat-box"><div class="stat-k">Sessions</div><div class="stat-v">' + srv.sessions + "</div></div>" +
      "</div>" +
      lockHtml +
      '<div class="btn-row">' + profileBtns + "</div>" +
      '<div class="btn-row" style="margin-top:8px">' +
        '<button type="button" class="btn btn-sm" id="btn-verify-now">' + (state.verifying ? "Verifying…" : "Verify live path") + "</button>" +
        '<button type="button" class="btn btn-sm" id="btn-next-live">Find next live relay</button>' +
        '<button type="button" class="btn btn-sm" id="btn-skip-listed">Skip listed candidate</button>' +
      "</div>" +
    "</div>";

    wrap.innerHTML = html;
    var hopGrid = wrap.querySelector(".hop-grid");
    if (hopGrid) {
      hopGrid.addEventListener("click", function (e) {
        var card = e.target.closest("[data-walk-ip]");
        if (!card || card.getAttribute("data-selectable") !== "1") return;
        adoptWalkHop(card.getAttribute("data-walk-ip"));
      });
    }
    var vBtn = document.getElementById("btn-verify-now");
    if (vBtn) {
      vBtn.disabled = state.verifying;
      vBtn.addEventListener("click", function () {
        runRecursiveVerify({ ip: srv.ip, walk: true, wrap: true, forceIp: srv.ip });
      });
    }
    var nBtn = document.getElementById("btn-next-live");
    if (nBtn) {
      nBtn.disabled = state.verifying;
      nBtn.addEventListener("click", function () {
        runRecursiveVerify({
          fromIndex: state.selectedIndex + 1,
          wrap: true,
          skipIp: srv.ip
        });
      });
    }
    var sBtn = document.getElementById("btn-skip-listed");
    if (sBtn) {
      sBtn.disabled = state.verifying;
      sBtn.addEventListener("click", function () {
        if (state.verifying) return;
        state.verified = null;
        state.selectedIndex = (state.selectedIndex + 1) % candidates.length;
        renderConnectHero();
      });
    }
  }

  function renderRelaysTab() {
    var listEl = document.getElementById("relays-list");
    var metaEl = document.getElementById("relays-meta");
    if (!listEl || !metaEl) return;
    prunePenalties();

    var filtered = state.servers.filter(function (s) {
      return matchRelayQuery(s, state.relaySearch) && matchProto(s, state.relayProto);
    });
    var sorted = sortList(filtered, state.relaySort, state.relayProto);
    var liveN = sorted.filter(function (s) { return s.verify_state === "live" || s.verify_state === "partial"; }).length;
    metaEl.textContent = "Showing " + Math.min(sorted.length, state.relayLimit) + " of " + sorted.length +
      " matching relays · " + liveN + " handshake-verified";

    if (sorted.length === 0) {
      listEl.innerHTML = '<div class="card-subtitle">No relays matched your filter criteria.</div>';
      return;
    }

    var slice = sorted.slice(0, state.relayLimit);
    var out = "";
    for (var i = 0; i < slice.length; i++) {
      var s = slice[i];
      var unlocked = unlockedFor(s);
      var canL2tp = unlocked.indexOf("l2tp") !== -1;
      var canUdp = unlocked.indexOf("udp") !== -1;
      var canTcp = unlocked.indexOf("tcp") !== -1;
      var itemCls = "relay-item";
      if (s.verify_state === "live") itemCls += " live";
      if (s.verify_state === "partial") itemCls += " partial";
      if (s.verify_state === "dead") itemCls += " dead";
      out += '<div class="' + itemCls + '">' +
        '<div class="relay-top">' +
          "<div>" +
            '<div style="font-weight:700;color:#F8FAFC">' + flagEmoji(s.country_short) + " " + esc(s.country_long) +
              ' <span style="color:var(--muted);font-family:var(--mono);font-size:11.5px">(' + esc(s.country_short) + ")</span></div>" +
            '<div class="relay-host">' + esc(hostLabel(s)) + " · " + esc(s.ip) + " · " + fmtMbps(s.speed_bps) + " · " +
              (s.ping_ms >= 9999 ? "—" : s.ping_ms + " ms") + " · Score " + fmtScore(s.score) + "</div>" +
          "</div>" +
          '<div class="badges">' + renderBadges(s) + "</div>" +
        "</div>" +
        '<div class="btn-row" style="margin-top:9px">' +
          (canL2tp
            ? '<a class="btn btn-sm" style="border-color:rgba(52,211,153,0.5);color:var(--emerald)" href="' + esc(buildMobileconfigHref(s)) + '">.mobileconfig</a>'
            : (s.l2tp ? '<span class="btn btn-sm btn-lock">' + esc(lockedLabel("l2tp", "L2TP locked", s)) + "</span>" : "")) +
          (canUdp
            ? '<button type="button" class="btn btn-sm" style="border-color:rgba(56,189,248,0.5);color:var(--cyan)" data-ovpn-href="' + esc(buildOvpnHref(s, "udp")) +
              '" data-ovpn-name="' + esc(ovpnFileName(s, "udp")) + '">' + esc(ovpnExportLabel("udp", true)) + "</button>"
            : (s.openvpn && s.udp_port > 0 ? '<span class="btn btn-sm btn-lock">' + esc(lockedLabel("udp", "UDP locked", s)) + "</span>" : "")) +
          (canTcp
            ? '<button type="button" class="btn btn-sm" data-ovpn-href="' + esc(buildOvpnHref(s, "tcp")) +
              '" data-ovpn-name="' + esc(ovpnFileName(s, "tcp")) + '">' + esc(ovpnExportLabel("tcp", true)) + "</button>"
            : (s.openvpn && s.tcp_port > 0 ? '<span class="btn btn-sm btn-lock">' + esc(lockedLabel("tcp", "TCP locked", s)) + "</span>" : "")) +
          '<button type="button" class="btn btn-sm" data-verify-ip="' + esc(s.ip) + '">Verify</button>' +
        "</div>" +
      "</div>";
    }
    if (sorted.length > state.relayLimit) {
      out += '<button type="button" class="btn" id="btn-more-relays">Show more relays (' + (sorted.length - state.relayLimit) + " remaining)</button>";
    }
    listEl.innerHTML = out;
    var moreBtn = document.getElementById("btn-more-relays");
    if (moreBtn) {
      moreBtn.addEventListener("click", function () {
        state.relayLimit += 40;
        renderRelaysTab();
      });
    }
  }

  function currentSeedText() {
    var lines = [];
    for (var i = 0; i < state.mirrors.length; i++) {
      if (state.mirrors[i].portal_url) lines.push(state.mirrors[i].portal_url);
    }
    return "# VPN Gate Connect mirror seed\n# Tsukuba daily mail: https://www.vpngate.net/en/mail.aspx\n" + lines.join("\n");
  }

  function refreshSeedPre() {
    var pre = document.getElementById("mirror-seed-pre");
    if (pre) pre.textContent = currentSeedText();
  }

  function renderMirrorsTab() {
    var listEl = document.getElementById("mirrors-list");
    var cntEl = document.getElementById("mirrors-count");
    if (!listEl || !cntEl) return;
    cntEl.textContent = state.mirrors.length + " portal(s) auto-merged into the live pool";
    refreshSeedPre();
    if (state.mirrors.length === 0) {
      listEl.innerHTML = '<div class="card-subtitle">Directory empty this round — HTTPS CSV feeds were still merged.</div>';
      return;
    }
    var out = "";
    for (var i = 0; i < state.mirrors.length; i++) {
      var m = state.mirrors[i];
      var statusBadge = "";
      if (m.reachable === true) {
        statusBadge = '<span class="badge badge-live">ONLINE · ' + (m.rtt_ms || 1) + " ms · " + (m.servers_count || 0) + " relays</span>";
      } else if (m.reachable === false) {
        statusBadge = '<span class="badge badge-err">OFFLINE</span>';
      } else {
        statusBadge = '<span class="badge badge-udp">' + esc(m.source || "directory") + "</span>";
      }
      out += '<div class="relay-item">' +
        '<div class="relay-top">' +
          "<div>" +
            '<div style="font-weight:700;color:#F8FAFC">🪞 ' + esc(m.location || "Official Mirror") + "</div>" +
            '<div class="relay-host">' + esc(m.portal_url) + "</div>" +
          "</div>" +
          '<div class="badges">' + statusBadge + "</div>" +
        "</div>" +
        '<div class="btn-row" style="margin-top:8px">' +
          '<span class="badge badge-live">AUTO-MERGED</span>' +
          '<a class="btn btn-sm" href="' + esc(m.portal_url) + '" target="_blank" rel="noopener noreferrer">Open portal</a>' +
        "</div>" +
      "</div>";
    }
    listEl.innerHTML = out;
  }

  async function loadPool(forceRefresh, customMirror) {
    setStatusPill("syncing", "SYNCING");
    setStepper("pool");
    appendLog("info", forceRefresh ? "Refreshing live VPN Gate relay pool from Cloudflare edge…" : "Loading VPN Gate relay pool…");
    try {
      var qs = new URLSearchParams();
      if (forceRefresh) qs.set("refresh", "1");
      if (customMirror) qs.set("mirror", customMirror);
      var resp = await fetch("/api/servers?" + qs.toString());
      var data = await resp.json();
      if (!data || !data.ok) throw new Error((data && data.error) || "Upstream discovery error");

      state.servers = (data.servers || []).map(function (s) {
        s.hostname = stripMarkup(s.hostname);
        s.country_long = stripMarkup(s.country_long);
        s.country_short = stripMarkup(s.country_short);
        if (s.operator) s.operator = stripMarkup(s.operator);
        return s;
      });
      state.countries = (data.countries || []).map(function (c) {
        c.country_long = stripMarkup(c.country_long);
        c.country_short = stripMarkup(c.country_short);
        return c;
      });
      state.mirrors = (data.mirrors || []).map(function (m) {
        m.location = stripMarkup(m.location);
        return m;
      });
      state.counts = data.counts || state.counts;
      state.selectedIndex = 0;
      state.verified = null;
      state.attempts = [];

      if (Array.isArray(data.logs)) {
        for (var i = 0; i < data.logs.length; i++) {
          appendLog(data.logs[i].level || "info", data.logs[i].msg);
        }
      }
      setStatusPill("", "POOL · " + state.counts.total + " listed");
      renderCountryControls();
      renderConnectHero();
      renderRelaysTab();
      renderMirrorsTab();
      await runRecursiveVerify({});
    } catch (err) {
      setStatusPill("error", "DISCOVERY ISSUE");
      setStepper("fail");
      appendLog("err", "Failed to load relay pool: " + (err && err.message ? err.message : String(err)));
    }
  }

  function markServerState(ip, rec) {
    for (var j = 0; j < state.servers.length; j++) {
      if (state.servers[j].ip !== ip) continue;
      var unlocked = (rec && rec.unlocked) || [];
      var locked = (rec && rec.locked) || [];
      if (rec && (rec.ok || unlocked.length)) {
        var advN = 0;
        if (state.servers[j].l2tp) advN += 1;
        if (state.servers[j].openvpn && state.servers[j].udp_port > 0) advN += 1;
        if (state.servers[j].openvpn && state.servers[j].tcp_port > 0) advN += 1;
        state.servers[j].unlocked = unlocked;
        state.servers[j].locked = locked;
        state.servers[j].verify_state = (advN > 0 && unlocked.length >= advN) ? "live" : "partial";
        state.servers[j].verified_port = rec.port;
        state.servers[j].verified_rtt_ms = rec.rtt_ms;
        state.servers[j].dead_until = 0;
      } else {
        state.servers[j].verify_state = "dead";
        state.servers[j].unlocked = [];
        state.servers[j].locked = locked;
        state.servers[j].dead_until = (rec && rec.dead_until) ? rec.dead_until : (Date.now() + DEAD_PENALTY_MS);
      }
      break;
    }
  }

  function isAbortErr(e) {
    if (!e) return false;
    if (e.name === "AbortError") return true;
    return /abort/i.test(String(e.message || e));
  }

  function countTestingIps() {
    var n = 0;
    if (!state.testingIps) return 0;
    for (var k in state.testingIps) {
      if (state.testingIps[k]) n += 1;
    }
    return n;
  }

  function normalizeVerifyResult(data, cand, err) {
    if (err) {
      return {
        rec: { ok: false },
        unlocked: [],
        locked: [],
        attempt: { ip: cand.ip, ok: false, error: err && err.message ? err.message : String(err) },
        errorMsg: err && err.message ? err.message : String(err),
        aborted: isAbortErr(err)
      };
    }
    var attempt = data && Array.isArray(data.attempts) && data.attempts[0] ? data.attempts[0] : null;
    var unlocked = [];
    var locked = [];
    if (data && data.verified && Array.isArray(data.verified.unlocked)) unlocked = data.verified.unlocked;
    else if (attempt && Array.isArray(attempt.unlocked)) unlocked = attempt.unlocked;
    if (data && data.verified && Array.isArray(data.verified.locked)) locked = data.verified.locked;
    else if (attempt && Array.isArray(attempt.locked)) locked = attempt.locked;
    var rec = {
      ok: unlocked.length > 0,
      port: data && data.verified ? data.verified.port : (attempt && attempt.port),
      rtt_ms: data && data.verified ? data.verified.rtt_ms : (attempt && attempt.rtt_ms),
      unlocked: unlocked,
      locked: locked,
      dead_until: attempt && attempt.dead_until
    };
    return {
      rec: rec,
      unlocked: unlocked,
      locked: locked,
      attempt: attempt,
      aborted: false,
      payload: (data && data.verified) || {
        ip: cand.ip,
        unlocked: unlocked,
        locked: locked,
        port: rec.port,
        rtt_ms: rec.rtt_ms
      }
    };
  }

  async function handshakeOne(srv, force, signal) {
    var qs = new URLSearchParams();
    qs.set("ip", srv.ip);
    if (force) qs.set("force", "1");
    var ctrl = new AbortController();
    var timer = setTimeout(function () { ctrl.abort(); }, 21000);
    function onWalkAbort() { ctrl.abort(); }
    if (signal) {
      if (signal.aborted) ctrl.abort();
      else signal.addEventListener("abort", onWalkAbort);
    }
    try {
      var resp = await fetch("/api/verify?" + qs.toString(), { signal: ctrl.signal });
      return await resp.json();
    } finally {
      clearTimeout(timer);
      if (signal) signal.removeEventListener("abort", onWalkAbort);
    }
  }

  function indexOfCandidate(candidates, ip) {
    for (var i = 0; i < candidates.length; i++) {
      if (candidates[i].ip === ip) return i;
    }
    return -1;
  }

  function revealIpInConnectList(ip) {
    var candidates = getConnectCandidates();
    var idx = indexOfCandidate(candidates, ip);
    if (idx >= 0) return { candidates: candidates, index: idx };
    var raw = null;
    for (var j = 0; j < state.servers.length; j++) {
      if (state.servers[j].ip === ip) { raw = state.servers[j]; break; }
    }
    if (!raw) return { candidates: candidates, index: -1 };
    var changed = false;
    if (!matchCountry(raw, state.country)) { state.country = "ALL"; changed = true; }
    if (!matchProto(raw, state.proto)) { state.proto = "auto"; changed = true; }
    if (changed) renderCountryControls();
    candidates = getConnectCandidates();
    return { candidates: candidates, index: indexOfCandidate(candidates, ip) };
  }

  async function runRecursiveVerify(opts) {
    opts = opts || {};
    var gen = ++verifyGen;
    if (walkAbort) walkAbort.abort();
    walkAbort = new AbortController();
    var signal = walkAbort.signal;
    var WALK_CAP = 24;
    var WALK_PARALLEL = 5;
    var WALK_BOXES = 4;
    var revealed = opts.ip ? revealIpInConnectList(opts.ip) : { candidates: getConnectCandidates(), index: -1 };
    var candidates = revealed.candidates;
    if (candidates.length === 0) {
      state.verifying = false;
      state.testingIp = "";
      state.testingIps = {};
      state.walkHops = [];
      state.verified = null;
      stopElapsedTicker();
      setStepper("fail");
      setStatusPill("error", "NO RELAYS");
      renderConnectHero();
      return;
    }

    var single = Boolean(opts.ip && !opts.walk && typeof opts.fromIndex !== "number");
    var start = 0;
    if (typeof opts.fromIndex === "number") {
      start = opts.fromIndex;
      if (start < 0) start = 0;
      if (start >= candidates.length) start = 0;
    } else if (opts.ip) {
      start = revealed.index >= 0 ? revealed.index : 0;
    } else {
      start = state.selectedIndex || 0;
      if (start < 0 || start >= candidates.length) start = 0;
    }

    var order = [];
    if (single) {
      order.push(start);
    } else {
      for (var k = start; k < candidates.length; k++) order.push(k);
      if (opts.wrap) {
        for (var k2 = 0; k2 < start; k2++) order.push(k2);
      }
    }

    var jobs = [];
    for (var oi = 0; oi < order.length; oi++) {
      var oiIdx = order[oi];
      var oiCand = candidates[oiIdx];
      var oiForce = Boolean(opts.force) || (opts.forceIp && oiCand.ip === opts.forceIp);
      if (opts.skipIp && oiCand.ip === opts.skipIp) continue;
      if (!oiForce && isPenalized(oiCand)) continue;
      if (!oiForce && oiCand.verify_state && oiCand.verify_state !== "untested" && Array.isArray(oiCand.unlocked)
        && !satisfiesProto(oiCand.unlocked, state.proto)) {
        continue;
      }
      jobs.push({ index: oiIdx, cand: oiCand, forceThis: oiForce });
      if (jobs.length >= WALK_CAP) {
        appendLog("warn", "Walk cap (" + WALK_CAP + ") reached — remaining slots keep their listed numbers.");
        break;
      }
    }

    var parallel = single ? 1 : Math.min(WALK_PARALLEL, Math.max(1, jobs.length));
    state.verifying = true;
    state.verified = null;
    state.attempts = [];
    state.testingIps = {};
    state.walkHops = [];
    state.walkHeadJob = 0;
    state.selectedIndex = start;
    state.testingIp = candidates[start] ? candidates[start].ip : "";
    state.walkSlot = start + 1;
    state.walkTotal = candidates.length;
    state.walkStartedAt = Date.now();
    state.hopStartedAt = Date.now();
    state.verifyLabel = "Testing [" + (start + 1) + "/" + candidates.length + "]";
    setStepper("probe");
    setStatusPill("syncing", (start + 1) + "/" + candidates.length);
    renderConnectHero();
    startElapsedTicker();
    appendLog("info", single
      ? ("Handshake on sort slot [" + (start + 1) + "/" + candidates.length + "]")
      : ("Walking sort order from [" + (start + 1) + "/" + candidates.length +
        "] — 1 hero + " + WALK_BOXES + " prefetch hops, 17.6s each. Slot numbers stay in listed order."));

    var winner = null;
    var probed = 0;
    var lastIdx = start;
    var pending = {};
    var hopStartAt = {};
    var settledMark = {};
    var jobPayloads = {};

    function paintHead(job) {
      if (!job) return;
      state.selectedIndex = job.index;
      state.testingIp = job.cand.ip;
      state.walkSlot = job.index + 1;
      state.walkTotal = candidates.length;
      if (hopStartAt[job._job]) state.hopStartedAt = hopStartAt[job._job];
      else state.hopStartedAt = Date.now();
      state.verifyLabel = "Testing [" + (job.index + 1) + "/" + candidates.length + "] " + job.cand.ip;
      var nFlight = countTestingIps();
      setStatusPill("syncing", (job.index + 1) + "/" + candidates.length + (nFlight > 1 ? (" · " + nFlight + " hops") : ""));
    }

    function snapshotWalkWindow(headJobIdx) {
      if (typeof headJobIdx !== "number") headJobIdx = state.walkHeadJob || 0;
      var hops = [];
      var from = headJobIdx + 1;
      var until = Math.min(jobs.length, from + WALK_BOXES);
      for (var h = from; h < until; h++) {
        var job = jobs[h];
        var srv = job.cand;
        var st = "testing";
        if (settledMark[h]) {
          if (srv.verify_state === "live") st = "live";
          else if (srv.verify_state === "partial") st = "partial";
          else st = "dead";
        }
        hops.push({
          index: job.index,
          ip: srv.ip,
          host: hostLabel(srv),
          country_short: srv.country_short,
          country_long: srv.country_long,
          speed_bps: srv.speed_bps,
          ping_ms: srv.ping_ms,
          status: st,
          payload: jobPayloads[h] || null,
          startedAt: hopStartAt[h] || Date.now()
        });
      }
      state.walkHops = hops;
      state.walkHeadJob = headJobIdx;
    }

    function refreshTestingIps(headJobIdx) {
      var ips = {};
      for (var t = 0; t < jobs.length; t++) {
        if (pending[t] && !settledMark[t]) ips[jobs[t].cand.ip] = true;
      }
      state.testingIps = ips;
      if (typeof headJobIdx !== "number") headJobIdx = state.walkHeadJob;
      if (typeof headJobIdx === "number" && jobs[headJobIdx]) paintHead(jobs[headJobIdx]);
      snapshotWalkWindow(headJobIdx);
    }

    function launchJob(jobIdx) {
      if (pending[jobIdx] || jobIdx >= jobs.length) return pending[jobIdx];
      var job = jobs[jobIdx];
      job._job = jobIdx;
      hopStartAt[jobIdx] = Date.now();
      probed += 1;
      appendLog("info", "Handshake [" + (job.index + 1) + "/" + candidates.length + "] " + hostLabel(job.cand) + " · " + job.cand.ip);
      pending[jobIdx] = handshakeOne(job.cand, job.forceThis, signal).then(function (data) {
        return normalizeVerifyResult(data, job.cand, null);
      }, function (e) {
        return normalizeVerifyResult(null, job.cand, e);
      }).then(function (parsed) {
        settledMark[jobIdx] = true;
        if (gen === verifyGen && !parsed.aborted) {
          if (parsed.payload) jobPayloads[jobIdx] = parsed.payload;
          if (parsed.unlocked && parsed.unlocked.length) markServerState(job.cand.ip, parsed.rec);
          else markServerState(job.cand.ip, { ok: false, dead_until: parsed.rec.dead_until, locked: parsed.locked });
          refreshTestingIps();
          renderConnectHero();
          paintElapsed();
          renderRelaysTab();
        }
        return parsed;
      });
      return pending[jobIdx];
    }

    for (var commit = 0; commit < jobs.length; commit++) {
      if (gen !== verifyGen) return;
      for (var p = 0; p < parallel && (commit + p) < jobs.length; p++) launchJob(commit + p);
      var head = jobs[commit];
      lastIdx = head.index;
      refreshTestingIps(commit);
      setStepper("handshake");
      renderConnectHero();
      paintElapsed();

      var parsed;
      try {
        parsed = await pending[commit];
      } catch (e) {
        parsed = normalizeVerifyResult(null, head.cand, e);
      }
      if (gen !== verifyGen) return;
      if (parsed && parsed.aborted) return;

      var unlocked = (parsed && parsed.unlocked) || [];
      var rec = (parsed && parsed.rec) || { ok: false };
      var attempt = parsed && parsed.attempt;
      if (attempt) state.attempts.push(attempt);
      else if (parsed && parsed.errorMsg) {
        state.attempts.push({ ip: head.cand.ip, ok: false, error: parsed.errorMsg });
      }

      if (satisfiesProto(unlocked, state.proto)) {
        markServerState(head.cand.ip, rec);
        appendLog("ok", "LIVE [" + (head.index + 1) + "/" + candidates.length + "] " + head.cand.ip +
          " · " + unlocked.join("+").toUpperCase() +
          (rec.rtt_ms ? (" · " + rec.rtt_ms + " ms") : "") +
          " · " + fmtElapsed(Date.now() - (hopStartAt[commit] || state.hopStartedAt)));
        winner = { index: head.index, payload: parsed.payload };
        break;
      }
      if (unlocked.length) {
        markServerState(head.cand.ip, rec);
        appendLog("warn", "Partial [" + (head.index + 1) + "/" + candidates.length + "] " + head.cand.ip +
          " · unlocked " + unlocked.join("+").toUpperCase() +
          " · selected protocol still locked · next slot");
        continue;
      }
      markServerState(head.cand.ip, { ok: false, dead_until: rec.dead_until, locked: parsed.locked || [] });
      appendLog("warn", "Dead [" + (head.index + 1) + "/" + candidates.length + "] " + head.cand.ip +
        (attempt && attempt.error ? " · " + attempt.error : (parsed.errorMsg ? " · " + parsed.errorMsg : "")) +
        " · 15m pool penalty · next slot");
    }

    if (walkAbort && walkAbort === signal) walkAbort.abort();
    if (gen !== verifyGen) return;
    state.verifying = false;
    state.testingIp = "";
    state.testingIps = {};
    state.walkHops = [];
    stopElapsedTicker();
    if (winner) {
      state.selectedIndex = winner.index;
      state.verified = winner.payload;
      setStepper("profile");
      setStatusPill("", "LIVE · #" + (winner.index + 1));
      appendLog("ok", "Profiles updated for sort slot [" + (winner.index + 1) + "/" + candidates.length + "] " + winner.payload.ip +
        " · unlocked " + ((winner.payload.unlocked || []).join("+").toUpperCase() || "none") +
        " after " + probed + " handshake(s) in " + fmtElapsed(Date.now() - state.walkStartedAt) + ".");
    } else {
      state.selectedIndex = lastIdx;
      state.verified = null;
      setStepper("fail");
      setStatusPill("error", "NO LIVE PATH");
      appendLog("err", "No live handshake along the current sort order. Dead relays stay numbered and sit out 15 minutes. Profiles remain withheld.");
    }
    renderConnectHero();
    renderRelaysTab();
  }

  async function runProbeMirrors() {
    var btn = document.getElementById("btn-probe-mirrors");
    if (btn) btn.disabled = true;
    appendLog("info", "Probing Official VPNGate Mirror Sites from Cloudflare edge…");
    try {
      var resp = await fetch("/api/mirrors?probe=1");
      var data = await resp.json();
      if (data && Array.isArray(data.mirrors)) {
        state.mirrors = data.mirrors;
        renderMirrorsTab();
        appendLog("ok", "Mirror probe complete: " + (data.online_count || 0) + "/" + data.mirrors.length + " Official Mirror(s) online.");
      }
    } catch (e) {
      appendLog("err", "Mirror probe failed: " + (e && e.message ? e.message : String(e)));
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function runDoctor() {
    var box = document.getElementById("doctor-results");
    var btn = document.getElementById("btn-run-doctor");
    if (btn) btn.disabled = true;
    if (box) box.innerHTML = '<div class="card-subtitle">Running edge, DoH, handshake & profile self-tests…</div>';
    appendLog("info", "Running edge & handshake diagnostics (/api/doctor)…");
    try {
      var resp = await fetch("/api/doctor");
      var data = await resp.json();
      var checks = (data && data.checks) || [];
      var html = "";
      for (var i = 0; i < checks.length; i++) {
        var c = checks[i];
        var bCls = c.status === "READY" ? "badge-live" : (c.status === "WARN" ? "badge-tcp" : "badge-err");
        html += '<div class="relay-item">' +
          '<div class="relay-top">' +
            '<div style="font-weight:700;color:#F8FAFC">' + esc(c.name) + "</div>" +
            '<span class="badge ' + bCls + '">' + esc(c.status) + "</span>" +
          "</div>" +
          '<div class="card-subtitle" style="margin-top:4px;font-family:var(--mono)">' + esc(c.detail) + "</div>" +
        "</div>";
      }
      if (box) box.innerHTML = html;
      appendLog("ok", "Doctor diagnostics completed (" + checks.length + " checks evaluated).");
    } catch (e) {
      if (box) box.innerHTML = '<div class="card-subtitle" style="color:var(--coral)">Diagnostics failed: ' + esc(e.message || e) + "</div>";
      appendLog("err", "Doctor check error: " + (e && e.message ? e.message : String(e)));
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  function switchTab(tabId) {
    state.tab = tabId;
    var panels = document.querySelectorAll(".tab-panel");
    for (var i = 0; i < panels.length; i++) {
      panels[i].classList.toggle("active", panels[i].id === "tab-" + tabId);
    }
    var navs = document.querySelectorAll(".nav-tab");
    for (var j = 0; j < navs.length; j++) {
      navs[j].classList.toggle("active", navs[j].getAttribute("data-tab") === tabId);
    }
    if (tabId === "doctor") {
      var box = document.getElementById("doctor-results");
      if (box && !box.hasChildNodes()) runDoctor();
    }
  }

  function onFilterChange() {
    state.selectedIndex = 0;
    state.verified = null;
    renderCountryControls();
    renderConnectHero();
    runRecursiveVerify({});
  }

  function onSortChange() {
    state.selectedIndex = 0;
    renderCountryControls();
    renderConnectHero();
    renderRelaysTab();
    var top = getConnectCandidates()[0];
    if (top && state.verified && state.verified.ip === top.ip) return;
    runRecursiveVerify({});
  }

  document.addEventListener("DOMContentLoaded", function () {
    if (!state.device.mobile) {
      state.compat = "ovpn26";
      var compatSel = document.getElementById("connect-compat");
      if (compatSel) compatSel.value = "ovpn26";
    }
    var devEl = document.getElementById("detected-device");
    if (devEl) devEl.textContent = state.device.label;

    document.querySelectorAll(".nav-tab").forEach(function (btn) {
      btn.addEventListener("click", function () { switchTab(btn.getAttribute("data-tab")); });
    });

    document.getElementById("btn-refresh").addEventListener("click", function () {
      loadPool(true, state.customMirror);
    });

    document.getElementById("connect-country").addEventListener("change", function (e) {
      state.country = e.target.value;
      onFilterChange();
    });

    document.getElementById("quick-country-pills").addEventListener("click", function (e) {
      var btn = e.target.closest("[data-cc]");
      if (!btn) return;
      state.country = btn.getAttribute("data-cc");
      onFilterChange();
    });

    document.getElementById("connect-proto").addEventListener("change", function (e) {
      state.proto = e.target.value;
      onFilterChange();
    });

    document.getElementById("connect-sort-pills").addEventListener("click", function (e) {
      var btn = e.target.closest("[data-csort]");
      if (!btn) return;
      state.connectSort = btn.getAttribute("data-csort");
      document.querySelectorAll("#connect-sort-pills .chip").forEach(function (c) {
        c.classList.toggle("active", c === btn);
      });
      onSortChange();
    });

    document.getElementById("connect-compat").addEventListener("change", function (e) {
      state.compat = e.target.value;
      renderConnectHero();
      renderRelaysTab();
    });

    document.getElementById("connect-dns").addEventListener("change", function (e) {
      state.dns = e.target.value;
      renderConnectHero();
      renderRelaysTab();
    });

    document.getElementById("relay-search").addEventListener("input", function (e) {
      state.relaySearch = e.target.value;
      state.relayLimit = 40;
      renderRelaysTab();
    });

    document.getElementById("relay-proto-pills").addEventListener("click", function (e) {
      var btn = e.target.closest("[data-rproto]");
      if (!btn) return;
      state.relayProto = btn.getAttribute("data-rproto");
      document.querySelectorAll("#relay-proto-pills .chip").forEach(function (c) {
        c.classList.toggle("active", c === btn);
      });
      renderRelaysTab();
    });

    document.getElementById("relay-sort-pills").addEventListener("click", function (e) {
      var btn = e.target.closest("[data-rsort]");
      if (!btn) return;
      state.relaySort = btn.getAttribute("data-rsort");
      document.querySelectorAll("#relay-sort-pills .chip").forEach(function (c) {
        c.classList.toggle("active", c === btn);
      });
      renderRelaysTab();
    });

    document.getElementById("btn-probe-mirrors").addEventListener("click", runProbeMirrors);
    document.getElementById("btn-apply-mirror").addEventListener("click", function () {
      var val = document.getElementById("custom-mirror-input").value.trim();
      state.customMirror = val;
      loadPool(true, val);
      switchTab("connect");
    });
    var copySeedBtn = document.getElementById("btn-copy-seed");
    if (copySeedBtn) {
      copySeedBtn.addEventListener("click", function () {
        var text = currentSeedText();
        if (navigator.clipboard && navigator.clipboard.writeText) {
          navigator.clipboard.writeText(text).then(function () {
            appendLog("info", "Mirror seed copied. Photograph or QR this list for later paste.");
          }).catch(function () {
            appendLog("warn", "Clipboard blocked — copy the seed box manually.");
          });
        } else {
          appendLog("warn", "Clipboard unavailable — copy the seed box manually.");
        }
      });
    }

    document.getElementById("btn-run-doctor").addEventListener("click", runDoctor);
    document.getElementById("btn-clear-log").addEventListener("click", function () {
      document.getElementById("console-log").innerHTML = "";
      appendLog("info", "Console log cleared.");
    });

    applyInstallOs(defaultInstallOs());
    var osPills = document.getElementById("install-os-pills");
    if (osPills) {
      osPills.addEventListener("click", function (e) {
        var btn = e.target.closest("[data-install-os]");
        if (!btn) return;
        applyInstallOs(btn.getAttribute("data-install-os"));
      });
    }
    var copyBtn = document.getElementById("install-copy");
    if (copyBtn) {
      copyBtn.addEventListener("click", function () {
        copyDesktopCommand(copyBtn, "Desktop install command copied.");
      });
    }
    var uninstallBtn = document.getElementById("uninstall-copy");
    if (uninstallBtn) {
      uninstallBtn.addEventListener("click", function () {
        copyDesktopCommand(uninstallBtn, "Desktop uninstall command copied.");
      });
    }

    document.body.addEventListener("click", function (e) {
      var ovBtn = e.target.closest("[data-ovpn-href]");
      if (ovBtn) {
        e.preventDefault();
        exportOvpnFile(ovBtn.getAttribute("data-ovpn-href"), ovBtn.getAttribute("data-ovpn-name"));
        return;
      }
      var vBtn = e.target.closest("[data-verify-ip]");
      if (vBtn) {
        var vip = vBtn.getAttribute("data-verify-ip");
        switchTab("connect");
        runRecursiveVerify({ ip: vip, walk: true, wrap: true, forceIp: vip });
        return;
      }
      var mirBtn = e.target.closest("[data-use-mirror]");
      if (mirBtn) {
        var mUrl = mirBtn.getAttribute("data-use-mirror");
        state.customMirror = mUrl;
        document.getElementById("custom-mirror-input").value = mUrl;
        loadPool(true, mUrl);
        switchTab("connect");
      }
    });

    appendLog("info", "Initialized VPN Gate Web Profile Console · Device: " + state.device.label);
    appendLog("info", "Profiles stay locked until a live OpenVPN TCP handshake is proven.");
    loadPool(false, "");
  });
})();
