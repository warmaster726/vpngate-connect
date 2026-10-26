//! Pure-Rust user-space `L2TP/IPsec` (`IKEv1 + ESP-in-UDP + L2TPv2 + PPP/IPCP`) engine
//! for Android `VpnService` (and any unprivileged Unix `TUN` file descriptor) where kernel
//! `XFRM` and `/dev/ppp` are unavailable.

use std::net::Ipv4Addr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use md5::{Digest as _, Md5};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use subtle::ConstantTimeEq;

use crate::ikev1_daemon::{
    IkeCipher, UserspaceIkeEspSession, ike_cbc_crypt, negotiate_userspace_ikev1_esp,
};

type HmacSha1 = Hmac<Sha1>;

pub const MOBILE_L2TP_MTU: u16 = 1360;

/// Negotiated IPv4 parameters returned once user-space `IKEv1 -> ESP -> L2TPv2 -> PPP/IPCP` completes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserspaceL2tpConfig {
    pub server_ip: String,
    pub assigned_ip: String,
    pub peer_ip: String,
    pub dns_primary: String,
    pub dns_secondary: String,
    pub mtu: u16,
    pub esp_cipher: String,
}

/// Live traffic & state snapshot of an active user-space L2TP/IPsec tunnel.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserspaceL2tpStats {
    pub active: bool,
    pub server_ip: String,
    pub assigned_ip: String,
    pub esp_cipher: String,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub error: String,
}

/// Encrypts and authenticates an outbound L2TPv2 packet inside UDP(1701) + RFC 4303 ESP Transport.
#[allow(clippy::too_many_arguments)]
pub fn esp_seal_l2tp_udp(
    cipher: IkeCipher,
    enc_key: &[u8],
    auth_key: &[u8],
    spi_out: u32,
    seq_out: u32,
    src_l2tp_port: u16,
    dst_l2tp_port: u16,
    l2tp_payload: &[u8],
) -> Result<Vec<u8>, String> {
    let blen = cipher.block_len();
    let udp_len = (8 + l2tp_payload.len()) as u16;
    let mut plain = Vec::with_capacity(8 + l2tp_payload.len() + blen + 2);
    plain.extend_from_slice(&src_l2tp_port.to_be_bytes());
    plain.extend_from_slice(&dst_l2tp_port.to_be_bytes());
    plain.extend_from_slice(&udp_len.to_be_bytes());
    plain.extend_from_slice(&0u16.to_be_bytes()); // IPv4 UDP checksum optional (0)
    plain.extend_from_slice(l2tp_payload);

    let rem = (plain.len() + 2) % blen;
    let pad_len = if rem == 0 { 0 } else { blen - rem };
    for i in 1..=pad_len {
        plain.push(i as u8);
    }
    plain.push(pad_len as u8);
    plain.push(17u8); // Next Header = UDP (17)

    let mut iv = vec![0u8; blen];
    rand::thread_rng().fill_bytes(&mut iv);
    let ciphertext = ike_cbc_crypt(cipher, enc_key, &iv, &plain, true)?;

    let mut esp = Vec::with_capacity(8 + blen + ciphertext.len() + 12);
    esp.extend_from_slice(&spi_out.to_be_bytes());
    esp.extend_from_slice(&seq_out.to_be_bytes());
    esp.extend_from_slice(&iv);
    esp.extend_from_slice(&ciphertext);

    let mut mac = HmacSha1::new_from_slice(auth_key).map_err(|e| e.to_string())?;
    mac.update(&esp);
    let tag = mac.finalize().into_bytes();
    esp.extend_from_slice(&tag[..12]);
    Ok(esp)
}

/// Verifies HMAC-SHA1-96 ICV and decrypts an inbound RFC 4303 ESP Transport packet into `(peer_udp_port, l2tp_bytes)`.
pub fn esp_open_l2tp_udp(
    cipher: IkeCipher,
    enc_key: &[u8],
    auth_key: &[u8],
    expected_spi_in: u32,
    pkt: &[u8],
) -> Result<(u16, Vec<u8>), String> {
    let blen = cipher.block_len();
    if pkt.len() < 8 + blen + blen + 12 {
        return Err("ESP packet too short".to_string());
    }
    let rx_spi = u32::from_be_bytes([pkt[0], pkt[1], pkt[2], pkt[3]]);
    if rx_spi != expected_spi_in {
        return Err("ESP SPI mismatch".to_string());
    }
    let (authenticated, rx_icv) = pkt.split_at(pkt.len() - 12);
    let mut mac = HmacSha1::new_from_slice(auth_key).map_err(|e| e.to_string())?;
    mac.update(authenticated);
    let calc_full = mac.finalize().into_bytes();
    if !bool::from(calc_full[..12].ct_eq(rx_icv)) {
        return Err("ESP HMAC-SHA1-96 authentication failed".to_string());
    }

    let iv = &authenticated[8..8 + blen];
    let ciphertext = &authenticated[8 + blen..];
    let plain = ike_cbc_crypt(cipher, enc_key, iv, ciphertext, false)?;
    if plain.len() < 10 {
        return Err("Decrypted ESP payload too short".to_string());
    }
    let next_hdr = plain[plain.len() - 1];
    let pad_len = plain[plain.len() - 2] as usize;
    if next_hdr != 17 || pad_len + 2 + 8 > plain.len() {
        return Err(format!(
            "Unexpected ESP inner protocol {next_hdr} or padding"
        ));
    }
    let udp = &plain[..plain.len() - 2 - pad_len];
    let src_port = u16::from_be_bytes([udp[0], udp[1]]);
    let udp_declared_len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    let end = udp_declared_len.clamp(8, udp.len());
    Ok((src_port, udp[8..end].to_vec()))
}

fn l2tp_avp(mandatory: bool, attr_type: u16, value: &[u8]) -> Vec<u8> {
    let len = (6 + value.len()) as u16;
    let flags_len = (if mandatory { 0x8000 } else { 0 }) | (len & 0x03FF);
    let mut out = Vec::with_capacity(6 + value.len());
    out.extend_from_slice(&flags_len.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // IETF Vendor = 0
    out.extend_from_slice(&attr_type.to_be_bytes());
    out.extend_from_slice(value);
    out
}

fn parse_l2tp_avps(mut buf: &[u8]) -> Vec<(u16, Vec<u8>)> {
    let mut out = Vec::new();
    while buf.len() >= 6 {
        let flags_len = u16::from_be_bytes([buf[0], buf[1]]);
        let alen = (flags_len & 0x03FF) as usize;
        if alen < 6 || alen > buf.len() {
            break;
        }
        let vendor = u16::from_be_bytes([buf[2], buf[3]]);
        let atype = u16::from_be_bytes([buf[4], buf[5]]);
        if vendor == 0 {
            out.push((atype, buf[6..alen].to_vec()));
        }
        buf = &buf[alen..];
    }
    out
}

fn build_l2tp_ctrl(tunnel_id: u16, session_id: u16, ns: u16, nr: u16, avps: &[Vec<u8>]) -> Vec<u8> {
    let body_len: usize = avps.iter().map(Vec::len).sum();
    let total_len = (12 + body_len) as u16;
    let mut pkt = Vec::with_capacity(total_len as usize);
    pkt.extend_from_slice(&0xC802u16.to_be_bytes()); // T=1, L=1, S=1, Ver=2
    pkt.extend_from_slice(&total_len.to_be_bytes());
    pkt.extend_from_slice(&tunnel_id.to_be_bytes());
    pkt.extend_from_slice(&session_id.to_be_bytes());
    pkt.extend_from_slice(&ns.to_be_bytes());
    pkt.extend_from_slice(&nr.to_be_bytes());
    for a in avps {
        pkt.extend_from_slice(a);
    }
    pkt
}

fn build_l2tp_data(tunnel_id: u16, session_id: u16, ppp_proto: u16, ppp_body: &[u8]) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(10 + ppp_body.len());
    pkt.extend_from_slice(&0x0002u16.to_be_bytes()); // T=0, Ver=2
    pkt.extend_from_slice(&tunnel_id.to_be_bytes());
    pkt.extend_from_slice(&session_id.to_be_bytes());
    pkt.push(0xFF);
    pkt.push(0x03);
    pkt.extend_from_slice(&ppp_proto.to_be_bytes());
    pkt.extend_from_slice(ppp_body);
    pkt
}

enum ParsedL2tpFrame {
    Control {
        ns: u16,
        avps: Vec<(u16, Vec<u8>)>,
    },
    Data {
        ppp_proto: u16,
        ppp_payload: Vec<u8>,
    },
}

fn parse_l2tp_frame(pkt: &[u8]) -> Option<ParsedL2tpFrame> {
    if pkt.len() < 6 {
        return None;
    }
    let flags_ver = u16::from_be_bytes([pkt[0], pkt[1]]);
    if (flags_ver & 0x000F) != 2 {
        return None;
    }
    let is_ctrl = (flags_ver & 0x8000) != 0;
    let has_len = (flags_ver & 0x4000) != 0;
    let has_seq = (flags_ver & 0x0800) != 0;
    let has_off = (flags_ver & 0x0200) != 0;

    let mut pos = 2usize;
    let mut end = pkt.len();
    if has_len {
        if pos + 2 > pkt.len() {
            return None;
        }
        let declared = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]) as usize;
        end = declared.min(pkt.len());
        pos += 2;
    }
    if pos + 4 > end {
        return None;
    }
    let _tun_id = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
    let _ses_id = u16::from_be_bytes([pkt[pos + 2], pkt[pos + 3]]);
    pos += 4;

    let mut ns = 0u16;
    if has_seq {
        if pos + 4 > end {
            return None;
        }
        ns = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
        pos += 4;
    }
    if has_off {
        if pos + 2 > end {
            return None;
        }
        let off_size = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]) as usize;
        pos += 2 + off_size;
    }
    if pos > end {
        return None;
    }
    let body = &pkt[pos..end];
    if is_ctrl {
        return Some(ParsedL2tpFrame::Control {
            ns,
            avps: parse_l2tp_avps(body),
        });
    }

    // Parse PPP header (optional 0xFF 0x03 ACFC + 1- or 2-byte PFC protocol)
    let mut p = body;
    if p.len() >= 2 && p[0] == 0xFF && p[1] == 0x03 {
        p = &p[2..];
    }
    if p.is_empty() {
        return None;
    }
    let (ppp_proto, payload) = if (p[0] & 1) == 1 {
        (u16::from(p[0]), &p[1..])
    } else if p.len() >= 2 {
        (u16::from_be_bytes([p[0], p[1]]), &p[2..])
    } else {
        return None;
    };
    Some(ParsedL2tpFrame::Data {
        ppp_proto,
        ppp_payload: payload.to_vec(),
    })
}

fn ppp_pkt(code: u8, id: u8, data: &[u8]) -> Vec<u8> {
    let len = (4 + data.len()) as u16;
    let mut b = Vec::with_capacity(len as usize);
    b.push(code);
    b.push(id);
    b.extend_from_slice(&len.to_be_bytes());
    b.extend_from_slice(data);
    b
}

/// Computes RFC 1994 CHAP-MD5 response `MD5(id || secret || challenge)`.
pub fn compute_chap_md5(chap_id: u8, secret: &[u8], challenge: &[u8]) -> [u8; 16] {
    let mut h = Md5::new();
    h.update([chap_id]);
    h.update(secret);
    h.update(challenge);
    h.finalize().into()
}

struct LiveEspL2tpDriver {
    ike: UserspaceIkeEspSession,
    seq_out: u32,
    local_l2tp_port: u16,
    peer_l2tp_port: u16,
    local_tun_id: u16,
    peer_tun_id: u16,
    peer_ses_id: u16,
    ns: u16,
    nr: u16,
    magic: u32,
}

impl LiveEspL2tpDriver {
    fn send_esp_l2tp(&mut self, l2tp_bytes: &[u8]) -> Result<(), String> {
        self.seq_out = self.seq_out.wrapping_add(1);
        let pkt = esp_seal_l2tp_udp(
            self.ike.esp_cipher,
            &self.ike.enc_out,
            &self.ike.auth_out,
            self.ike.spi_out,
            self.seq_out,
            self.local_l2tp_port,
            self.peer_l2tp_port,
            l2tp_bytes,
        )?;
        let _ = self.ike.s4500.send(&pkt);
        Ok(())
    }

    fn send_ctrl(&mut self, session_id: u16, avps: &[Vec<u8>]) -> Result<(), String> {
        let pkt = build_l2tp_ctrl(self.peer_tun_id, session_id, self.ns, self.nr, avps);
        self.ns = self.ns.wrapping_add(1);
        self.send_esp_l2tp(&pkt)
    }

    fn send_zlb_ack(&mut self) -> Result<(), String> {
        let pkt = build_l2tp_ctrl(self.peer_tun_id, 0, self.ns, self.nr, &[]);
        self.send_esp_l2tp(&pkt)
    }

    fn send_ppp(&mut self, proto: u16, body: &[u8]) -> Result<(), String> {
        let pkt = build_l2tp_data(self.peer_tun_id, self.peer_ses_id, proto, body);
        self.send_esp_l2tp(&pkt)
    }
}

/// Active handle to a running user-space L2TP/IPsec background packet pump thread.
pub struct UserspaceL2tpHandle {
    pub config: UserspaceL2tpConfig,
    pub stop_flag: Arc<AtomicBool>,
    pub active_flag: Arc<AtomicBool>,
    pub tx_bytes: Arc<AtomicU64>,
    pub rx_bytes: Arc<AtomicU64>,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl UserspaceL2tpHandle {
    pub fn stats(&self) -> UserspaceL2tpStats {
        UserspaceL2tpStats {
            active: self.active_flag.load(Ordering::Relaxed),
            server_ip: self.config.server_ip.clone(),
            assigned_ip: self.config.assigned_ip.clone(),
            esp_cipher: self.config.esp_cipher.clone(),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            error: String::new(),
        }
    }

    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::SeqCst);
        if let Some(j) = self.worker.take() {
            let _ = j.join();
        }
        self.active_flag.store(false, Ordering::SeqCst);
    }
}

impl Drop for UserspaceL2tpHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

fn negotiate_l2tp_ppp_ipcp(
    server_ip: Ipv4Addr,
    dns_override: &[String],
    timeout_secs: u64,
    protect_fd: Option<&dyn Fn(i32) -> bool>,
    stop_flag: &AtomicBool,
) -> Result<(LiveEspL2tpDriver, UserspaceL2tpConfig), String> {
    let ike = negotiate_userspace_ikev1_esp(server_ip, protect_fd)?;
    let mut rng = rand::thread_rng();
    let mut rand_b = [0u8; 8];
    rng.fill_bytes(&mut rand_b);
    let local_tun_id = (u16::from_be_bytes([rand_b[0], rand_b[1]]) & 0x7FFF).max(1);
    let local_ses_id = (u16::from_be_bytes([rand_b[2], rand_b[3]]) & 0x7FFF).max(1);
    let magic = u32::from_be_bytes([rand_b[4], rand_b[5], rand_b[6], rand_b[7]]) | 1;

    let mut drv = LiveEspL2tpDriver {
        ike,
        seq_out: 0,
        local_l2tp_port: 1701,
        peer_l2tp_port: 1701,
        local_tun_id,
        peer_tun_id: 0,
        peer_ses_id: 0,
        ns: 0,
        nr: 0,
        magic,
    };

    let _ = drv
        .ike
        .s4500
        .set_read_timeout(Some(Duration::from_millis(250)));

    // 1. Send L2TP SCCRQ (MsgType = 1)
    let sccrq_avps = vec![
        l2tp_avp(true, 0, &1u16.to_be_bytes()), // MsgType = SCCRQ (1)
        l2tp_avp(true, 2, &[1, 0]),             // Protocol Version 1.0
        l2tp_avp(true, 7, b"vpngate-mobile"),   // Host Name
        l2tp_avp(true, 3, &3u32.to_be_bytes()), // Framing Capabilities (Sync + Async)
        l2tp_avp(true, 9, &local_tun_id.to_be_bytes()), // Assigned Tunnel ID
    ];
    let sccrq_pkt = build_l2tp_ctrl(0, 0, 0, 0, &sccrq_avps);
    drv.ns = 1;
    drv.send_esp_l2tp(&sccrq_pkt)?;

    let deadline = Instant::now() + Duration::from_secs(timeout_secs.max(18));
    let mut last_retransmit = Instant::now();
    let mut stage = 0u8; // 0=wait SCCRP, 1=wait ICRP, 2=PPP LCP/Auth, 3=IPCP, 4=Established
    let mut lcp_peer_acked = false;
    let mut lcp_our_acked = false;
    let mut auth_proto: u16 = 0; // 0=none, 0xC023=PAP, 0xC223=CHAP
    let mut auth_done = false;
    let mut ipcp_sent = false;
    let mut req_ip = Ipv4Addr::UNSPECIFIED;
    let mut peer_ip = Ipv4Addr::new(10, 211, 254, 254);
    let mut dns1 = Ipv4Addr::new(1, 1, 1, 1);
    let mut dns2 = Ipv4Addr::new(1, 0, 0, 1);
    let mut ask_dns_opts = true;
    let mut lcp_use_mru = true;
    let mut lcp_use_magic = true;
    let mut lcp_req_id = 1u8;
    let mut ipcp_req_id = 1u8;
    let mut rx_buf = [0u8; 4096];

    let build_our_lcp_opts = |use_mru: bool, use_magic: bool, magic_val: u32| -> Vec<u8> {
        let mut opts = Vec::new();
        if use_mru {
            opts.extend_from_slice(&[1, 4]);
            opts.extend_from_slice(&MOBILE_L2TP_MTU.to_be_bytes());
        }
        if use_magic {
            opts.extend_from_slice(&[5, 6]);
            opts.extend_from_slice(&magic_val.to_be_bytes());
        }
        opts
    };

    while Instant::now() < deadline && stage < 4 && !stop_flag.load(Ordering::Relaxed) {
        if last_retransmit.elapsed() >= Duration::from_millis(1200) {
            last_retransmit = Instant::now();
            if stage == 0 {
                drv.send_esp_l2tp(&sccrq_pkt)?;
            } else if stage == 2 && !lcp_our_acked {
                let opts = build_our_lcp_opts(lcp_use_mru, lcp_use_magic, drv.magic);
                drv.send_ppp(0xC021, &ppp_pkt(1, lcp_req_id, &opts))?;
            } else if stage == 3 {
                let mut opts = Vec::new();
                opts.extend_from_slice(&[3, 6]);
                opts.extend_from_slice(&req_ip.octets());
                if ask_dns_opts {
                    opts.extend_from_slice(&[129, 6]);
                    opts.extend_from_slice(&dns1.octets());
                    opts.extend_from_slice(&[131, 6]);
                    opts.extend_from_slice(&dns2.octets());
                }
                drv.send_ppp(0x8021, &ppp_pkt(1, ipcp_req_id, &opts))?;
            }
        }

        let Ok(n) = drv.ike.s4500.recv(&mut rx_buf) else {
            continue;
        };
        let raw = &rx_buf[..n];
        if raw == [0xFF] {
            continue;
        }
        if raw.len() >= 32 && raw[0..4] == [0, 0, 0, 0] {
            drv.ike.handle_non_esp_ike_packet(raw);
            continue;
        }
        let Ok((peer_port, l2tp_raw)) = esp_open_l2tp_udp(
            drv.ike.esp_cipher,
            &drv.ike.enc_in,
            &drv.ike.auth_in,
            drv.ike.spi_in,
            raw,
        ) else {
            continue;
        };
        drv.peer_l2tp_port = peer_port;

        let Some(frame) = parse_l2tp_frame(&l2tp_raw) else {
            continue;
        };
        match frame {
            ParsedL2tpFrame::Control { ns, avps } => {
                if ns == drv.nr && !avps.is_empty() {
                    drv.nr = drv.nr.wrapping_add(1);
                }
                let msg_type = avps
                    .iter()
                    .find(|(t, v)| *t == 0 && v.len() == 2)
                    .map(|(_, v)| u16::from_be_bytes([v[0], v[1]]))
                    .unwrap_or(0);

                match msg_type {
                    2 if stage == 0 => {
                        if let Some((_, v)) = avps.iter().find(|(t, v)| *t == 9 && v.len() == 2) {
                            drv.peer_tun_id = u16::from_be_bytes([v[0], v[1]]);
                        }
                        drv.send_ctrl(0, &[l2tp_avp(true, 0, &3u16.to_be_bytes())])?;
                        let icrq_avps = vec![
                            l2tp_avp(true, 0, &10u16.to_be_bytes()),
                            l2tp_avp(true, 14, &local_ses_id.to_be_bytes()),
                            l2tp_avp(true, 15, &1u32.to_be_bytes()),
                        ];
                        drv.send_ctrl(0, &icrq_avps)?;
                        stage = 1;
                    }
                    11 if stage == 1 => {
                        if let Some((_, v)) = avps.iter().find(|(t, v)| *t == 14 && v.len() == 2) {
                            drv.peer_ses_id = u16::from_be_bytes([v[0], v[1]]);
                        }
                        let iccn_avps = vec![
                            l2tp_avp(true, 0, &12u16.to_be_bytes()),
                            l2tp_avp(true, 24, &100_000_000u32.to_be_bytes()),
                            l2tp_avp(true, 19, &1u32.to_be_bytes()),
                        ];
                        let pkt = build_l2tp_ctrl(
                            drv.peer_tun_id,
                            drv.peer_ses_id,
                            drv.ns,
                            drv.nr,
                            &iccn_avps,
                        );
                        drv.ns = drv.ns.wrapping_add(1);
                        drv.send_esp_l2tp(&pkt)?;

                        let opts = build_our_lcp_opts(lcp_use_mru, lcp_use_magic, drv.magic);
                        drv.send_ppp(0xC021, &ppp_pkt(1, lcp_req_id, &opts))?;
                        last_retransmit = Instant::now();
                        stage = 2;
                    }
                    6 => drv.send_zlb_ack()?,
                    4 | 14 => {
                        return Err("Remote VPN Gate relay closed L2TP control session".to_string());
                    }
                    _ => {
                        if msg_type != 0 {
                            drv.send_zlb_ack()?;
                        }
                    }
                }
            }
            ParsedL2tpFrame::Data {
                ppp_proto,
                ppp_payload,
            } => {
                if ppp_payload.len() < 4 {
                    continue;
                }
                let code = ppp_payload[0];
                let id = ppp_payload[1];
                let plen = u16::from_be_bytes([ppp_payload[2], ppp_payload[3]]) as usize;
                if plen < 4 || plen > ppp_payload.len() {
                    continue;
                }
                let body = &ppp_payload[4..plen];

                match ppp_proto {
                    0xC021 => {
                        match code {
                            1 => {
                                let mut ack_opts = Vec::new();
                                let mut nak_opts = Vec::new();
                                let mut rej_opts = Vec::new();
                                let mut off = 0usize;
                                while off + 2 <= body.len() {
                                    let otype = body[off];
                                    let olen = body[off + 1] as usize;
                                    if olen < 2 || off + olen > body.len() {
                                        break;
                                    }
                                    let oval = &body[off..off + olen];
                                    match otype {
                                        1 | 2 | 5 | 7 | 8 => ack_opts.extend_from_slice(oval),
                                        3 if olen >= 4 => {
                                            let ap = u16::from_be_bytes([oval[2], oval[3]]);
                                            if ap == 0xC023 {
                                                auth_proto = 0xC023;
                                                ack_opts.extend_from_slice(oval);
                                            } else if ap == 0xC223 && olen >= 5 && oval[4] == 5 {
                                                auth_proto = 0xC223;
                                                ack_opts.extend_from_slice(oval);
                                            } else {
                                                nak_opts.extend_from_slice(&[3, 5, 0xC2, 0x23, 5]);
                                            }
                                        }
                                        _ => rej_opts.extend_from_slice(oval),
                                    }
                                    off += olen;
                                }
                                if !rej_opts.is_empty() {
                                    drv.send_ppp(0xC021, &ppp_pkt(4, id, &rej_opts))?;
                                } else if !nak_opts.is_empty() {
                                    drv.send_ppp(0xC021, &ppp_pkt(3, id, &nak_opts))?;
                                } else {
                                    drv.send_ppp(0xC021, &ppp_pkt(2, id, &ack_opts))?;
                                    lcp_peer_acked = true;
                                }
                            }
                            2 => lcp_our_acked = true,
                            3 | 4 => {
                                let mut off = 0usize;
                                while off + 2 <= body.len() {
                                    let otype = body[off];
                                    let olen = body[off + 1] as usize;
                                    if olen < 2 || off + olen > body.len() {
                                        break;
                                    }
                                    if otype == 1 {
                                        lcp_use_mru = false;
                                    } else if otype == 5 {
                                        lcp_use_magic = false;
                                    }
                                    off += olen;
                                }
                                lcp_req_id = lcp_req_id.wrapping_add(1);
                                let opts =
                                    build_our_lcp_opts(lcp_use_mru, lcp_use_magic, drv.magic);
                                drv.send_ppp(0xC021, &ppp_pkt(1, lcp_req_id, &opts))?;
                                last_retransmit = Instant::now();
                            }
                            9 if body.len() >= 4 => {
                                let mut rep = drv.magic.to_be_bytes().to_vec();
                                rep.extend_from_slice(&body[4..]);
                                drv.send_ppp(0xC021, &ppp_pkt(10, id, &rep))?;
                            }
                            5 => return Err("PPP LCP Terminate-Request received".to_string()),
                            _ => {}
                        }

                        if lcp_peer_acked && lcp_our_acked && !auth_done {
                            if auth_proto == 0 {
                                auth_done = true;
                            } else if auth_proto == 0xC023 {
                                let pap_body = [3, b'v', b'p', b'n', 3, b'v', b'p', b'n'];
                                drv.send_ppp(0xC023, &ppp_pkt(1, 1, &pap_body))?;
                            }
                        }
                        if lcp_peer_acked && lcp_our_acked && auth_done && !ipcp_sent {
                            ipcp_sent = true;
                            stage = 3;
                            let mut opts = Vec::new();
                            opts.extend_from_slice(&[3, 6, 0, 0, 0, 0]);
                            opts.extend_from_slice(&[129, 6, 0, 0, 0, 0]);
                            opts.extend_from_slice(&[131, 6, 0, 0, 0, 0]);
                            drv.send_ppp(0x8021, &ppp_pkt(1, ipcp_req_id, &opts))?;
                            last_retransmit = Instant::now();
                        }
                    }
                    0xC023 => {
                        if code == 2 {
                            auth_done = true;
                            if !ipcp_sent {
                                ipcp_sent = true;
                                stage = 3;
                                let mut opts = Vec::new();
                                opts.extend_from_slice(&[3, 6, 0, 0, 0, 0]);
                                opts.extend_from_slice(&[129, 6, 0, 0, 0, 0]);
                                opts.extend_from_slice(&[131, 6, 0, 0, 0, 0]);
                                drv.send_ppp(0x8021, &ppp_pkt(1, ipcp_req_id, &opts))?;
                                last_retransmit = Instant::now();
                            }
                        } else if code == 3 {
                            return Err("PPP PAP authentication rejected".to_string());
                        }
                    }
                    0xC223 => match code {
                        1 if !body.is_empty() => {
                            let vsize = body[0] as usize;
                            if body.len() > vsize {
                                let chal = &body[1..1 + vsize];
                                let md5_resp = compute_chap_md5(id, b"vpn", chal);
                                let mut resp = Vec::with_capacity(1 + 16 + 3);
                                resp.push(16);
                                resp.extend_from_slice(&md5_resp);
                                resp.extend_from_slice(b"vpn");
                                drv.send_ppp(0xC223, &ppp_pkt(2, id, &resp))?;
                            }
                        }
                        3 => {
                            auth_done = true;
                            if !ipcp_sent {
                                ipcp_sent = true;
                                stage = 3;
                                let mut opts = Vec::new();
                                opts.extend_from_slice(&[3, 6, 0, 0, 0, 0]);
                                opts.extend_from_slice(&[129, 6, 0, 0, 0, 0]);
                                opts.extend_from_slice(&[131, 6, 0, 0, 0, 0]);
                                drv.send_ppp(0x8021, &ppp_pkt(1, ipcp_req_id, &opts))?;
                                last_retransmit = Instant::now();
                            }
                        }
                        4 => return Err("PPP CHAP-MD5 authentication rejected".to_string()),
                        _ => {}
                    },
                    0x8021 => match code {
                        1 => {
                            let mut rej = Vec::new();
                            let mut ack = Vec::new();
                            let mut off = 0usize;
                            while off + 2 <= body.len() {
                                let otype = body[off];
                                let olen = body[off + 1] as usize;
                                if olen < 2 || off + olen > body.len() {
                                    break;
                                }
                                let oval = &body[off..off + olen];
                                if otype == 3 && olen == 6 {
                                    peer_ip = Ipv4Addr::new(oval[2], oval[3], oval[4], oval[5]);
                                    ack.extend_from_slice(oval);
                                } else {
                                    rej.extend_from_slice(oval);
                                }
                                off += olen;
                            }
                            if !rej.is_empty() {
                                drv.send_ppp(0x8021, &ppp_pkt(4, id, &rej))?;
                            } else {
                                drv.send_ppp(0x8021, &ppp_pkt(2, id, &ack))?;
                            }
                        }
                        2 if !req_ip.is_unspecified() => stage = 4,
                        3 => {
                            let mut off = 0usize;
                            while off + 2 <= body.len() {
                                let otype = body[off];
                                let olen = body[off + 1] as usize;
                                if olen < 2 || off + olen > body.len() {
                                    break;
                                }
                                if olen == 6 {
                                    let ip = Ipv4Addr::new(
                                        body[off + 2],
                                        body[off + 3],
                                        body[off + 4],
                                        body[off + 5],
                                    );
                                    match otype {
                                        3 => req_ip = ip,
                                        129 => dns1 = ip,
                                        131 => dns2 = ip,
                                        _ => {}
                                    }
                                }
                                off += olen;
                            }
                            ipcp_req_id = ipcp_req_id.wrapping_add(1);
                            let mut opts = Vec::new();
                            opts.extend_from_slice(&[3, 6]);
                            opts.extend_from_slice(&req_ip.octets());
                            if ask_dns_opts {
                                opts.extend_from_slice(&[129, 6]);
                                opts.extend_from_slice(&dns1.octets());
                                opts.extend_from_slice(&[131, 6]);
                                opts.extend_from_slice(&dns2.octets());
                            }
                            drv.send_ppp(0x8021, &ppp_pkt(1, ipcp_req_id, &opts))?;
                            last_retransmit = Instant::now();
                        }
                        4 => {
                            ask_dns_opts = false;
                            ipcp_req_id = ipcp_req_id.wrapping_add(1);
                            let mut opts = Vec::new();
                            opts.extend_from_slice(&[3, 6]);
                            opts.extend_from_slice(&req_ip.octets());
                            drv.send_ppp(0x8021, &ppp_pkt(1, ipcp_req_id, &opts))?;
                            last_retransmit = Instant::now();
                        }
                        _ => {}
                    },
                    other => {
                        let mut preject = other.to_be_bytes().to_vec();
                        preject.extend_from_slice(&ppp_payload[..ppp_payload.len().min(48)]);
                        lcp_req_id = lcp_req_id.wrapping_add(1);
                        drv.send_ppp(0xC021, &ppp_pkt(8, lcp_req_id, &preject))?;
                    }
                }
            }
        }
    }

    if stage < 4 || req_ip.is_unspecified() {
        drv.ike.send_delete_sa();
        return Err("User-space L2TP/PPP negotiation timed out before IPCP completed".to_string());
    }

    let eff_dns1 = dns_override
        .first()
        .cloned()
        .unwrap_or_else(|| dns1.to_string());
    let eff_dns2 = dns_override
        .get(1)
        .cloned()
        .unwrap_or_else(|| dns2.to_string());

    let cfg = UserspaceL2tpConfig {
        server_ip: server_ip.to_string(),
        assigned_ip: req_ip.to_string(),
        peer_ip: peer_ip.to_string(),
        dns_primary: eff_dns1,
        dns_secondary: eff_dns2,
        mtu: MOBILE_L2TP_MTU,
        esp_cipher: drv.ike.esp_alg_label.clone(),
    };
    Ok((drv, cfg))
}

/// Negotiates `IKEv1 -> ESP -> L2TPv2 -> PPP/IPCP` synchronously on the caller's thread
/// (so Android `JNIEnv*` callbacks `protect_fd` and `establish_tun` never cross thread boundaries),
/// then spawns a detached pure-Rust packet pump thread on `tun_fd`.
pub fn spawn_userspace_l2tp_session(
    server_ip: Ipv4Addr,
    dns_override: &[String],
    timeout_secs: u64,
    protect_fd: Option<&dyn Fn(i32) -> bool>,
    establish_tun: &mut dyn FnMut(&UserspaceL2tpConfig) -> Result<i32, String>,
) -> Result<UserspaceL2tpHandle, String> {
    let stop_flag = Arc::new(AtomicBool::new(false));
    let active_flag = Arc::new(AtomicBool::new(true));
    let tx_bytes = Arc::new(AtomicU64::new(0));
    let rx_bytes = Arc::new(AtomicU64::new(0));

    let (mut drv, cfg) = negotiate_l2tp_ppp_ipcp(
        server_ip,
        dns_override,
        timeout_secs,
        protect_fd,
        &stop_flag,
    )?;

    let tun_fd = match establish_tun(&cfg) {
        Ok(fd) => fd,
        Err(e) => {
            let stop_avps = vec![
                l2tp_avp(true, 0, &4u16.to_be_bytes()),
                l2tp_avp(true, 1, &1u16.to_be_bytes()),
                l2tp_avp(true, 9, &drv.local_tun_id.to_be_bytes()),
            ];
            let _ = drv.send_ctrl(0, &stop_avps);
            drv.ike.send_delete_sa();
            return Err(e);
        }
    };

    if tun_fd < 0 {
        let stop_avps = vec![
            l2tp_avp(true, 0, &4u16.to_be_bytes()),
            l2tp_avp(true, 1, &1u16.to_be_bytes()),
            l2tp_avp(true, 9, &drv.local_tun_id.to_be_bytes()),
        ];
        let _ = drv.send_ctrl(0, &stop_avps);
        drv.ike.send_delete_sa();
        active_flag.store(false, Ordering::SeqCst);
        return Ok(UserspaceL2tpHandle {
            config: cfg,
            stop_flag,
            active_flag,
            tx_bytes,
            rx_bytes,
            worker: None,
        });
    }

    let stop_bg = Arc::clone(&stop_flag);
    let active_bg = Arc::clone(&active_flag);
    let tx_bg = Arc::clone(&tx_bytes);
    let rx_bg = Arc::clone(&rx_bytes);

    let worker = std::thread::Builder::new()
        .name("vpngate-l2tp-pump".to_string())
        .spawn(move || {
            pump_tun_and_esp(&mut drv, tun_fd, &stop_bg, &tx_bg, &rx_bg);
            let stop_avps = vec![
                l2tp_avp(true, 0, &4u16.to_be_bytes()),
                l2tp_avp(true, 1, &1u16.to_be_bytes()),
                l2tp_avp(true, 9, &drv.local_tun_id.to_be_bytes()),
            ];
            let _ = drv.send_ctrl(0, &stop_avps);
            drv.ike.send_delete_sa();
            close_tun_fd(tun_fd);
            active_bg.store(false, Ordering::SeqCst);
        })
        .map_err(|e| {
            close_tun_fd(tun_fd);
            format!("Failed spawning L2TP packet pump thread: {e}")
        })?;

    Ok(UserspaceL2tpHandle {
        config: cfg,
        stop_flag,
        active_flag,
        tx_bytes,
        rx_bytes,
        worker: Some(worker),
    })
}

/// Negotiates full user-space `IKEv1 -> ESP-in-UDP -> L2TPv2 -> PPP (LCP + PAP/CHAP + IPCP)`
/// with a VPN Gate relay and pumps IPv4 packets over `tun_fd` until `stop_flag` is set.
#[allow(clippy::too_many_arguments)]
pub fn run_userspace_l2tp_session(
    server_ip: Ipv4Addr,
    dns_override: &[String],
    timeout_secs: u64,
    protect_fd: Option<&dyn Fn(i32) -> bool>,
    establish_tun: &mut dyn FnMut(&UserspaceL2tpConfig) -> Result<i32, String>,
    stop_flag: &AtomicBool,
    tx_counter: &Arc<AtomicU64>,
    rx_counter: &Arc<AtomicU64>,
) -> Result<(), String> {
    let (mut drv, cfg) =
        negotiate_l2tp_ppp_ipcp(server_ip, dns_override, timeout_secs, protect_fd, stop_flag)?;
    let tun_fd = establish_tun(&cfg)?;
    if tun_fd < 0 {
        let stop_avps = vec![
            l2tp_avp(true, 0, &4u16.to_be_bytes()),
            l2tp_avp(true, 1, &1u16.to_be_bytes()),
            l2tp_avp(true, 9, &drv.local_tun_id.to_be_bytes()),
        ];
        let _ = drv.send_ctrl(0, &stop_avps);
        drv.ike.send_delete_sa();
        return Ok(());
    }

    pump_tun_and_esp(&mut drv, tun_fd, stop_flag, tx_counter, rx_counter);

    let stop_avps = vec![
        l2tp_avp(true, 0, &4u16.to_be_bytes()),
        l2tp_avp(true, 1, &1u16.to_be_bytes()),
        l2tp_avp(true, 9, &drv.local_tun_id.to_be_bytes()),
    ];
    let _ = drv.send_ctrl(0, &stop_avps);
    drv.ike.send_delete_sa();
    close_tun_fd(tun_fd);
    Ok(())
}

#[cfg(unix)]
fn close_tun_fd(fd: i32) {
    if fd >= 0 {
        unsafe {
            let _ = libc::close(fd);
        }
    }
}

#[cfg(not(unix))]
fn close_tun_fd(_fd: i32) {}

#[cfg(unix)]
fn pump_tun_and_esp(
    drv: &mut LiveEspL2tpDriver,
    tun_fd: i32,
    stop_flag: &AtomicBool,
    tx_counter: &Arc<AtomicU64>,
    rx_counter: &Arc<AtomicU64>,
) {
    use std::os::fd::AsRawFd;
    let udp_fd = drv.ike.s4500.as_raw_fd();
    unsafe {
        let fl_t = libc::fcntl(tun_fd, libc::F_GETFL, 0);
        if fl_t >= 0 {
            let _ = libc::fcntl(tun_fd, libc::F_SETFL, fl_t | libc::O_NONBLOCK);
        }
        let fl_u = libc::fcntl(udp_fd, libc::F_GETFL, 0);
        if fl_u >= 0 {
            let _ = libc::fcntl(udp_fd, libc::F_SETFL, fl_u | libc::O_NONBLOCK);
        }
    }

    let mut last_ka = Instant::now();
    let mut tun_buf = [0u8; 2048];
    let mut udp_buf = [0u8; 4096];

    while !stop_flag.load(Ordering::Relaxed) {
        let mut pfd = [
            libc::pollfd {
                fd: tun_fd,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: udp_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];

        let rc = unsafe { libc::poll(pfd.as_mut_ptr(), 2, 250) };
        if rc > 0 {
            if (pfd[0].revents & libc::POLLIN) != 0 {
                loop {
                    let n = unsafe {
                        libc::read(tun_fd, tun_buf.as_mut_ptr().cast::<libc::c_void>(), 2000)
                    };
                    if n <= 0 {
                        break;
                    }
                    let pkt = &tun_buf[..n as usize];
                    // Forward IPv4 packets (version nibble == 4)
                    if !pkt.is_empty() && (pkt[0] >> 4) == 4 && drv.send_ppp(0x0021, pkt).is_ok() {
                        tx_counter.fetch_add(n as u64, Ordering::Relaxed);
                    }
                }
            }

            if (pfd[1].revents & libc::POLLIN) != 0 {
                while let Ok(n) = drv.ike.s4500.recv(&mut udp_buf) {
                    let raw = &udp_buf[..n];
                    if raw == [0xFF] {
                        continue;
                    }
                    if raw.len() >= 32 && raw[0..4] == [0, 0, 0, 0] {
                        drv.ike.handle_non_esp_ike_packet(raw);
                        continue;
                    }
                    let Ok((peer_port, l2tp_raw)) = esp_open_l2tp_udp(
                        drv.ike.esp_cipher,
                        &drv.ike.enc_in,
                        &drv.ike.auth_in,
                        drv.ike.spi_in,
                        raw,
                    ) else {
                        continue;
                    };
                    drv.peer_l2tp_port = peer_port;
                    let Some(frame) = parse_l2tp_frame(&l2tp_raw) else {
                        continue;
                    };
                    match frame {
                        ParsedL2tpFrame::Control { ns, avps, .. } => {
                            if ns == drv.nr && !avps.is_empty() {
                                drv.nr = drv.nr.wrapping_add(1);
                            }
                            let mtype = avps
                                .iter()
                                .find(|(t, v)| *t == 0 && v.len() == 2)
                                .map(|(_, v)| u16::from_be_bytes([v[0], v[1]]))
                                .unwrap_or(0);
                            if mtype == 6 {
                                let _ = drv.send_zlb_ack();
                            } else if mtype == 4 || mtype == 14 {
                                stop_flag.store(true, Ordering::SeqCst);
                                break;
                            } else if mtype != 0 {
                                let _ = drv.send_zlb_ack();
                            }
                        }
                        ParsedL2tpFrame::Data {
                            ppp_proto,
                            ppp_payload,
                        } => {
                            if ppp_proto == 0x0021 && !ppp_payload.is_empty() {
                                let written = unsafe {
                                    libc::write(
                                        tun_fd,
                                        ppp_payload.as_ptr().cast::<libc::c_void>(),
                                        ppp_payload.len(),
                                    )
                                };
                                if written > 0 {
                                    rx_counter.fetch_add(written as u64, Ordering::Relaxed);
                                }
                            } else if ppp_proto == 0xC021
                                && ppp_payload.len() >= 8
                                && ppp_payload[0] == 9
                            {
                                // Reply to LCP Echo-Request during active data session!
                                let id = ppp_payload[1];
                                let mut rep = drv.magic.to_be_bytes().to_vec();
                                rep.extend_from_slice(&ppp_payload[8..]);
                                let _ = drv.send_ppp(0xC021, &ppp_pkt(10, id, &rep));
                            } else if ppp_proto == 0xC021
                                && !ppp_payload.is_empty()
                                && ppp_payload[0] == 5
                            {
                                stop_flag.store(true, Ordering::SeqCst);
                                break;
                            }
                        }
                    }
                }
            }
        }

        if last_ka.elapsed() >= Duration::from_secs(18) {
            last_ka = Instant::now();
            let _ = drv.ike.s4500.send(&[0xFF]);
        }
    }
}

#[cfg(not(unix))]
fn pump_tun_and_esp(
    _drv: &mut LiveEspL2tpDriver,
    _tun_fd: i32,
    _stop_flag: &AtomicBool,
    _tx_counter: &Arc<AtomicU64>,
    _rx_counter: &Arc<AtomicU64>,
) {
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_and_opens_rfc4303_esp_l2tp_roundtrip() {
        let enc_key = [0x42u8; 32];
        let auth_key = [0x99u8; 20];
        let sample = build_l2tp_data(12, 34, 0x0021, &[0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4]);
        let sealed = esp_seal_l2tp_udp(
            IkeCipher::Aes256,
            &enc_key,
            &auth_key,
            0xAABB_CCDD,
            1,
            1701,
            1701,
            &sample,
        )
        .expect("ESP seal succeeds");
        let (sport, opened) =
            esp_open_l2tp_udp(IkeCipher::Aes256, &enc_key, &auth_key, 0xAABB_CCDD, &sealed)
                .expect("ESP open succeeds");
        assert_eq!(sport, 1701);
        assert_eq!(opened, sample);

        let Some(ParsedL2tpFrame::Data {
            ppp_proto,
            ppp_payload,
        }) = parse_l2tp_frame(&opened)
        else {
            panic!("Expected parsed L2TP data frame");
        };
        assert_eq!(ppp_proto, 0x0021);
        assert_eq!(ppp_payload, vec![0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4]);
    }

    #[test]
    fn computes_rfc1994_chap_md5_digest() {
        let digest = compute_chap_md5(7, b"vpn", &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(digest.len(), 16);
    }

    #[test]
    #[ignore]
    fn live_diag_softether_l2tp() {
        let server_ip: Ipv4Addr = "219.100.37.1".parse().unwrap();
        let stop = AtomicBool::new(false);
        let (drv, cfg) =
            negotiate_l2tp_ppp_ipcp(server_ip, &[], 12, None, &stop).expect("L2TP IPCP succeeds");
        assert!(!cfg.assigned_ip.is_empty());
        drv.ike.send_delete_sa();
    }
}
