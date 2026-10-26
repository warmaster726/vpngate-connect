use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use md5::Md5;
use num_bigint::BigUint;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use subtle::ConstantTimeEq;
use tokio::net::{TcpStream, UdpSocket};

type HmacSha1 = Hmac<Sha1>;
type HmacMd5 = Hmac<Md5>;

/// RFC 2409 Oakley Group 2 (1024-bit MODP, generator `g = 2`) registered in SoftEther `NewIkeEngine()`.
const MODP_1024_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381",
    "FFFFFFFFFFFFFFFF"
);

/// Mandatory NAT-T + DPD + SoftEther Vendor IDs required by SoftEther `IPsec_IKE.c`.
const IKEV1_NAT_T_VIDS: &[&[u8]] = &[
    // RFC 3947 NAT-T
    &[
        0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45, 0x5c, 0x57, 0x28, 0xf2, 0x0e, 0x95, 0x45,
        0x2f,
    ],
    // draft-ietf-ipsec-nat-t-ike-02\n
    &[
        0x90, 0xcb, 0x80, 0x91, 0x3e, 0xbb, 0x69, 0x6e, 0x08, 0x63, 0x81, 0xb5, 0xec, 0x42, 0x7b,
        0x1f,
    ],
    // RFC 3706 DPD
    &[
        0xaf, 0xca, 0xd7, 0x13, 0x68, 0xa1, 0xf1, 0xc9, 0x6b, 0x86, 0x96, 0xfc, 0x77, 0x57, 0x01,
        0x00,
    ],
    // SoftEther / Microsoft L2TP-IPsec VID
    &[
        0x40, 0x48, 0xb7, 0xd5, 0x6e, 0xbc, 0xe8, 0x85, 0x25, 0xe7, 0xde, 0x7f, 0x00, 0xd6, 0xc2,
        0xd3, 0xc0, 0x00, 0x00, 0x00,
    ],
];

/// Outcome of 1-RTT IKEv1 Aggressive Mode `PSK == "vpn"` pre-flight verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum L2tpVerifyOutcome {
    /// Responder is alive and `HASH_R` cryptographically matches `PSK == "vpn"`.
    VerifiedPskVpn,
    /// Responder replied to IKEv1, but `HASH_R` did not match `PSK == "vpn"` (private router).
    PrivatePskMismatch,
    /// Peer returned an ISAKMP Informational reject (`NO_PROPOSAL_CHOSEN` / XAUTH only).
    PeerRejected,
    /// Peer replied with non-Aggressive exchange.
    NonAggressiveReply,
    /// UDP 500 timed out or unreachable.
    Timeout,
}

impl L2tpVerifyOutcome {
    pub const fn is_verified(self) -> bool {
        matches!(self, Self::VerifiedPskVpn)
    }
}

fn ike_attr_tv(attr_type: u16, val: u16) -> [u8; 4] {
    let mut out = [0u8; 4];
    out[0..2].copy_from_slice(&(0x8000 | attr_type).to_be_bytes());
    out[2..4].copy_from_slice(&val.to_be_bytes());
    out
}

/// Builds the exact SoftEther `NewIkeEngine()` SA payload:
/// `AES-256-CBC/SHA1/DH2`, `AES-128-CBC/SHA1/DH2`, `3DES-CBC/SHA1/DH2`, `3DES-CBC/MD5/DH2` (`PSK`).
pub fn build_softether_sa_payload() -> Vec<u8> {
    let specs: [(u16, u16, u16, u16); 4] =
        [(7, 256, 2, 2), (7, 128, 2, 2), (5, 0, 2, 2), (5, 0, 1, 2)];

    let mut transforms = Vec::new();
    for (idx, (enc_id, key_len, hash_id, dh_grp)) in specs.iter().enumerate() {
        let mut attrs = Vec::with_capacity(28);
        attrs.extend_from_slice(&ike_attr_tv(1, *enc_id));
        if *key_len > 0 {
            attrs.extend_from_slice(&ike_attr_tv(14, *key_len));
        }
        attrs.extend_from_slice(&ike_attr_tv(2, *hash_id));
        attrs.extend_from_slice(&ike_attr_tv(3, 1)); // PSK auth
        attrs.extend_from_slice(&ike_attr_tv(4, *dh_grp));
        attrs.extend_from_slice(&ike_attr_tv(11, 1)); // LifeType = seconds
        attrs.extend_from_slice(&ike_attr_tv(12, 28800)); // 28800s

        let next_p = if idx + 1 == specs.len() { 0u8 } else { 3u8 };
        let t_len = (8 + attrs.len()) as u16;
        transforms.push(next_p);
        transforms.push(0);
        transforms.extend_from_slice(&t_len.to_be_bytes());
        transforms.push((idx + 1) as u8);
        transforms.push(1); // KEY_IKE
        transforms.extend_from_slice(&0u16.to_be_bytes());
        transforms.extend_from_slice(&attrs);
    }

    let prop_len = (8 + transforms.len()) as u16;
    let mut sa = Vec::with_capacity(16 + transforms.len());
    sa.extend_from_slice(&1u32.to_be_bytes()); // DOI = IPsec (1)
    sa.extend_from_slice(&1u32.to_be_bytes()); // Situation = SIT_IDENTITY_ONLY (1)
    sa.push(0); // NextPayload = NONE
    sa.push(0);
    sa.extend_from_slice(&prop_len.to_be_bytes());
    sa.push(1); // Proposal #1
    sa.push(1); // Proto = ISAKMP
    sa.push(0); // SPI size = 0
    sa.push(specs.len() as u8);
    sa.extend_from_slice(&transforms);
    sa
}

fn encode_payload_chain(payloads: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (idx, (_, body)) in payloads.iter().enumerate() {
        let next_np = if idx + 1 < payloads.len() {
            payloads[idx + 1].0
        } else {
            0u8
        };
        let plen = (4 + body.len()) as u16;
        out.push(next_np);
        out.push(0);
        out.extend_from_slice(&plen.to_be_bytes());
        out.extend_from_slice(body);
    }
    out
}

/// Builds IKEv1 Main Mode Packet 1 (`ExchangeType = 2`) body appended after 8-byte Initiator Cookie.
pub fn build_main_mode_body() -> Vec<u8> {
    let sa = build_softether_sa_payload();
    let mut payloads = Vec::with_capacity(1 + IKEV1_NAT_T_VIDS.len());
    payloads.push((1u8, sa));
    for vid in IKEV1_NAT_T_VIDS {
        payloads.push((13u8, vid.to_vec()));
    }
    let encoded = encode_payload_chain(&payloads);
    let total_len = (28 + encoded.len()) as u32;

    let mut body = Vec::with_capacity(20 + encoded.len());
    body.extend_from_slice(&[0u8; 8]); // Responder cookie = 0
    body.push(1); // First payload = SA (1)
    body.push(0x10); // Version 1.0
    body.push(2); // ExchangeType = Identity Protection (Main Mode)
    body.push(0); // Flags
    body.extend_from_slice(&0u32.to_be_bytes()); // Message ID
    body.extend_from_slice(&total_len.to_be_bytes());
    body.extend_from_slice(&encoded);
    body
}

struct AggressiveProbePacket {
    packet: Vec<u8>,
    icookie: [u8; 8],
    gxi: Vec<u8>,
    ni: [u8; 20],
    sa_body: Vec<u8>,
}

fn build_aggressive_mode_packet() -> AggressiveProbePacket {
    let p = BigUint::parse_bytes(MODP_1024_HEX.as_bytes(), 16).expect("valid Oakley Group 2 prime");
    let g = BigUint::from(2u32);

    let mut priv_bytes = [0u8; 32];
    let mut ni = [0u8; 20];
    let mut icookie = [0u8; 8];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut priv_bytes);
    rng.fill_bytes(&mut ni);
    rng.fill_bytes(&mut icookie);

    let priv_x = BigUint::from_bytes_be(&priv_bytes);
    let gxi_raw = g.modpow(&priv_x, &p).to_bytes_be();
    let mut gxi = vec![0u8; 128];
    let offset = 128usize.saturating_sub(gxi_raw.len());
    gxi[offset..].copy_from_slice(&gxi_raw[gxi_raw.len().saturating_sub(128)..]);

    let sa_body = build_softether_sa_payload();
    // ID_IPV4_ADDR (type 1, proto 0, port 0, 10.0.0.2)
    let idi_body = vec![1u8, 0, 0, 0, 10, 0, 0, 2];

    let mut payloads = vec![
        (1u8, sa_body.clone()),
        (4u8, gxi.clone()),
        (10u8, ni.to_vec()),
        (5u8, idi_body),
    ];
    for vid in IKEV1_NAT_T_VIDS {
        payloads.push((13u8, vid.to_vec()));
    }

    let encoded = encode_payload_chain(&payloads);
    let total_len = (28 + encoded.len()) as u32;

    let mut packet = Vec::with_capacity(28 + encoded.len());
    packet.extend_from_slice(&icookie);
    packet.extend_from_slice(&[0u8; 8]);
    packet.push(1); // NextPayload = SA
    packet.push(0x10); // IKEv1
    packet.push(4); // ExchangeType = Aggressive (4)
    packet.push(0);
    packet.extend_from_slice(&0u32.to_be_bytes());
    packet.extend_from_slice(&total_len.to_be_bytes());
    packet.extend_from_slice(&encoded);

    AggressiveProbePacket {
        packet,
        icookie,
        gxi,
        ni,
        sa_body,
    }
}

struct AggressiveHashContext<'a> {
    ni: &'a [u8],
    nr: &'a [u8],
    gxr: &'a [u8],
    gxi: &'a [u8],
    rcookie: &'a [u8],
    icookie: &'a [u8],
    sa_body: &'a [u8],
    idr_body: &'a [u8],
}

fn verify_aggressive_hash_r(psk: &[u8], ctx: &AggressiveHashContext<'_>, hash_r: &[u8]) -> bool {
    let mut msg = Vec::with_capacity(
        ctx.gxr.len()
            + ctx.gxi.len()
            + ctx.rcookie.len()
            + ctx.icookie.len()
            + ctx.sa_body.len()
            + ctx.idr_body.len(),
    );
    msg.extend_from_slice(ctx.gxr);
    msg.extend_from_slice(ctx.gxi);
    msg.extend_from_slice(ctx.rcookie);
    msg.extend_from_slice(ctx.icookie);
    msg.extend_from_slice(ctx.sa_body);
    msg.extend_from_slice(ctx.idr_body);

    // Check HMAC-SHA1 (20 bytes)
    if hash_r.len() == 20
        && let Ok(mut skey_mac) = HmacSha1::new_from_slice(psk)
    {
        skey_mac.update(ctx.ni);
        skey_mac.update(ctx.nr);
        let skeyid = skey_mac.finalize().into_bytes();
        if let Ok(mut prf) = HmacSha1::new_from_slice(&skeyid) {
            prf.update(&msg);
            let expected = prf.finalize().into_bytes();
            if bool::from(expected.as_slice().ct_eq(hash_r)) {
                return true;
            }
        }
    }

    // Check HMAC-MD5 (16 bytes)
    if hash_r.len() == 16
        && let Ok(mut skey_mac) = HmacMd5::new_from_slice(psk)
    {
        skey_mac.update(ctx.ni);
        skey_mac.update(ctx.nr);
        let skeyid = skey_mac.finalize().into_bytes();
        if let Ok(mut prf) = HmacMd5::new_from_slice(&skeyid) {
            prf.update(&msg);
            let expected = prf.finalize().into_bytes();
            if bool::from(expected.as_slice().ct_eq(hash_r)) {
                return true;
            }
        }
    }

    false
}

/// Cryptographically verifies in 1 UDP RTT whether `(ip, 500)` is a live SoftEther-compatible
/// IKEv1 L2TP/IPsec responder whose Pre-Shared Key equals `psk` (default `b"vpn"`).
pub async fn verify_l2tp_psk_vpn(
    ip: Ipv4Addr,
    per_try_timeout: Duration,
    retries: usize,
    psk: &[u8],
) -> L2tpVerifyOutcome {
    let mut last = L2tpVerifyOutcome::Timeout;
    let target = SocketAddr::new(IpAddr::V4(ip), 500);

    for _ in 0..retries.max(1) {
        let probe = build_aggressive_mode_packet();
        let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
            continue;
        };
        if sock.send_to(&probe.packet, target).await.is_err() {
            continue;
        }

        let mut buf = [0u8; 4096];
        let Ok(Ok((n, _))) = tokio::time::timeout(per_try_timeout, sock.recv_from(&mut buf)).await
        else {
            continue;
        };
        let resp = &buf[..n];
        if resp.len() < 28 || resp[0..8] != probe.icookie || resp[17] != 0x10 {
            continue;
        }

        let exch = resp[18];
        if exch == 5 {
            return L2tpVerifyOutcome::PeerRejected;
        }
        if exch != 4 {
            last = L2tpVerifyOutcome::NonAggressiveReply;
            continue;
        }

        let rcookie = &resp[8..16];
        let mut parsed: HashMap<u8, &[u8]> = HashMap::new();
        let mut off = 28usize;
        let mut cur_np = resp[16];
        while cur_np != 0 && off + 4 <= resp.len() {
            let next_np = resp[off];
            let plen = u16::from_be_bytes([resp[off + 2], resp[off + 3]]) as usize;
            if plen < 4 || off + plen > resp.len() {
                break;
            }
            parsed.entry(cur_np).or_insert(&resp[off + 4..off + plen]);
            off += plen;
            cur_np = next_np;
        }

        if let (Some(gxr), Some(nr), Some(idr), Some(hash_r)) = (
            parsed.get(&4),
            parsed.get(&10),
            parsed.get(&5),
            parsed.get(&8),
        ) {
            let ctx = AggressiveHashContext {
                ni: &probe.ni,
                nr,
                gxr,
                gxi: &probe.gxi,
                rcookie,
                icookie: &probe.icookie,
                sa_body: &probe.sa_body,
                idr_body: idr,
            };
            if verify_aggressive_hash_r(psk, &ctx, hash_r) {
                return L2tpVerifyOutcome::VerifiedPskVpn;
            }
            return L2tpVerifyOutcome::PrivatePskMismatch;
        }
    }

    last
}

/// Multiplexed multi-socket UDP `500` Main Mode SA+NAT-T sweep (sharded at 240 IPs per socket
/// so home/mobile NAT tables never drop conntrack entries).
pub async fn sweep_ikev1_sa_responders(ips: &[Ipv4Addr], window: Duration) -> HashSet<Ipv4Addr> {
    if ips.is_empty() {
        return HashSet::new();
    }
    let body = build_main_mode_body();
    let mut live_ips = HashSet::new();
    let mut sockets = Vec::new();
    let mut cookies: HashMap<Ipv4Addr, (usize, [u8; 8])> = HashMap::with_capacity(ips.len());

    let mut rng = rand::thread_rng();
    for (shard_idx, shard) in ips.chunks(240).enumerate() {
        let Ok(sock) = UdpSocket::bind("0.0.0.0:0").await else {
            continue;
        };
        for &ip in shard {
            let mut ic = [0u8; 8];
            rng.fill_bytes(&mut ic);
            cookies.insert(ip, (shard_idx, ic));
        }
        sockets.push(sock);
    }
    if sockets.is_empty() {
        return live_ips;
    }

    // Initial transmit wave
    for (&ip, &(s_idx, ic)) in &cookies {
        if let Some(sock) = sockets.get(s_idx) {
            let mut pkt = Vec::with_capacity(8 + body.len());
            pkt.extend_from_slice(&ic);
            pkt.extend_from_slice(&body);
            let _ = sock
                .send_to(&pkt, SocketAddr::new(IpAddr::V4(ip), 500))
                .await;
        }
    }

    let start = Instant::now();
    let retransmit_at = start + window.mul_f32(0.45);
    let mut deadline = start + window;
    let mut resent = false;
    let mut buf = [0u8; 2048];

    while Instant::now() < deadline {
        if !resent && Instant::now() >= retransmit_at {
            resent = true;
            for (&ip, &(s_idx, ic)) in &cookies {
                if !live_ips.contains(&ip)
                    && let Some(sock) = sockets.get(s_idx)
                {
                    let mut pkt = Vec::with_capacity(8 + body.len());
                    pkt.extend_from_slice(&ic);
                    pkt.extend_from_slice(&body);
                    let _ = sock
                        .send_to(&pkt, SocketAddr::new(IpAddr::V4(ip), 500))
                        .await;
                }
            }
            let min_tail = Instant::now() + Duration::from_millis(850);
            if min_tail > deadline {
                deadline = min_tail;
            }
        }

        for sock in &sockets {
            while let Ok((n, SocketAddr::V4(peer))) = sock.try_recv_from(&mut buf) {
                let rip = *peer.ip();
                if n >= 28
                    && let Some(&(_, expected_ic)) = cookies.get(&rip)
                    && buf[0..8] == expected_ic
                    && buf[17] == 0x10
                    && buf[18] == 2
                    && buf[16] == 1
                {
                    live_ips.insert(rip);
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    live_ips
}

/// Fast async TCP reachability & RTT check (for OpenVPN TCP pre-flight verification).
pub async fn probe_tcp(addr: SocketAddr, timeout: Duration) -> Option<Duration> {
    let t0 = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => Some(t0.elapsed()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_valid_isakmp_main_and_aggressive_packets() {
        let mm = build_main_mode_body();
        // Body excludes 8-byte initiator cookie, so ISAKMP total_len == 8 + mm.len()
        let total_len = u32::from_be_bytes([mm[16], mm[17], mm[18], mm[19]]) as usize;
        assert_eq!(total_len, 8 + mm.len());
        assert_eq!(mm[9], 0x10);
        assert_eq!(mm[10], 2);

        let am = build_aggressive_mode_packet();
        let am_len =
            u32::from_be_bytes([am.packet[24], am.packet[25], am.packet[26], am.packet[27]])
                as usize;
        assert_eq!(am_len, am.packet.len());
        assert_eq!(am.packet[18], 4);
        assert_eq!(am.gxi.len(), 128);
    }

    #[test]
    fn verifies_rfc2409_aggressive_hash_r_sha1() {
        let psk = b"vpn";
        let ni = [0x11u8; 20];
        let nr = [0x22u8; 20];
        let gxr = [0x33u8; 128];
        let gxi = [0x44u8; 128];
        let rcookie = [0x55u8; 8];
        let icookie = [0x66u8; 8];
        let sa = build_softether_sa_payload();
        let idr = [1u8, 0, 0, 0, 203, 0, 113, 5];

        let mut sk = HmacSha1::new_from_slice(psk).unwrap();
        sk.update(&ni);
        sk.update(&nr);
        let skeyid = sk.finalize().into_bytes();

        let mut prf = HmacSha1::new_from_slice(&skeyid).unwrap();
        prf.update(&gxr);
        prf.update(&gxi);
        prf.update(&rcookie);
        prf.update(&icookie);
        prf.update(&sa);
        prf.update(&idr);
        let tag = prf.finalize().into_bytes();

        let ctx = AggressiveHashContext {
            ni: &ni,
            nr: &nr,
            gxr: &gxr,
            gxi: &gxi,
            rcookie: &rcookie,
            icookie: &icookie,
            sa_body: &sa,
            idr_body: &idr,
        };
        assert!(verify_aggressive_hash_r(b"vpn", &ctx, &tag));
        assert!(!verify_aggressive_hash_r(b"wrongpsk", &ctx, &tag));
    }
}
