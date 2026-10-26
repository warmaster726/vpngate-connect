use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use aes::{Aes128, Aes256};
use cbc::{Decryptor, Encryptor};
use cipher::block_padding::NoPadding;
use cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use des::TdesEde3;
use hmac::{Hmac, Mac};
use md5::{Digest as _, Md5};
use num_bigint::BigUint;
use rand::RngCore;
use sha1::Sha1;
use subtle::ConstantTimeEq;

use crate::cache::{Ikev1StateInfo, atomic_write_json, now_unix_secs};

type HmacSha1 = Hmac<Sha1>;
type HmacMd5 = Hmac<Md5>;

pub const VPNGATE_XFRM_REQID: &str = "17010";

const MODP_1024_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1",
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD",
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED",
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381",
    "FFFFFFFFFFFFFFFF"
);

const IKEV1_NAT_T_VIDS: &[&[u8]] = &[
    &[
        0x4a, 0x13, 0x1c, 0x81, 0x07, 0x03, 0x58, 0x45, 0x5c, 0x57, 0x28, 0xf2, 0x0e, 0x95, 0x45,
        0x2f,
    ],
    &[
        0x90, 0xcb, 0x80, 0x91, 0x3e, 0xbb, 0x69, 0x6e, 0x08, 0x63, 0x81, 0xb5, 0xec, 0x42, 0x7b,
        0x1f,
    ],
    &[
        0xaf, 0xca, 0xd7, 0x13, 0x68, 0xa1, 0xf1, 0xc9, 0x6b, 0x86, 0x96, 0xfc, 0x77, 0x57, 0x01,
        0x00,
    ],
    &[
        0x40, 0x48, 0xb7, 0xd5, 0x6e, 0xbc, 0xe8, 0x85, 0x25, 0xe7, 0xde, 0x7f, 0x00, 0xd6, 0xc2,
        0xd3, 0xc0, 0x00, 0x00, 0x00,
    ],
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IkeCipher {
    Aes256,
    Aes128,
    Des3,
}

impl IkeCipher {
    pub const fn key_len(self) -> usize {
        match self {
            Self::Aes256 => 32,
            Self::Aes128 => 16,
            Self::Des3 => 24,
        }
    }

    pub const fn block_len(self) -> usize {
        match self {
            Self::Aes256 | Self::Aes128 => 16,
            Self::Des3 => 8,
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Aes256 => "aes256",
            Self::Aes128 => "aes128",
            Self::Des3 => "3des",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IkeHash {
    Sha1,
    Md5,
}

impl IkeHash {
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => Sha1::digest(data).to_vec(),
            Self::Md5 => Md5::digest(data).to_vec(),
        }
    }

    pub fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha1 => {
                let mut m = HmacSha1::new_from_slice(key).expect("HMAC accepts any key size");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
            Self::Md5 => {
                let mut m = HmacMd5::new_from_slice(key).expect("HMAC accepts any key size");
                m.update(data);
                m.finalize().into_bytes().to_vec()
            }
        }
    }
}

/// Pure-Rust raw-block CBC encryption/decryption for IKEv1 payloads (zero OpenSSL dependency).
pub fn ike_cbc_crypt(
    alg: IkeCipher,
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    encrypt: bool,
) -> std::result::Result<Vec<u8>, String> {
    let blen = alg.block_len();
    if data.is_empty() || !data.len().is_multiple_of(blen) {
        return Err(format!(
            "IKEv1 CBC payload length {} is not a multiple of block size {blen}",
            data.len()
        ));
    }
    let mut buf = data.to_vec();
    match (alg, encrypt) {
        (IkeCipher::Aes256, true) => {
            Encryptor::<Aes256>::new_from_slices(key, iv)
                .map_err(|e| e.to_string())?
                .encrypt_padded_mut::<NoPadding>(&mut buf, data.len())
                .map_err(|e| e.to_string())?;
        }
        (IkeCipher::Aes256, false) => {
            Decryptor::<Aes256>::new_from_slices(key, iv)
                .map_err(|e| e.to_string())?
                .decrypt_padded_mut::<NoPadding>(&mut buf)
                .map_err(|e| e.to_string())?;
        }
        (IkeCipher::Aes128, true) => {
            Encryptor::<Aes128>::new_from_slices(key, iv)
                .map_err(|e| e.to_string())?
                .encrypt_padded_mut::<NoPadding>(&mut buf, data.len())
                .map_err(|e| e.to_string())?;
        }
        (IkeCipher::Aes128, false) => {
            Decryptor::<Aes128>::new_from_slices(key, iv)
                .map_err(|e| e.to_string())?
                .decrypt_padded_mut::<NoPadding>(&mut buf)
                .map_err(|e| e.to_string())?;
        }
        (IkeCipher::Des3, true) => {
            Encryptor::<TdesEde3>::new_from_slices(key, iv)
                .map_err(|e| e.to_string())?
                .encrypt_padded_mut::<NoPadding>(&mut buf, data.len())
                .map_err(|e| e.to_string())?;
        }
        (IkeCipher::Des3, false) => {
            Decryptor::<TdesEde3>::new_from_slices(key, iv)
                .map_err(|e| e.to_string())?
                .decrypt_padded_mut::<NoPadding>(&mut buf)
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(buf)
}

/// RFC 2409 Appendix B key expansion (`SKEYID_e` -> 24B 3DES / 32B AES-256).
pub fn ike_expand_key(hash: IkeHash, seed: &[u8], target_len: usize) -> Vec<u8> {
    if seed.len() >= target_len {
        return seed[..target_len].to_vec();
    }
    let mut out = Vec::with_capacity(target_len + 20);
    let mut prev = vec![0u8];
    while out.len() < target_len {
        prev = hash.hmac(seed, &prev);
        out.extend_from_slice(&prev);
    }
    out.truncate(target_len);
    out
}

/// RFC 2409 §5.5 Phase 2 ESP `KEYMAT` derivation (no-PFS).
pub fn ike_calc_keymat(
    hash: IkeHash,
    skeyid_d: &[u8],
    proto: u8,
    spi: u32,
    ni: &[u8],
    nr: &[u8],
    needed: usize,
) -> Vec<u8> {
    let mut seed = Vec::with_capacity(5 + ni.len() + nr.len());
    seed.push(proto);
    seed.extend_from_slice(&spi.to_be_bytes());
    seed.extend_from_slice(ni);
    seed.extend_from_slice(nr);

    let mut out = Vec::with_capacity(needed + 20);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < needed {
        let mut input = Vec::with_capacity(prev.len() + seed.len());
        input.extend_from_slice(&prev);
        input.extend_from_slice(&seed);
        prev = hash.hmac(skeyid_d, &input);
        out.extend_from_slice(&prev);
    }
    out.truncate(needed);
    out
}

/// Runs non-destructive cryptographic + socket self-tests for `vpngate doctor`.
pub fn run_ikev1_crypto_self_test() -> std::result::Result<(), String> {
    let mut rng = rand::thread_rng();
    for alg in [IkeCipher::Aes256, IkeCipher::Aes128, IkeCipher::Des3] {
        let mut key = vec![0u8; alg.key_len()];
        let mut iv = vec![0u8; alg.block_len()];
        let mut pt = vec![0u8; alg.block_len() * 2];
        rng.fill_bytes(&mut key);
        rng.fill_bytes(&mut iv);
        rng.fill_bytes(&mut pt);
        let ct = ike_cbc_crypt(alg, &key, &iv, &pt, true)?;
        let rt = ike_cbc_crypt(alg, &key, &iv, &ct, false)?;
        if rt != pt {
            return Err(format!("{} CBC roundtrip mismatch", alg.label()));
        }
    }

    let p = BigUint::parse_bytes(MODP_1024_HEX.as_bytes(), 16).ok_or("MODP-1024 parse failed")?;
    let pub_dh = BigUint::from(2u32).modpow(&BigUint::from(0x1234_5678_9abc_def1u64), &p);
    if pub_dh <= BigUint::from(1u32) {
        return Err("MODP-1024 modular exponentiation failed".to_string());
    }

    let km = ike_calc_keymat(
        IkeHash::Sha1,
        b"skeyid_d_20byte_seed",
        3,
        0x1234_5678,
        b"ni",
        b"nr",
        52,
    );
    if km.len() != 52 {
        return Err("KEYMAT length mismatch".to_string());
    }

    let sock = UdpSocket::bind("127.0.0.1:0").map_err(|e| format!("UDP bind failed: {e}"))?;
    enable_linux_espinudp(&sock)?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn enable_linux_espinudp(sock: &UdpSocket) -> std::result::Result<(), String> {
    use std::os::fd::AsRawFd;
    let val: libc::c_int = 2; // UDP_ENCAP_ESPINUDP = 2
    // SAFETY: `sock.as_raw_fd()` is a valid UDP socket descriptor; `SOL_UDP=17`, `UDP_ENCAP=100`.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            17,
            100,
            (&raw const val).cast::<libc::c_void>(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(format!(
            "setsockopt(UDP_ENCAP_ESPINUDP) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn enable_linux_espinudp(_sock: &UdpSocket) -> std::result::Result<(), String> {
    Ok(())
}

fn ike_attr_tv(attr_type: u16, val: u16) -> [u8; 4] {
    let mut b = [0u8; 4];
    b[0..2].copy_from_slice(&(0x8000 | attr_type).to_be_bytes());
    b[2..4].copy_from_slice(&val.to_be_bytes());
    b
}

fn ike_attr_tlv(attr_type: u16, val_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + val_bytes.len());
    out.extend_from_slice(&(attr_type & 0x7FFF).to_be_bytes());
    out.extend_from_slice(&(val_bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(val_bytes);
    out
}

fn ike_wrap_pl(next_pt: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(next_pt);
    out.push(0);
    out.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn ike_build_chain(items: &[(u8, Vec<u8>)]) -> (u8, Vec<u8>) {
    if items.is_empty() {
        return (0, Vec::new());
    }
    let mut out = Vec::new();
    for (idx, (_, body)) in items.iter().enumerate() {
        let npt = if idx + 1 < items.len() {
            items[idx + 1].0
        } else {
            0
        };
        out.extend_from_slice(&ike_wrap_pl(npt, body));
    }
    (items[0].0, out)
}

fn ike_parse_payloads(buf: &[u8], first_pt: u8) -> Vec<(u8, Vec<u8>)> {
    let mut res = Vec::new();
    let mut pt = first_pt;
    let mut off = 0usize;
    while pt != 0 && off + 4 <= buf.len() {
        let npt = buf[off];
        let plen = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
        if plen < 4 || off + plen > buf.len() {
            break;
        }
        res.push((pt, buf[off + 4..off + plen].to_vec()));
        off += plen;
        pt = npt;
    }
    res
}

fn ike_parse_attrs(buf: &[u8]) -> HashMap<u16, u32> {
    let mut attrs = HashMap::new();
    let mut off = 0usize;
    while off + 4 <= buf.len() {
        let af_t = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let val_len = u16::from_be_bytes([buf[off + 2], buf[off + 3]]);
        let t = af_t & 0x7FFF;
        if (af_t & 0x8000) != 0 {
            attrs.insert(t, u32::from(val_len));
            off += 4;
        } else {
            let vlen = val_len as usize;
            if off + 4 + vlen > buf.len() || vlen > 4 {
                break;
            }
            let mut val = 0u32;
            for &b in &buf[off + 4..off + 4 + vlen] {
                val = (val << 8) | u32::from(b);
            }
            attrs.insert(t, val);
            off += 4 + vlen;
        }
    }
    attrs
}

struct Phase1Session {
    local_ip: Ipv4Addr,
    local_port: u16,
    server_ip: Ipv4Addr,
    ck_i: [u8; 8],
    ck_r: [u8; 8],
    alg: IkeCipher,
    hash: IkeHash,
    key: Vec<u8>,
    iv: Vec<u8>,
    skeyid_d: Vec<u8>,
    skeyid_a: Vec<u8>,
}

fn send_informational(
    s4500: &UdpSocket,
    p1: &Phase1Session,
    pt_type: u8,
    body: &[u8],
) -> std::result::Result<(), String> {
    let mut mid_bytes = [0u8; 4];
    rand::thread_rng().fill_bytes(&mut mid_bytes);
    let mid = u32::from_be_bytes(mid_bytes) | 1;

    let mut iv_in = p1.iv.clone();
    iv_in.extend_from_slice(&mid.to_be_bytes());
    let iv = &p1.hash.digest(&iv_in)[..p1.alg.block_len()];

    let inner_pl = ike_wrap_pl(0, body);
    let mut h_in = mid.to_be_bytes().to_vec();
    h_in.extend_from_slice(&inner_pl);
    let h_val = p1.hash.hmac(&p1.skeyid_a, &h_in);

    let mut plain = ike_wrap_pl(pt_type, &h_val);
    plain.extend_from_slice(&inner_pl);
    let blen = p1.alg.block_len();
    let pad = (blen - (plain.len() % blen)) % blen;
    plain.resize(plain.len() + pad, 0);

    let enc = ike_cbc_crypt(p1.alg, &p1.key, iv, &plain, true)?;
    let mut pkt = Vec::with_capacity(4 + 28 + enc.len());
    pkt.extend_from_slice(&[0u8; 4]); // Non-ESP marker
    pkt.extend_from_slice(&p1.ck_i);
    pkt.extend_from_slice(&p1.ck_r);
    pkt.push(8); // NextPayload = HASH
    pkt.push(0x10);
    pkt.push(5); // Informational
    pkt.push(1); // Encrypted
    pkt.extend_from_slice(&mid.to_be_bytes());
    pkt.extend_from_slice(&((28 + enc.len()) as u32).to_be_bytes());
    pkt.extend_from_slice(&enc);
    let _ = s4500.send(&pkt);
    Ok(())
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

fn negotiate_quick_mode_and_install_xfrm(
    s4500: &UdpSocket,
    p1: &Phase1Session,
    am3_pkt: Option<&[u8]>,
    update_policies: bool,
) -> std::result::Result<(u32, u32, String), String> {
    let mut rng = rand::thread_rng();
    let mut mid_b = [0u8; 4];
    let mut spi_b = [0u8; 4];
    let mut ni_qm = [0u8; 20];
    rng.fill_bytes(&mut mid_b);
    rng.fill_bytes(&mut spi_b);
    rng.fill_bytes(&mut ni_qm);

    let msg_id = u32::from_be_bytes(mid_b) | 1;
    let spi_in = (u32::from_be_bytes(spi_b) & 0x7FFF_FFFF) | 0x1000_0000;
    let blen = p1.alg.block_len();

    let mut qm1_iv_in = p1.iv.clone();
    qm1_iv_in.extend_from_slice(&msg_id.to_be_bytes());
    let qm1_iv = &p1.hash.digest(&qm1_iv_in)[..blen];

    let p2_specs: [(u8, u16, u16, u16); 6] = [
        (12, 256, 2, 4),
        (12, 256, 2, 61444),
        (12, 128, 2, 4),
        (12, 128, 2, 61444),
        (3, 0, 2, 4),
        (3, 0, 2, 61444),
    ];
    let mut p2_tbytes = Vec::new();
    for (idx, (esp_id, kbits, hmac_id, cap_mode)) in p2_specs.iter().enumerate() {
        let mut at = Vec::new();
        at.extend_from_slice(&ike_attr_tv(4, *cap_mode));
        at.extend_from_slice(&ike_attr_tv(5, *hmac_id));
        if *kbits > 0 {
            at.extend_from_slice(&ike_attr_tv(6, *kbits));
        }
        at.extend_from_slice(&ike_attr_tv(1, 1));
        at.extend_from_slice(&ike_attr_tlv(2, &86400u32.to_be_bytes()));

        let mut tbody = vec![(idx + 1) as u8, *esp_id, 0, 0];
        tbody.extend_from_slice(&at);
        let npt = if idx + 1 < p2_specs.len() { 3 } else { 0 };
        p2_tbytes.extend_from_slice(&ike_wrap_pl(npt, &tbody));
    }

    let mut p2_prop = vec![1u8, 3, 4, p2_specs.len() as u8];
    p2_prop.extend_from_slice(&spi_in.to_be_bytes());
    p2_prop.extend_from_slice(&p2_tbytes);

    let mut p2_sa = Vec::new();
    p2_sa.extend_from_slice(&1u32.to_be_bytes());
    p2_sa.extend_from_slice(&1u32.to_be_bytes());
    p2_sa.extend_from_slice(&ike_wrap_pl(0, &p2_prop));

    let mut id_ci = vec![1u8, 17];
    id_ci.extend_from_slice(&1701u16.to_be_bytes());
    id_ci.extend_from_slice(&p1.local_ip.octets());

    let mut id_cr = vec![1u8, 17];
    id_cr.extend_from_slice(&1701u16.to_be_bytes());
    id_cr.extend_from_slice(&p1.server_ip.octets());

    let (_, after_h1) =
        ike_build_chain(&[(1, p2_sa), (10, ni_qm.to_vec()), (5, id_ci), (5, id_cr)]);
    let mut h1_in = msg_id.to_be_bytes().to_vec();
    h1_in.extend_from_slice(&after_h1);
    let hash1 = p1.hash.hmac(&p1.skeyid_a, &h1_in);

    let mut qm1_plain = ike_wrap_pl(1, &hash1);
    qm1_plain.extend_from_slice(&after_h1);
    let pad = (blen - (qm1_plain.len() % blen)) % blen;
    qm1_plain.resize(qm1_plain.len() + pad, 0);
    let qm1_enc = ike_cbc_crypt(p1.alg, &p1.key, qm1_iv, &qm1_plain, true)?;

    let mut qm1_pkt = Vec::with_capacity(4 + 28 + qm1_enc.len());
    qm1_pkt.extend_from_slice(&[0u8; 4]);
    qm1_pkt.extend_from_slice(&p1.ck_i);
    qm1_pkt.extend_from_slice(&p1.ck_r);
    qm1_pkt.push(8);
    qm1_pkt.push(0x10);
    qm1_pkt.push(32); // Quick Mode
    qm1_pkt.push(1);
    qm1_pkt.extend_from_slice(&msg_id.to_be_bytes());
    qm1_pkt.extend_from_slice(&((28 + qm1_enc.len()) as u32).to_be_bytes());
    qm1_pkt.extend_from_slice(&qm1_enc);

    let _ = s4500.set_read_timeout(Some(Duration::from_millis(600)));
    let mut qm2_raw: Option<Vec<u8>> = None;
    let mut rx_buf = [0u8; 4096];

    for _ in 0..3 {
        if let Some(am3) = am3_pkt {
            let mut framed = Vec::with_capacity(4 + am3.len());
            framed.extend_from_slice(&[0u8; 4]);
            framed.extend_from_slice(am3);
            let _ = s4500.send(&framed);
            std::thread::sleep(Duration::from_millis(40));
        }
        let _ = s4500.send(&qm1_pkt);

        let deadline = Instant::now() + Duration::from_millis(1800);
        while Instant::now() < deadline {
            if let Ok(n) = s4500.recv(&mut rx_buf) {
                let raw = &rx_buf[..n];
                if raw.len() >= 32 && raw[0..4] == [0, 0, 0, 0] {
                    let ike = &raw[4..];
                    let rx_mid = u32::from_be_bytes([ike[20], ike[21], ike[22], ike[23]]);
                    if ike[18] == 32 && rx_mid == msg_id && (ike[19] & 1) != 0 {
                        qm2_raw = Some(ike.to_vec());
                        break;
                    }
                }
            }
        }
        if qm2_raw.is_some() {
            break;
        }
    }

    let qm2 = qm2_raw.ok_or("IKEv1 Phase 2 Quick Mode timed out waiting for server QM2")?;
    let qm2_enc = &qm2[28..];
    let qm2_dec = ike_cbc_crypt(
        p1.alg,
        &p1.key,
        &qm1_enc[qm1_enc.len() - blen..],
        qm2_enc,
        false,
    )?;

    if qm2[16] != 8 || qm2_dec.len() < 8 {
        return Err("Server QM2 missing leading HASH(2) payload".to_string());
    }
    let h2_npt = qm2_dec[0];
    let h2_plen = u16::from_be_bytes([qm2_dec[2], qm2_dec[3]]) as usize;
    if h2_plen < 4 || h2_plen > qm2_dec.len() {
        return Err("Malformed QM2 HASH(2) length".to_string());
    }
    let hash2_rx = &qm2_dec[4..h2_plen];

    let mut off = h2_plen;
    let mut pt = h2_npt;
    while pt != 0 && off + 4 <= qm2_dec.len() {
        let npt = qm2_dec[off];
        let plen = u16::from_be_bytes([qm2_dec[off + 2], qm2_dec[off + 3]]) as usize;
        if plen < 4 || off + plen > qm2_dec.len() {
            break;
        }
        off += plen;
        pt = npt;
    }
    let after_h2 = &qm2_dec[h2_plen..off];
    let mut h2_in = msg_id.to_be_bytes().to_vec();
    h2_in.extend_from_slice(&ni_qm);
    h2_in.extend_from_slice(after_h2);
    let hash2_calc = p1.hash.hmac(&p1.skeyid_a, &h2_in);
    if !bool::from(hash2_rx.ct_eq(&hash2_calc)) {
        return Err("IKEv1 Quick Mode HASH(2) authentication failed".to_string());
    }

    let qm2_pls: HashMap<u8, Vec<u8>> = ike_parse_payloads(&qm2_dec, qm2[16]).into_iter().collect();
    let sa2_body = qm2_pls.get(&1).ok_or("QM2 missing SA payload")?;
    let nr_qm = qm2_pls.get(&10).ok_or("QM2 missing Nonce payload")?;

    let p2_prop_r = ike_parse_payloads(&sa2_body[8..], 2)
        .into_iter()
        .next()
        .ok_or("QM2 missing Proposal")?
        .1;
    if p2_prop_r.len() < 8 {
        return Err("Short QM2 Proposal".to_string());
    }
    let spi_out = u32::from_be_bytes([p2_prop_r[4], p2_prop_r[5], p2_prop_r[6], p2_prop_r[7]]);
    let p2_tr_r = ike_parse_payloads(&p2_prop_r[8..], 3)
        .into_iter()
        .next()
        .ok_or("QM2 missing Transform")?
        .1;
    let esp_trans_id = p2_tr_r[1];
    let p2_r_attrs = ike_parse_attrs(&p2_tr_r[4..]);
    let esp_kbits = *p2_r_attrs
        .get(&6)
        .unwrap_or(&(if esp_trans_id == 3 { 192 } else { 256 }));
    let (esp_alg, esp_klen, xfrm_enc_alg) = if esp_trans_id == 12 && esp_kbits == 256 {
        ("aes256", 32usize, "cbc(aes)")
    } else if esp_trans_id == 12 {
        ("aes128", 16usize, "cbc(aes)")
    } else {
        ("3des", 24usize, "cbc(des3_ede)")
    };

    // Send QM3 [HASH(3)]
    let mut h3_in = vec![0u8];
    h3_in.extend_from_slice(&msg_id.to_be_bytes());
    h3_in.extend_from_slice(&ni_qm);
    h3_in.extend_from_slice(nr_qm);
    let hash3 = p1.hash.hmac(&p1.skeyid_a, &h3_in);
    let mut qm3_plain = ike_wrap_pl(0, &hash3);
    let pad3 = (blen - (qm3_plain.len() % blen)) % blen;
    qm3_plain.resize(qm3_plain.len() + pad3, 0);
    let qm3_enc = ike_cbc_crypt(
        p1.alg,
        &p1.key,
        &qm2_enc[qm2_enc.len() - blen..],
        &qm3_plain,
        true,
    )?;

    let mut qm3_pkt = Vec::with_capacity(4 + 28 + qm3_enc.len());
    qm3_pkt.extend_from_slice(&[0u8; 4]);
    qm3_pkt.extend_from_slice(&p1.ck_i);
    qm3_pkt.extend_from_slice(&p1.ck_r);
    qm3_pkt.push(8);
    qm3_pkt.push(0x10);
    qm3_pkt.push(32);
    qm3_pkt.push(1);
    qm3_pkt.extend_from_slice(&msg_id.to_be_bytes());
    qm3_pkt.extend_from_slice(&((28 + qm3_enc.len()) as u32).to_be_bytes());
    qm3_pkt.extend_from_slice(&qm3_enc);
    let _ = s4500.send(&qm3_pkt);

    // Derive outbound & inbound ESP KEYMAT
    let km_out = ike_calc_keymat(
        p1.hash,
        &p1.skeyid_d,
        3,
        spi_out,
        &ni_qm,
        nr_qm,
        esp_klen + 20,
    );
    let km_in = ike_calc_keymat(
        p1.hash,
        &p1.skeyid_d,
        3,
        spi_in,
        &ni_qm,
        nr_qm,
        esp_klen + 20,
    );
    let (enc_out, auth_out) = (&km_out[..esp_klen], &km_out[esp_klen..esp_klen + 20]);
    let (enc_in, auth_in) = (&km_in[..esp_klen], &km_in[esp_klen..esp_klen + 20]);

    let state_verb = if update_policies { "replace" } else { "add" };
    let loc_s = p1.local_ip.to_string();
    let srv_s = p1.server_ip.to_string();
    let port_s = p1.local_port.to_string();

    for (label, args) in [
        (
            "outbound XFRM state",
            vec![
                "xfrm",
                "state",
                state_verb,
                "src",
                &loc_s,
                "dst",
                &srv_s,
                "proto",
                "esp",
                "spi",
                &format!("0x{spi_out:08x}"),
                "reqid",
                VPNGATE_XFRM_REQID,
                "mode",
                "transport",
                "replay-window",
                "32",
                "auth-trunc",
                "hmac(sha1)",
                &format!("0x{}", hex_encode(auth_out)),
                "96",
                "enc",
                xfrm_enc_alg,
                &format!("0x{}", hex_encode(enc_out)),
                "encap",
                "espinudp",
                &port_s,
                "4500",
                "0.0.0.0",
            ],
        ),
        (
            "inbound XFRM state",
            vec![
                "xfrm",
                "state",
                state_verb,
                "src",
                &srv_s,
                "dst",
                &loc_s,
                "proto",
                "esp",
                "spi",
                &format!("0x{spi_in:08x}"),
                "reqid",
                VPNGATE_XFRM_REQID,
                "mode",
                "transport",
                "replay-window",
                "32",
                "auth-trunc",
                "hmac(sha1)",
                &format!("0x{}", hex_encode(auth_in)),
                "96",
                "enc",
                xfrm_enc_alg,
                &format!("0x{}", hex_encode(enc_in)),
                "encap",
                "espinudp",
                "4500",
                &port_s,
                "0.0.0.0",
            ],
        ),
    ] {
        let out = Command::new("ip")
            .args(&args)
            .output()
            .map_err(|e| format!("{label}: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "Failed to install {label}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
    }

    let loc_cidr = format!("{loc_s}/32");
    let srv_cidr = format!("{srv_s}/32");
    for (label, verb_first, args_tail) in [
        (
            "outbound XFRM policy",
            if update_policies { "update" } else { "add" },
            vec![
                "src",
                loc_cidr.as_str(),
                "dst",
                srv_cidr.as_str(),
                "proto",
                "udp",
                "dport",
                "1701",
                "dir",
                "out",
                "priority",
                "1701",
                "tmpl",
                "proto",
                "esp",
                "mode",
                "transport",
                "reqid",
                VPNGATE_XFRM_REQID,
                "level",
                "required",
            ],
        ),
        (
            "inbound XFRM policy",
            if update_policies { "update" } else { "add" },
            vec![
                "src",
                srv_cidr.as_str(),
                "dst",
                loc_cidr.as_str(),
                "proto",
                "udp",
                "sport",
                "1701",
                "dir",
                "in",
                "priority",
                "1701",
                "tmpl",
                "proto",
                "esp",
                "mode",
                "transport",
                "reqid",
                VPNGATE_XFRM_REQID,
                "level",
                "required",
            ],
        ),
    ] {
        let mut cmd_args = vec!["xfrm", "policy", verb_first];
        cmd_args.extend_from_slice(&args_tail);
        let mut out = Command::new("ip")
            .args(&cmd_args)
            .output()
            .map_err(|e| format!("{label}: {e}"))?;
        if !out.status.success() && !update_policies {
            cmd_args[2] = "update";
            out = Command::new("ip")
                .args(&cmd_args)
                .output()
                .map_err(|e| format!("{label}: {e}"))?;
        }
        if !out.status.success() {
            return Err(format!(
                "Failed to install {label}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
    }

    Ok((spi_in, spi_out, esp_alg.to_string()))
}

/// Entry point for `vpngate _ikev1 <server_ip> <state_file>` on Linux.
/// Negotiates pure-Rust IKEv1 Aggressive + Quick Mode, programs Linux kernel `XFRM` ESPinUDP,
/// and services NAT-T keepalives (`0xff`), RFC 3706 DPD, and clean Delete-SA teardown.
pub async fn run_ikev1_daemon(server_ip_str: &str, state_path: &Path) -> i32 {
    let stop_flag = Arc::new(AtomicBool::new(false));
    {
        let sf = Arc::clone(&stop_flag);
        tokio::spawn(async move {
            let _ = tokio::signal::ctrl_c().await;
            sf.store(true, Ordering::SeqCst);
        });
    }
    #[cfg(unix)]
    {
        let sf = Arc::clone(&stop_flag);
        tokio::spawn(async move {
            if let Ok(mut sigterm) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            {
                let _ = sigterm.recv().await;
                sf.store(true, Ordering::SeqCst);
            }
        });
    }

    let state_buf = state_path.to_path_buf();
    let srv_str = server_ip_str.to_string();
    let res = tokio::task::spawn_blocking(move || {
        ikev1_daemon_blocking(&srv_str, &state_buf, &stop_flag)
    })
    .await;

    match res {
        Ok(Ok(())) => 0,
        Ok(Err(err_msg)) => {
            let err_state = Ikev1StateInfo {
                status: "error".to_string(),
                error: err_msg,
                pid: std::process::id(),
                local_ip: String::new(),
                local_port: 0,
                server_ip: server_ip_str.to_string(),
                p1_alg: String::new(),
                esp_alg: String::new(),
                spi_in: String::new(),
                spi_out: String::new(),
                established_at: 0,
            };
            let _ = atomic_write_json(state_path, &err_state);
            1
        }
        Err(_) => 1,
    }
}

fn ikev1_daemon_blocking(
    server_ip_str: &str,
    state_path: &Path,
    stop_flag: &AtomicBool,
) -> std::result::Result<(), String> {
    let server_ip: Ipv4Addr = server_ip_str
        .parse()
        .map_err(|_| format!("Invalid IPv4: {server_ip_str}"))?;

    let probe_sock = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    probe_sock
        .connect(SocketAddr::new(IpAddr::V4(server_ip), 4500))
        .map_err(|e| e.to_string())?;
    let IpAddr::V4(local_ip) = probe_sock.local_addr().map_err(|e| e.to_string())?.ip() else {
        return Err("Failed to determine IPv4 local source address".to_string());
    };
    drop(probe_sock);

    let s4500 = UdpSocket::bind(SocketAddr::new(IpAddr::V4(local_ip), 4500))
        .or_else(|_| UdpSocket::bind(SocketAddr::new(IpAddr::V4(local_ip), 0)))
        .map_err(|e| format!("Failed binding UDP 4500 socket: {e}"))?;
    let local_port = s4500.local_addr().map_err(|e| e.to_string())?.port();
    enable_linux_espinudp(&s4500)?;
    s4500
        .connect(SocketAddr::new(IpAddr::V4(server_ip), 4500))
        .map_err(|e| e.to_string())?;

    // Phase 1 Aggressive Mode on UDP 500
    let p = BigUint::parse_bytes(MODP_1024_HEX.as_bytes(), 16).ok_or("MODP-1024 parse error")?;
    let mut rng = rand::thread_rng();
    let mut ck_i = [0u8; 8];
    let mut priv_b = [0u8; 32];
    let mut ni = [0u8; 20];
    rng.fill_bytes(&mut ck_i);
    rng.fill_bytes(&mut priv_b);
    priv_b[31] |= 1;
    rng.fill_bytes(&mut ni);

    let priv_x = BigUint::from_bytes_be(&priv_b);
    let gxi_raw = BigUint::from(2u32).modpow(&priv_x, &p).to_bytes_be();
    let mut gxi = vec![0u8; 128];
    let off_gxi = 128usize.saturating_sub(gxi_raw.len());
    gxi[off_gxi..].copy_from_slice(&gxi_raw[gxi_raw.len().saturating_sub(128)..]);

    let mut idi_body = vec![1u8, 17, 0, 0];
    idi_body.extend_from_slice(&local_ip.octets());

    let p1_specs: [(u16, u16, u16, u16); 4] =
        [(7, 256, 2, 2), (7, 128, 2, 2), (5, 0, 2, 2), (5, 0, 1, 2)];
    let mut t_bytes = Vec::new();
    for (idx, (enc_id, kbits, hsh_id, dh_grp)) in p1_specs.iter().enumerate() {
        let mut at = Vec::new();
        at.extend_from_slice(&ike_attr_tv(1, *enc_id));
        if *kbits > 0 {
            at.extend_from_slice(&ike_attr_tv(14, *kbits));
        }
        at.extend_from_slice(&ike_attr_tv(2, *hsh_id));
        at.extend_from_slice(&ike_attr_tv(3, 1));
        at.extend_from_slice(&ike_attr_tv(4, *dh_grp));
        at.extend_from_slice(&ike_attr_tv(11, 1));
        at.extend_from_slice(&ike_attr_tlv(12, &86400u32.to_be_bytes()));

        let mut tbody = vec![(idx + 1) as u8, 1, 0, 0];
        tbody.extend_from_slice(&at);
        let npt = if idx + 1 < p1_specs.len() { 3 } else { 0 };
        t_bytes.extend_from_slice(&ike_wrap_pl(npt, &tbody));
    }

    let mut prop_b = vec![1u8, 1, 0, p1_specs.len() as u8];
    prop_b.extend_from_slice(&t_bytes);
    let mut sa_i_body = Vec::new();
    sa_i_body.extend_from_slice(&1u32.to_be_bytes());
    sa_i_body.extend_from_slice(&1u32.to_be_bytes());
    sa_i_body.extend_from_slice(&ike_wrap_pl(0, &prop_b));

    let mut am1_items = vec![
        (1u8, sa_i_body.clone()),
        (4u8, gxi.clone()),
        (10u8, ni.to_vec()),
        (5u8, idi_body.clone()),
    ];
    for vid in IKEV1_NAT_T_VIDS {
        am1_items.push((13u8, vid.to_vec()));
    }
    let (am1_fpt, am1_body) = ike_build_chain(&am1_items);
    let mut am1_pkt = Vec::with_capacity(28 + am1_body.len());
    am1_pkt.extend_from_slice(&ck_i);
    am1_pkt.extend_from_slice(&[0u8; 8]);
    am1_pkt.push(am1_fpt);
    am1_pkt.push(0x10);
    am1_pkt.push(4);
    am1_pkt.push(0);
    am1_pkt.extend_from_slice(&0u32.to_be_bytes());
    am1_pkt.extend_from_slice(&((28 + am1_body.len()) as u32).to_be_bytes());
    am1_pkt.extend_from_slice(&am1_body);

    let s500 = UdpSocket::bind("0.0.0.0:0").map_err(|e| e.to_string())?;
    let _ = s500.set_read_timeout(Some(Duration::from_millis(1600)));
    let mut am2: Option<Vec<u8>> = None;
    let mut buf500 = [0u8; 4096];
    for _ in 0..3 {
        let _ = s500.send_to(&am1_pkt, SocketAddr::new(IpAddr::V4(server_ip), 500));
        if let Ok((n, _)) = s500.recv_from(&mut buf500)
            && n >= 28
            && buf500[0..8] == ck_i
        {
            am2 = Some(buf500[..n].to_vec());
            break;
        }
    }
    drop(s500);

    let am2 = am2.ok_or_else(|| format!("IKEv1 Phase 1 timed out on {server_ip}:500"))?;
    if am2[18] == 5 {
        return Err(format!(
            "Peer {server_ip}:500 rejected Phase 1 proposal (Informational Notify)"
        ));
    }

    let mut ck_r = [0u8; 8];
    ck_r.copy_from_slice(&am2[8..16]);
    let pls2_list = ike_parse_payloads(&am2[28..], am2[16]);
    let pls2: HashMap<u8, Vec<u8>> = pls2_list.iter().cloned().collect();
    let sa_r = pls2.get(&1).ok_or("Phase 1 missing SA")?;
    let gxr = pls2.get(&4).ok_or("Phase 1 missing KE")?;
    let nr = pls2.get(&10).ok_or("Phase 1 missing Nonce")?;
    let idr = pls2.get(&5).ok_or("Phase 1 missing ID")?;
    let hash_r = pls2.get(&8).ok_or("Phase 1 missing HASH_R")?;

    let prop_pl = ike_parse_payloads(&sa_r[8..], 2)
        .into_iter()
        .next()
        .ok_or("Phase 1 missing Proposal")?
        .1;
    let spi_sz = prop_pl[2] as usize;
    let tr_pl = ike_parse_payloads(&prop_pl[4 + spi_sz..], 3)
        .into_iter()
        .next()
        .ok_or("Phase 1 missing Transform")?
        .1;
    let p1_attrs = ike_parse_attrs(&tr_pl[4..]);
    let p1_enc = *p1_attrs.get(&1).unwrap_or(&7);
    let p1_kbits = *p1_attrs
        .get(&14)
        .unwrap_or(&(if p1_enc == 5 { 192 } else { 256 }));
    let hash = if *p1_attrs.get(&2).unwrap_or(&2) == 2 {
        IkeHash::Sha1
    } else {
        IkeHash::Md5
    };
    let alg = if p1_enc == 7 && p1_kbits == 256 {
        IkeCipher::Aes256
    } else if p1_enc == 7 {
        IkeCipher::Aes128
    } else {
        IkeCipher::Des3
    };

    let gxy_raw = BigUint::from_bytes_be(gxr)
        .modpow(&priv_x, &p)
        .to_bytes_be();
    let mut gxy = vec![0u8; 128];
    let off_gxy = 128usize.saturating_sub(gxy_raw.len());
    gxy[off_gxy..].copy_from_slice(&gxy_raw[gxy_raw.len().saturating_sub(128)..]);

    let mut skey_in = ni.to_vec();
    skey_in.extend_from_slice(nr);
    let skeyid = hash.hmac(b"vpn", &skey_in);

    let mut hr_in = Vec::new();
    hr_in.extend_from_slice(gxr);
    hr_in.extend_from_slice(&gxi);
    hr_in.extend_from_slice(&ck_r);
    hr_in.extend_from_slice(&ck_i);
    hr_in.extend_from_slice(&sa_i_body);
    hr_in.extend_from_slice(idr);
    let exp_hr = hash.hmac(&skeyid, &hr_in);
    if !bool::from(exp_hr.as_slice().ct_eq(hash_r)) {
        return Err(format!("PSK mismatch on {server_ip} (PSK != 'vpn')"));
    }

    let mut d_in = gxy.clone();
    d_in.extend_from_slice(&ck_i);
    d_in.extend_from_slice(&ck_r);
    d_in.push(0);
    let skeyid_d = hash.hmac(&skeyid, &d_in);

    let mut a_in = skeyid_d.clone();
    a_in.extend_from_slice(&gxy);
    a_in.extend_from_slice(&ck_i);
    a_in.extend_from_slice(&ck_r);
    a_in.push(1);
    let skeyid_a = hash.hmac(&skeyid, &a_in);

    let mut e_in = skeyid_a.clone();
    e_in.extend_from_slice(&gxy);
    e_in.extend_from_slice(&ck_i);
    e_in.extend_from_slice(&ck_r);
    e_in.push(2);
    let skeyid_e = hash.hmac(&skeyid, &e_in);

    let p1_key = ike_expand_key(hash, &skeyid_e, alg.key_len());
    let mut iv_seed = gxi.clone();
    iv_seed.extend_from_slice(gxr);
    let blen = alg.block_len();
    let p1_iv_init = hash.digest(&iv_seed)[..blen].to_vec();

    // Build AM3 [HASH_I, NAT-D, NAT-D]
    let mut hi_in = gxi;
    hi_in.extend_from_slice(gxr);
    hi_in.extend_from_slice(&ck_i);
    hi_in.extend_from_slice(&ck_r);
    hi_in.extend_from_slice(&sa_i_body);
    hi_in.extend_from_slice(&idi_body);
    let hash_i = hash.hmac(&skeyid, &hi_in);

    let natd_pt = if pls2_list.iter().any(|(pt, _)| *pt == 20) {
        20u8
    } else {
        130u8
    };
    let mut nd1 = [0u8; 20];
    let mut nd2 = [0u8; 20];
    rng.fill_bytes(&mut nd1);
    rng.fill_bytes(&mut nd2);
    let (am3_fpt, mut am3_plain) = ike_build_chain(&[
        (8, hash_i),
        (natd_pt, nd1.to_vec()),
        (natd_pt, nd2.to_vec()),
    ]);
    let pad_am3 = (blen - (am3_plain.len() % blen)) % blen;
    am3_plain.resize(am3_plain.len() + pad_am3, 0);
    let am3_enc = ike_cbc_crypt(alg, &p1_key, &p1_iv_init, &am3_plain, true)?;
    let p1_iv = am3_enc[am3_enc.len() - blen..].to_vec();

    let mut am3_pkt = Vec::with_capacity(28 + am3_enc.len());
    am3_pkt.extend_from_slice(&ck_i);
    am3_pkt.extend_from_slice(&ck_r);
    am3_pkt.push(am3_fpt);
    am3_pkt.push(0x10);
    am3_pkt.push(4);
    am3_pkt.push(1);
    am3_pkt.extend_from_slice(&0u32.to_be_bytes());
    am3_pkt.extend_from_slice(&((28 + am3_enc.len()) as u32).to_be_bytes());
    am3_pkt.extend_from_slice(&am3_enc);

    let p1 = Phase1Session {
        local_ip,
        local_port,
        server_ip,
        ck_i,
        ck_r,
        alg,
        hash,
        key: p1_key,
        iv: p1_iv,
        skeyid_d,
        skeyid_a,
    };

    let (mut spi_in, spi_out, esp_alg) =
        negotiate_quick_mode_and_install_xfrm(&s4500, &p1, Some(&am3_pkt), false)?;

    let ready = Ikev1StateInfo {
        status: "ready".to_string(),
        pid: std::process::id(),
        local_ip: local_ip.to_string(),
        local_port,
        server_ip: server_ip.to_string(),
        p1_alg: alg.label().to_string(),
        esp_alg,
        spi_in: format!("0x{spi_in:08x}"),
        spi_out: format!("0x{spi_out:08x}"),
        established_at: now_unix_secs(),
        error: String::new(),
    };
    let _ = atomic_write_json(state_path, &ready);

    // Steady-state NAT-T keepalive + RFC 3706 DPD responder + rekey loop
    let _ = s4500.set_read_timeout(Some(Duration::from_millis(900)));
    let mut last_ka = Instant::now();
    let mut last_dpd = Instant::now();
    let mut last_rekey = Instant::now();
    let mut dpd_seq = {
        let mut b = [0u8; 4];
        rng.fill_bytes(&mut b);
        u32::from_be_bytes(b) & 0x7FFF_FFFF
    };
    let mut rx = [0u8; 4096];

    while !stop_flag.load(Ordering::Relaxed) {
        if let Ok(n) = s4500.recv(&mut rx) {
            let raw = &rx[..n];
            if raw.len() >= 32 && raw[0..4] == [0, 0, 0, 0] {
                let ike = &raw[4..];
                if ike[18] == 5 && (ike[19] & 1) != 0 && ike[0..8] == ck_i && ike[8..16] == ck_r {
                    let rx_mid = u32::from_be_bytes([ike[20], ike[21], ike[22], ike[23]]);
                    let enc_body = &ike[28..];
                    if !enc_body.is_empty() && enc_body.len().is_multiple_of(blen) {
                        let mut iv_in = p1.iv.clone();
                        iv_in.extend_from_slice(&rx_mid.to_be_bytes());
                        let rx_iv = &p1.hash.digest(&iv_in)[..blen];
                        if let Ok(dec) = ike_cbc_crypt(p1.alg, &p1.key, rx_iv, enc_body, false) {
                            for (pt, b) in ike_parse_payloads(&dec, ike[16]) {
                                if pt == 11 && b.len() >= 8 {
                                    let spisz = b[5] as usize;
                                    let mtype = u16::from_be_bytes([b[6], b[7]]);
                                    if mtype == 36136 && b.len() >= 8 + spisz + 4 {
                                        let seq = &b[8 + spisz..8 + spisz + 4];
                                        let mut ack = Vec::with_capacity(28);
                                        ack.extend_from_slice(&1u32.to_be_bytes());
                                        ack.push(1);
                                        ack.push(16);
                                        ack.extend_from_slice(&36137u16.to_be_bytes());
                                        ack.extend_from_slice(&ck_i);
                                        ack.extend_from_slice(&ck_r);
                                        ack.extend_from_slice(seq);
                                        let _ = send_informational(&s4500, &p1, 11, &ack);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        if last_ka.elapsed() >= Duration::from_secs(20) {
            last_ka = Instant::now();
            let _ = s4500.send(&[0xff]);
        }
        if last_dpd.elapsed() >= Duration::from_secs(60) {
            last_dpd = Instant::now();
            dpd_seq = (dpd_seq + 1) & 0x7FFF_FFFF;
            let mut req = Vec::with_capacity(28);
            req.extend_from_slice(&1u32.to_be_bytes());
            req.push(1);
            req.push(16);
            req.extend_from_slice(&36136u16.to_be_bytes());
            req.extend_from_slice(&ck_i);
            req.extend_from_slice(&ck_r);
            req.extend_from_slice(&dpd_seq.to_be_bytes());
            let _ = send_informational(&s4500, &p1, 11, &req);
        }
        if last_rekey.elapsed() >= Duration::from_secs(72000) {
            last_rekey = Instant::now();
            if let Ok((new_spi_in, _, _)) =
                negotiate_quick_mode_and_install_xfrm(&s4500, &p1, None, true)
            {
                spi_in = new_spi_in;
            }
            let _ = s4500.set_read_timeout(Some(Duration::from_millis(900)));
        }
    }

    // Clean Delete-SA teardown
    let mut del_esp = Vec::with_capacity(12);
    del_esp.extend_from_slice(&1u32.to_be_bytes());
    del_esp.push(3);
    del_esp.push(4);
    del_esp.extend_from_slice(&1u16.to_be_bytes());
    del_esp.extend_from_slice(&spi_in.to_be_bytes());
    let _ = send_informational(&s4500, &p1, 12, &del_esp);

    let mut del_ike = Vec::with_capacity(24);
    del_ike.extend_from_slice(&1u32.to_be_bytes());
    del_ike.push(1);
    del_ike.push(16);
    del_ike.extend_from_slice(&1u16.to_be_bytes());
    del_ike.extend_from_slice(&ck_i);
    del_ike.extend_from_slice(&ck_r);
    let _ = send_informational(&s4500, &p1, 12, &del_ike);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passes_pure_rust_ikev1_crypto_self_test() {
        run_ikev1_crypto_self_test().expect("IKEv1 CBC + MODP-1024 + KEYMAT self-test succeeds");
    }
}
