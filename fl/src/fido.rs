// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Drive the device's FIDO interface over CTAPHID: U2F register then authenticate,
//! verifying the authentication signature against the freshly registered key.
//! The CTAPHID framing mirrors KeyOS-dev/utils/passport-drive.

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use hidapi::{HidApi, HidDevice};
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

const PASSPORT_VID: u16 = 0x1307;
const FIDO_USAGE_PAGE: u16 = 0xf1d0;
const REPORT_SIZE: usize = 64;

const BROADCAST_CID: u32 = 0xffff_ffff;
const CTAPHID_INIT: u8 = 0x06;
const CTAPHID_MSG: u8 = 0x03;
const CTAPHID_KEEPALIVE: u8 = 0x3b;
const CTAPHID_ERROR: u8 = 0x3f;
const INIT_HEADER: usize = 7; // cid:4 cmd:1 len:2
const CONT_HEADER: usize = 5; // cid:4 seq:1

/// Long enough for the on-device user-presence prompt.
const TIMEOUT_MS: i32 = 30_000;

#[derive(clap::Args)]
pub struct Args {
    /// Run against the hosted simulator instead of a real device (not wired up yet).
    #[arg(long)]
    hosted: bool,
}

pub fn run(args: Args) -> Result<()> {
    if args.hosted {
        bail!("--hosted is not wired up yet (the sim has no HID transport)");
    }

    let api = HidApi::new().context("open the HID API")?;
    let info = api
        .device_list()
        .find(|d| d.vendor_id() == PASSPORT_VID && d.usage_page() == FIDO_USAGE_PAGE)
        .with_context(|| {
            format!("no Passport Prime FIDO HID interface ({PASSPORT_VID:04x}/{FIDO_USAGE_PAGE:04x})")
        })?;
    println!("using FIDO HID: {}", info.product_string().unwrap_or(""));
    let device = info.open_device(&api).context("open the FIDO HID device")?;

    let cid = ctaphid_init(&device)?;

    let version = u2f(&device, cid, &u2f_apdu(0x03, 0x00, &[]))?;
    println!("U2F version: {}\n", String::from_utf8_lossy(&version));

    let challenge: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(13).wrapping_add(1));
    let appid: [u8; 32] = Sha256::digest(b"https://foundation.xyz").into();

    println!("REGISTER -- confirm presence on the device...");
    let mut data = challenge.to_vec();
    data.extend_from_slice(&appid);
    let reg = u2f_await_presence(&device, cid, &u2f_apdu(0x01, 0x00, &data))?;
    let (pubkey, key_handle) = parse_registration(&reg)?;
    println!("  registered: P-256 user key, key handle {} bytes\n", key_handle.len());

    println!("AUTHENTICATE -- confirm presence on the device...");
    let mut data = challenge.to_vec();
    data.extend_from_slice(&appid);
    data.push(key_handle.len() as u8);
    data.extend_from_slice(&key_handle);
    let auth = u2f_await_presence(&device, cid, &u2f_apdu(0x02, 0x03, &data))?;
    let (presence, counter, signature) = parse_authentication(&auth)?;

    // U2F signs SHA-256(appid || presence || counter || challenge).
    let mut signed = appid.to_vec();
    signed.push(presence);
    signed.extend_from_slice(&counter.to_be_bytes());
    signed.extend_from_slice(&challenge);
    let digest: [u8; 32] = Sha256::digest(&signed).into();
    pubkey
        .verify_prehash(&digest, &signature)
        .context("authentication signature does NOT verify against the registered key")?;
    println!("  signature verifies against the registered key (counter={counter}) -- U2F chain OK\n");

    println!("FIDO: all checks passed.");
    Ok(())
}

/// Extended-length U2F command APDU (CLA=00, the U2F encoding).
fn u2f_apdu(ins: u8, p1: u8, data: &[u8]) -> Vec<u8> {
    let mut a = vec![0x00, ins, p1, 0x00, 0x00];
    a.extend_from_slice(&(data.len() as u16).to_be_bytes());
    a.extend_from_slice(data);
    a.extend_from_slice(&[0x00, 0x00]); // extended Le
    a
}

/// Send a U2F APDU over CTAPHID_MSG; returns (response without the status word, status word).
fn u2f_once(device: &HidDevice, cid: u32, apdu: &[u8]) -> Result<(Vec<u8>, u16)> {
    let (cmd, data) = exchange(device, cid, CTAPHID_MSG, apdu)?;
    if cmd != CTAPHID_MSG {
        bail!("unexpected CTAPHID response cmd {cmd:02x}");
    }
    if data.len() < 2 {
        bail!("U2F response too short");
    }
    let sw = u16::from_be_bytes([data[data.len() - 2], data[data.len() - 1]]);
    Ok((data[..data.len() - 2].to_vec(), sw))
}

/// A U2F command that returns 9000 immediately (no user presence required).
fn u2f(device: &HidDevice, cid: u32, apdu: &[u8]) -> Result<Vec<u8>> {
    let (data, sw) = u2f_once(device, cid, apdu)?;
    if sw != 0x9000 {
        bail!("U2F status word {sw:04x}");
    }
    Ok(data)
}

/// A U2F command gated on user presence: the device returns 6985 until the user confirms on
/// screen, so poll until 9000 or the prompt times out.
fn u2f_await_presence(device: &HidDevice, cid: u32, apdu: &[u8]) -> Result<Vec<u8>> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let (data, sw) = u2f_once(device, cid, apdu)?;
        match sw {
            0x9000 => return Ok(data),
            0x6985 if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(200)),
            0x6985 => bail!("timed out waiting for user presence on the device"),
            other => bail!("U2F status word {other:04x}"),
        }
    }
}

fn parse_registration(resp: &[u8]) -> Result<(VerifyingKey, Vec<u8>)> {
    // 0x05 | pubkey[65] | khlen[1] | key handle | attestation cert | signature
    if resp.first() != Some(&0x05) || resp.len() < 67 {
        bail!("malformed U2F registration response");
    }
    let pubkey = VerifyingKey::from_sec1_bytes(&resp[1..66]).context("registration key is not P-256")?;
    let kh_len = resp[66] as usize;
    let key_handle = resp.get(67..67 + kh_len).context("key handle truncated")?.to_vec();
    Ok((pubkey, key_handle))
}

fn parse_authentication(resp: &[u8]) -> Result<(u8, u32, Signature)> {
    // presence[1] | counter[4] | signature (DER)
    if resp.len() < 6 {
        bail!("malformed U2F authentication response");
    }
    let presence = resp[0];
    let counter = u32::from_be_bytes([resp[1], resp[2], resp[3], resp[4]]);
    let signature = Signature::from_der(&resp[5..]).context("authentication signature is not DER ECDSA")?;
    Ok((presence, counter, signature))
}

/// Allocate a CTAPHID channel and return its CID.
fn ctaphid_init(device: &HidDevice) -> Result<u32> {
    let (_, data) = exchange(device, BROADCAST_CID, CTAPHID_INIT, &[0x42; 8])?;
    // nonce[8] | cid[4] | ...
    let cid = data.get(8..12).context("short CTAPHID_INIT response")?;
    Ok(u32::from_be_bytes([cid[0], cid[1], cid[2], cid[3]]))
}

/// One CTAPHID transaction: fragment + write the request, then read + reassemble the reply,
/// skipping KEEPALIVE frames the device sends while waiting for the user.
fn exchange(device: &HidDevice, cid: u32, cmd: u8, payload: &[u8]) -> Result<(u8, Vec<u8>)> {
    for report in fragment(cid, cmd, payload) {
        let mut buf = Vec::with_capacity(1 + REPORT_SIZE);
        buf.push(0x00); // HID report id
        buf.extend_from_slice(&report);
        device.write(&buf).context("CTAPHID write")?;
    }

    let mut read = [0u8; REPORT_SIZE];
    let mut acc = Vec::new();
    let mut remaining = 0usize;
    let mut expected_seq = 0u8;
    let mut response_cmd = 0u8;
    loop {
        let n = device.read_timeout(&mut read, TIMEOUT_MS).context("CTAPHID read")?;
        if n == 0 {
            bail!("CTAPHID read timeout");
        }
        let r = &read[..n];
        if r.len() < CONT_HEADER {
            bail!("CTAPHID report too short");
        }

        if r[4] & 0x80 != 0 {
            response_cmd = r[4] & 0x7f;
            let total = u16::from_be_bytes([r[5], r[6]]) as usize;
            let take = (r.len() - INIT_HEADER).min(total);
            acc.clear();
            acc.extend_from_slice(&r[INIT_HEADER..INIT_HEADER + take]);
            remaining = total - take;
            expected_seq = 0;
        } else {
            if r[4] != expected_seq {
                bail!("CTAPHID sequence mismatch");
            }
            let take = (r.len() - CONT_HEADER).min(remaining);
            acc.extend_from_slice(&r[CONT_HEADER..CONT_HEADER + take]);
            remaining -= take;
            expected_seq += 1;
        }

        if remaining == 0 {
            match response_cmd {
                CTAPHID_KEEPALIVE => continue, // device still waiting on the user
                CTAPHID_ERROR => bail!("CTAPHID error: {:02x?}", acc),
                _ => return Ok((response_cmd, std::mem::take(&mut acc))),
            }
        }
    }
}

fn fragment(cid: u32, cmd: u8, payload: &[u8]) -> Vec<[u8; REPORT_SIZE]> {
    let mut reports = Vec::new();
    let mut report = [0u8; REPORT_SIZE];
    report[0..4].copy_from_slice(&cid.to_be_bytes());
    report[4] = cmd | 0x80;
    report[5..7].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    let first = payload.len().min(REPORT_SIZE - INIT_HEADER);
    report[INIT_HEADER..INIT_HEADER + first].copy_from_slice(&payload[..first]);
    reports.push(report);

    let mut offset = first;
    let mut seq = 0u8;
    while offset < payload.len() {
        let mut report = [0u8; REPORT_SIZE];
        report[0..4].copy_from_slice(&cid.to_be_bytes());
        report[4] = seq;
        let chunk = (payload.len() - offset).min(REPORT_SIZE - CONT_HEADER);
        report[CONT_HEADER..CONT_HEADER + chunk].copy_from_slice(&payload[offset..offset + chunk]);
        reports.push(report);
        offset += chunk;
        seq += 1;
    }

    reports
}
