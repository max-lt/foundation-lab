// SPDX-FileCopyrightText: 2026 Foundation Devices, Inc. <hello@foundation.xyz>
// SPDX-License-Identifier: GPL-3.0-or-later

//! Drive the device's PIV applet over CCID/PCSC and validate the full chain:
//! SELECT -> GET DATA (CHUID, slot 9A cert) -> GENERAL AUTHENTICATE, then verify
//! the signature against the certificate's public key.

use std::ffi::CStr;

use anyhow::{bail, Context, Result};
use p256::ecdsa::{signature::hazmat::PrehashVerifier, Signature, VerifyingKey};
use pcsc::{Card, Context as Pcsc, Protocols, Scope, ShareMode};
use x509_cert::{der::Decode, Certificate};

const PIV_AID: &[u8] = &[0xa0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00];

#[derive(clap::Args)]
pub struct Args {
    /// Substring of the reader name to use (default: the first reader).
    #[arg(long)]
    reader: Option<String>,
}

pub fn run(args: Args) -> Result<()> {
    let ctx = Pcsc::establish(Scope::User).context("establish PCSC context")?;
    let mut buf = [0u8; 2048];
    let readers: Vec<_> = ctx.list_readers(&mut buf)?.collect();
    if readers.is_empty() {
        bail!("no PCSC reader -- flash the device so its CCID interface enumerates, or plug a PIV card");
    }

    println!("readers:");
    for r in &readers {
        println!("  - {}", r.to_string_lossy());
    }

    let reader = match &args.reader {
        Some(want) => *readers
            .iter()
            .find(|r| r.to_string_lossy().contains(want.as_str()))
            .with_context(|| format!("no reader matching {want:?}"))?,
        None => readers[0],
    };
    println!("\nusing reader: {}\n", reader.to_string_lossy());

    run_sequence(&ctx, reader)
}

/// Connect and run the full PIV chain once; any PCSC/card hiccup returns Err so run() can retry.
fn run_sequence(ctx: &Pcsc, reader: &CStr) -> Result<()> {
    let mut card = ctx.connect(reader, ShareMode::Shared, Protocols::ANY).context("connect to card")?;
    // Hold the card for the whole exchange so CryptoTokenKit can't reset it between our APDUs.
    let card = card.transaction().context("begin card transaction")?;

    expect_ok("SELECT PIV", &card, &apdu(0x00, 0xa4, 0x04, 0x00, PIV_AID))?;
    expect_ok("GET DATA CHUID", &card, &get_data(&[0x5f, 0xc1, 0x02]))?;

    let cert_object = expect_ok("GET DATA cert 9A", &card, &get_data(&[0x5f, 0xc1, 0x05]))?;
    let pubkey = pubkey_from_cert_object(&cert_object)?;
    println!("  parsed slot 9A certificate; got its P-256 public key");

    let challenge: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(3));
    let auth = expect_ok("GENERAL AUTHENTICATE", &card, &general_authenticate(&challenge))?;
    let signature = signature_from_auth(&auth)?;
    pubkey
        .verify_prehash(&challenge, &signature)
        .context("signature does NOT verify against the slot 9A key")?;
    println!("  signature verifies against the slot 9A key -- full PIV auth chain OK\n");

    println!("PIV: all checks passed.");
    Ok(())
}

/// Case-3/4 short APDU: header, Lc, data, then Le = 0 (request all available bytes).
fn apdu(cla: u8, ins: u8, p1: u8, p2: u8, data: &[u8]) -> Vec<u8> {
    let mut a = vec![cla, ins, p1, p2, data.len() as u8];
    a.extend_from_slice(data);
    a.push(0x00);
    a
}

fn get_data(tag: &[u8]) -> Vec<u8> {
    let mut tag_list = vec![0x5c, tag.len() as u8];
    tag_list.extend_from_slice(tag);
    apdu(0x00, 0xcb, 0x3f, 0xff, &tag_list)
}

fn general_authenticate(challenge: &[u8; 32]) -> Vec<u8> {
    // 7C { 82 00 (response placeholder)  81 <len> <challenge> }
    let mut template = vec![0x82, 0x00, 0x81, challenge.len() as u8];
    template.extend_from_slice(challenge);
    let mut data = vec![0x7c, template.len() as u8];
    data.extend_from_slice(&template);
    apdu(0x00, 0x87, 0x11, 0x9a, &data)
}

/// Transmit, follow 61xx GET RESPONSE chaining, print the exchange, and require SW 9000.
fn expect_ok(label: &str, card: &Card, send: &[u8]) -> Result<Vec<u8>> {
    let (data, sw) = transmit(card, send)?;
    println!("{label}\n  > {}\n  < {} SW={sw:04x}", hex(send), hex(&data));
    if sw != 0x9000 {
        bail!("{label}: expected SW 9000, got {sw:04x}");
    }
    Ok(data)
}

fn transmit(card: &Card, send: &[u8]) -> Result<(Vec<u8>, u16)> {
    let mut buf = vec![0u8; 4096];
    let mut out = Vec::new();
    let mut command = send.to_vec();
    loop {
        let resp = card.transmit(&command, &mut buf).context("APDU transmit")?;
        let (data, sw) = split_sw(resp)?;
        out.extend_from_slice(data);
        if sw >> 8 == 0x61 {
            command = vec![0x00, 0xc0, 0x00, 0x00, (sw & 0xff) as u8];
            continue;
        }
        return Ok((out, sw));
    }
}

fn split_sw(resp: &[u8]) -> Result<(&[u8], u16)> {
    if resp.len() < 2 {
        bail!("response too short for a status word");
    }
    let (data, sw) = resp.split_at(resp.len() - 2);
    Ok((data, u16::from_be_bytes([sw[0], sw[1]])))
}

fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }

/// Pull the X.509 certificate out of the PIV `53 { 70 <der> .. }` object and read its key.
fn pubkey_from_cert_object(object: &[u8]) -> Result<VerifyingKey> {
    let inner = unwrap_tlv(object, 0x53)?;
    let der = find_tlv(inner, 0x70).context("no 0x70 certificate in the PIV object")?;
    let cert = Certificate::from_der(der).context("parse X.509 certificate")?;
    let key = cert
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .context("certificate public key is not byte-aligned")?;
    VerifyingKey::from_sec1_bytes(key).context("certificate key is not a valid P-256 point")
}

/// Read the signature from the `7C { 82 <sig> }` GENERAL AUTHENTICATE response.
///
/// The device returns a raw r||s value; a standards-strict host expects the DER form, so this
/// is one of the wire details to confirm against a reference card.
fn signature_from_auth(resp: &[u8]) -> Result<Signature> {
    let inner = unwrap_tlv(resp, 0x7c)?;
    let raw = find_tlv(inner, 0x82).context("no 0x82 signature in the auth response")?;
    if let Ok(fixed) = <[u8; 64]>::try_from(raw) {
        return Signature::from_bytes(&fixed.into()).context("invalid raw ECDSA signature");
    }
    Signature::from_der(raw).context("invalid DER ECDSA signature")
}

/// Value of a single TLV that spans the whole buffer, checking its tag.
fn unwrap_tlv(data: &[u8], tag: u8) -> Result<&[u8]> {
    let (t, value, _) = read_tlv(data).context("truncated TLV")?;
    if t != tag {
        bail!("expected tag {tag:02x}, found {t:02x}");
    }
    Ok(value)
}

/// First value tagged `tag` in a flat short/long-form BER-TLV sequence.
fn find_tlv(mut data: &[u8], tag: u8) -> Option<&[u8]> {
    while !data.is_empty() {
        let (t, value, rest) = read_tlv(data)?;
        if t == tag {
            return Some(value);
        }
        data = rest;
    }
    None
}

/// One BER-TLV (single-byte tag; short, 0x81 or 0x82 length) -> (tag, value, remainder).
fn read_tlv(data: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *data.first()?;
    let (len, header) = match *data.get(1)? as usize {
        0x81 => (*data.get(2)? as usize, 3),
        0x82 => (((*data.get(2)? as usize) << 8) | *data.get(3)? as usize, 4),
        short => (short, 2),
    };
    let value = data.get(header..header + len)?;
    Some((tag, value, &data[header + len..]))
}
