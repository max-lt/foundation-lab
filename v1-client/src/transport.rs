//! QL v1 over the sim's BLE-over-TCP bridge.
//!
//! Each TCP frame is a 4-byte big-endian length followed by one btp chunk
//! (one BlePacket), mirroring KeyOS-dev os/bt/src/hosted.rs.

use std::io::{Read, Write};
use std::net::TcpStream;

use btp::{chunk, Chunk, MasterDechunker};

pub struct Transport {
    stream: TcpStream,
    dechunker: MasterDechunker<10>,
}

impl Transport {
    pub fn connect(addr: &str) -> std::io::Result<Self> {
        let stream = TcpStream::connect(addr)?;
        stream.set_nodelay(true).ok();
        Ok(Self { stream, dechunker: MasterDechunker::default() })
    }

    /// Chunk one QL envelope and write each chunk as a length-delimited frame.
    pub fn send_envelope(&mut self, cbor: &[u8]) -> std::io::Result<()> {
        for chunk in chunk(cbor) {
            let len = (chunk.len() as u32).to_be_bytes();
            self.stream.write_all(&len)?;
            self.stream.write_all(&chunk)?;
        }
        self.stream.flush()
    }

    /// Block until a full envelope reassembles, returning its CBOR bytes.
    pub fn recv_envelope(&mut self) -> std::io::Result<Vec<u8>> {
        loop {
            let mut len_buf = [0u8; 4];
            self.stream.read_exact(&mut len_buf)?;
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut payload = vec![0u8; len];
            self.stream.read_exact(&mut payload)?;

            let chunk = match Chunk::decode(&payload) {
                Ok(c) => c,
                Err(e) => {
                    log::warn!("dropping undecodable chunk: {e:?}");
                    continue;
                }
            };
            if let Some(envelope) = self.dechunker.insert_chunk(chunk) {
                return Ok(envelope);
            }
        }
    }
}
