use std::collections::{HashMap, HashSet};

use log::{warn, trace, info, error, debug};
use mio::{net::UdpSocket, Poll};
use quiche::{self, h3::{NameValue, self}};
use octets;

const WEBTRANSPORT_UNI_STREAM_TYPE: u64 = 0x54;
const H3_SETTING_ENABLE_WEBTRANSPORT: (u64, u64) = (0x2b603742, 1);

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[derive(Debug)]
pub enum Error {
    H3Error(quiche::h3::Error),
    BadH3Settings,
    CouldNotEstablishSession,
    MissingCapacityForOpeningStream,
    NotImplemented,
    SessionNotFound,
    VarintParsingError,
}

pub enum Event {
    StreamData,
}

// Implement the conversion from `ParseIntError` to `DoubleError`.
// This will be automatically called by `?` if a `ParseIntError`
// needs to be converted into a `DoubleError`.
impl From<quiche::h3::Error> for Error {
    fn from(err: quiche::h3::Error) -> Error {
        Error::H3Error(err)
    }
}
impl From<octets::BufferTooShortError> for Error {
    fn from(err: octets::BufferTooShortError) -> Error {
        Error::VarintParsingError
    }
}

#[derive(Clone, Copy)]
struct PartialSessionID {
    data: [u8; 8],
    received_len: usize,
}

pub struct Sessions {
    stream_id_to_session_id: HashMap<u64, u64>,
    partial_session_ids: HashMap<u64, PartialSessionID>,
    readable_streams: HashMap<u64, u64>,
    finished_streams: HashSet<u64>,
    ignore_webtransport_setting: bool,
}

impl Sessions {
    pub fn new(ignore_webtransport_setting: bool) -> Sessions {
        // nothing to do
        Sessions {
            stream_id_to_session_id: std::collections::HashMap::new(),
            partial_session_ids: std::collections::HashMap::new(),
            readable_streams: std::collections::HashMap::new(),
            finished_streams: std::collections::HashSet::new(),
            ignore_webtransport_setting,
        }
    }

    pub fn pipe_h3_streams(&mut self, h3_conn: &mut quiche::h3::Connection) -> Result<(), Error> {
        Ok(h3_conn.set_piped_stream_types(HashSet::from([WEBTRANSPORT_UNI_STREAM_TYPE]))?)
    }

    pub fn configure_h3_for_webtransport(&self, h3_config: &mut quiche::h3::Config) {
        // enable_webtransport settings
        h3_config.set_raw_settings(vec![H3_SETTING_ENABLE_WEBTRANSPORT]);
    }

    pub fn h3_connect_new_webtransport_session(&mut self, h3_conn: &mut quiche::h3::Connection, new_session_id: u64) -> Result<(), Error> {
        if self.ignore_webtransport_setting {
            return Ok(());
        }
        let raw_settings = h3_conn.peer_settings_raw();
        match raw_settings {
            Some(raw) => {
                for setting in raw {
                    if setting == &H3_SETTING_ENABLE_WEBTRANSPORT {
                        return Ok(())
                    }
                }
                trace!("BAD SETTINGS, RAW = {:?}", raw);
                Err(Error::BadH3Settings)
            }
            None => {
                trace!("BAD SETTINGS2");
                Err(Error::BadH3Settings)
            }
        }
    }

    pub fn is_stream_readable(
        &mut self, h3_conn: &mut quiche::h3::Connection, conn: &mut quiche::Connection, stream_id: u64, session_id: u64
    ) -> Result<bool, Error> {
        match self.stream_id_to_session_id.get(&stream_id) {
            Some(&s) if s == session_id => {
                Ok(conn.stream_readable(stream_id) || self.finished_streams.contains(&stream_id))
            }
            Some(_) | None => Err(Error::SessionNotFound)
        }
    }


    pub fn is_stream_finished(
        &mut self, h3_conn: &mut quiche::h3::Connection, conn: &mut quiche::Connection, stream_id: u64,
    ) -> Result<bool, Error> {
        match self.stream_id_to_session_id.get(&stream_id) {
            Some(&s) => {
                Ok(self.finished_streams.contains(&stream_id))
            }
            None => Err(Error::SessionNotFound)
        }
    }

    /// (stream_id, session_id)
    // pub fn readable(&self) -> std::collections::hash_map::Iter<u64, u64> {
    //     self.readable_streams.iter()
    // }


    /// (stream_id, session_id)
    pub fn readable(&self) -> Vec<(u64, u64)> {
        let mut ret = Vec::new();
        for (&stream_id, &session_id) in self.readable_streams.iter() {
            ret.push((stream_id, session_id));
        }
        ret
    }

    fn update_readable_state(&mut self, h3_conn: &mut quiche::h3::Connection, conn: &mut quiche::Connection, stream_id: u64, session_id: u64) -> Result<(), Error> {
        if self.is_stream_readable(h3_conn, conn, stream_id, session_id)? {
            self.readable_streams.insert(stream_id, session_id);
        } else {
            self.readable_streams.remove(&stream_id);
        }
        Ok(())
    }

    pub fn h3_stream_finished(&mut self, h3_stream_id: u64, h3_conn: &mut quiche::h3::Connection, conn: &mut quiche::Connection) -> Result<(), Error> {
        if let Some(&session_id) = self.stream_id_to_session_id.get(&h3_stream_id) {
            self.finished_streams.insert(h3_stream_id);
            self.update_readable_state(h3_conn, conn, h3_stream_id, session_id)
        } else {
            Err(Error::SessionNotFound)
        }
    }


    pub fn available_h3_stream_data(&mut self, h3_stream_id: u64, h3_conn: &mut quiche::h3::Connection, conn: &mut quiche::Connection) -> Result<(), Error> {
        let sid = match self.stream_id_to_session_id.get(&h3_stream_id) {
            Some(&session_id) => {
                Some(session_id)
                // maybe provide data to application
            }
            None => {
                let mut session_id = None;
                // create new stream ?
                let partial_session_id = match self.partial_session_ids.get_mut(&h3_stream_id) {
                    Some(partial_session_id) => {
                        partial_session_id
                    }
                    None => {
                        let mut partial_session_id = PartialSessionID { data: [0; 8], received_len: 0 };
                        // first read the first byte only
                        let read = h3_conn.recv_body(conn, h3_stream_id, &mut partial_session_id.data[..1])?;
                        if read == 0 {  // could not read the first session ID's byte
                            return Ok(());
                        }
                        partial_session_id.received_len += 1;
                        self.partial_session_ids.insert(h3_stream_id, partial_session_id);
                        self.partial_session_ids.get_mut(&h3_stream_id).unwrap()
                    }
                };
                let mut to_read = octets::varint_parse_len(partial_session_id.data[0]) - partial_session_id.received_len;
                if to_read > 0 {
                    let offset = partial_session_id.received_len;
                    let read = h3_conn.recv_body(conn, h3_stream_id, &mut partial_session_id.data[offset..offset+to_read])?;
                    to_read -= read;
                }
                if to_read == 0 {
                    let mut buf = octets::Octets::with_slice(&partial_session_id.data);
                    let sid = buf.get_varint()?;
                    self.partial_session_ids.remove(&h3_stream_id);
                    self.stream_id_to_session_id.insert(h3_stream_id, sid);
                    session_id = Some(sid);
                }
                session_id
            }
        };
        if let Some(session_id) = sid {
            self.update_readable_state(h3_conn, conn, h3_stream_id, session_id)?
        }
        Ok(())
    }

    pub fn open_uni_stream(&mut self, conn: &mut quiche::Connection, h3_conn: &mut quiche::h3::Connection, session_id: u64) -> Result<u64, Error> {
        let stream_id = h3_conn.open_application_pipe_uni_stream(conn, WEBTRANSPORT_UNI_STREAM_TYPE)?;
        let mut data = [0u8; 8];
        let mut buf = octets::OctetsMut::with_slice(&mut data);
        buf.put_varint(session_id).unwrap();
        let data = buf.buf();
        let written = h3_conn.send_application_pipe_stream_data(conn, stream_id, &data[..buf.off()], false)?;
        if written != buf.off() {
            return Err(Error::MissingCapacityForOpeningStream);
        }
        self.stream_id_to_session_id.insert(stream_id, session_id);
        Ok(stream_id)
    }

    pub fn uni_stream_write(&mut self, conn: &mut quiche::Connection, h3_conn: &mut quiche::h3::Connection, stream_id: u64, data: &[u8], fin: bool) -> Result<usize, Error> {
        Ok(h3_conn.send_application_pipe_stream_data(conn, stream_id, data, fin)?)
    }

    pub fn stream_recv(&mut self, conn: &mut quiche::Connection, h3_conn: &mut quiche::h3::Connection, stream_id: u64, session_id: u64, data: &mut[u8]) -> Result<usize, Error> {
        match self.stream_id_to_session_id.get(&stream_id) {
            Some(&s) if s == session_id => {
                let ret = Ok(h3_conn.recv_body(conn, stream_id, data)?);

                self.update_readable_state(h3_conn, conn, stream_id, session_id);
                ret
            }
            Some(_) | None => Err(Error::SessionNotFound)
        }
    }

    pub fn new_client_session_request(path: &str) -> Vec<quiche::h3::Header> {
        vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"quic.tech"),
            quiche::h3::Header::new(b":path", path.as_bytes()),
            quiche::h3::Header::new(b":protocol", b"webtransport"),
            quiche::h3::Header::new(b"user-agent", b"quiche"),
        ]
    }

}

impl Default for Sessions {
    fn default() -> Self {
        Self::new(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
