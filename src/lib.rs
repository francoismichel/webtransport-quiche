use std::collections::{HashMap, HashSet};

use octets;
pub extern crate quiche;
pub extern crate mio;

const WEBTRANSPORT_UNI_STREAM_TYPE: u64 = 0x54;
const WEBTRANSPORT_BIDI_FRAME_TYPE: u64 = 0x41;
const H3_SETTING_ENABLE_WEBTRANSPORT: (u64, u64) = (0x2b603742, 1);
const H3_SETTING_ENABLE_DATAGRAM_CHROME_SPECIFIC: (u64, u64) = (0xFFD277, 1);
const _H3_SETTING_ENABLE_CONNECT_PROTOCOL_CHROME_SPECIFIC: (u64, u64) = (0x8, 1);

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

#[derive(Debug)]
pub enum Error {
    H3Error(quiche::h3::Error),
    Done,
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
    fn from(_: octets::BufferTooShortError) -> Error {
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
    ignore_enable_webtransport_setting_absence: bool,
    google_chrome_compatible: bool,
}

impl Sessions {
    pub fn new(ignore_webtransport_setting: bool) -> Sessions {
        // nothing to do
        Sessions {
            stream_id_to_session_id: std::collections::HashMap::new(),
            partial_session_ids: std::collections::HashMap::new(),
            readable_streams: std::collections::HashMap::new(),
            finished_streams: std::collections::HashSet::new(),
            ignore_enable_webtransport_setting_absence: ignore_webtransport_setting,
            google_chrome_compatible: true,
        }
    }

    pub fn pipe_h3_streams(&self, config: &mut quiche::h3::Config) -> Result<(), Error> {
        Ok(config.set_passthrough_stream_types(HashSet::from([WEBTRANSPORT_UNI_STREAM_TYPE]))?)
    }

    pub fn pipe_h3_query_frames(
        &self,
        config: &mut quiche::h3::Config,
    ) -> Result<(), Error> {
        Ok(config.set_passthrough_query_frame_types(HashSet::from([WEBTRANSPORT_BIDI_FRAME_TYPE]))?)
    }

    pub fn configure_h3_for_webtransport(&self, h3_config: &mut quiche::h3::Config) -> Result<(), Error> {
        // enable_webtransport settings
        let additional_settings = if self.google_chrome_compatible {
            // H3_SETTING_ENABLE_CONNECT_PROTOCOL not needed but sent by chromium
            vec![
                H3_SETTING_ENABLE_WEBTRANSPORT,
                H3_SETTING_ENABLE_DATAGRAM_CHROME_SPECIFIC,
            ]
        } else {
            vec![H3_SETTING_ENABLE_WEBTRANSPORT]
        };
        h3_config.set_additional_settings(additional_settings);
        
        self
        .pipe_h3_streams(h3_config)?;
        
        self
        .pipe_h3_query_frames(h3_config)?;
        Ok(())
    }

    pub fn validate_new_webtransport_session(
        &mut self,
        h3_conn: &mut quiche::h3::Connection,
    ) -> Result<(), Error> {
        if self.ignore_enable_webtransport_setting_absence {
            return Ok(());
        }
        let raw_settings = h3_conn.peer_settings_raw();
        match raw_settings {
            Some(raw) => {
                for setting in raw {
                    if setting == &H3_SETTING_ENABLE_WEBTRANSPORT {
                        return Ok(());
                    }
                }
                Err(Error::BadH3Settings)
            }
            None => Err(Error::BadH3Settings),
        }
    }

    pub fn session_id(&self, stream_id: u64) -> Option<u64> {
        self.stream_id_to_session_id.get(&stream_id).copied()
    }

    pub fn is_stream_readable(
        &mut self,
        _h3_conn: &mut quiche::h3::Connection,
        conn: &mut quiche::Connection,
        stream_id: u64,
        session_id: u64,
    ) -> Result<bool, Error> {
        match self.stream_id_to_session_id.get(&stream_id) {
            Some(&s) if s == session_id => {
                Ok(conn.stream_readable(stream_id) || self.finished_streams.contains(&stream_id))
            }
            Some(_) | None => Err(Error::SessionNotFound),
        }
    }

    pub fn is_stream_finished(&mut self, stream_id: u64) -> Result<bool, Error> {
        match self.stream_id_to_session_id.get(&stream_id) {
            Some(&_sesion_id) => Ok(self.finished_streams.contains(&stream_id)),
            None => Err(Error::SessionNotFound),
        }
    }

    /// (stream_id, session_id)
    pub fn readable(&self) -> Vec<(u64, u64)> {
        let mut ret = Vec::new();
        for (&stream_id, &session_id) in self.readable_streams.iter() {
            ret.push((stream_id, session_id));
        }
        ret
    }

    fn set_readable_state(&mut self, stream_id: u64, session_id: u64, readable: bool) {
        if readable {
            self.readable_streams.insert(stream_id, session_id);
        } else {
            self.readable_streams.remove(&stream_id);
        }
    }

    pub fn h3_stream_finished(
        &mut self,
        h3_stream_id: u64,
        _h3_conn: &mut quiche::h3::Connection,
        _conn: &mut quiche::Connection,
    ) -> Result<(), Error> {
        if let Some(&session_id) = self.stream_id_to_session_id.get(&h3_stream_id) {
            self.finished_streams.insert(h3_stream_id);
            self.set_readable_state(h3_stream_id, session_id, true);
            Ok(())
        } else {
            Err(Error::SessionNotFound)
        }
    }

    pub fn available_h3_stream_data(
        &mut self,
        h3_stream_id: u64,
        h3_conn: &mut quiche::h3::Connection,
        conn: &mut quiche::Connection,
    ) -> Result<Option<u64>, Error> {
        let sid = match self.stream_id_to_session_id.get(&h3_stream_id) {
            Some(&session_id) => {
                Some(session_id)
                // maybe provide data to application
            }
            None => {
                let mut session_id = None;
                // create new stream ?
                let partial_session_id = match self.partial_session_ids.get_mut(&h3_stream_id) {
                    Some(partial_session_id) => partial_session_id,
                    None => {
                        let mut partial_session_id = PartialSessionID {
                            data: [0; 8],
                            received_len: 0,
                        };
                        // first read the first byte only
                        let read = h3_conn.recv_body(
                            conn,
                            h3_stream_id,
                            &mut partial_session_id.data[..1],
                        )?;
                        if read == 0 {
                            // could not read the first session ID's byte
                            return Ok(None);
                        }
                        partial_session_id.received_len += 1;
                        self.partial_session_ids
                            .insert(h3_stream_id, partial_session_id);
                        self.partial_session_ids.get_mut(&h3_stream_id).unwrap()
                    }
                };
                let mut to_read = octets::varint_parse_len(partial_session_id.data[0])
                    - partial_session_id.received_len;
                if to_read > 0 {
                    let offset = partial_session_id.received_len;
                    let read = h3_conn.recv_body(
                        conn,
                        h3_stream_id,
                        &mut partial_session_id.data[offset..offset + to_read],
                    )?;
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
            self.set_readable_state(h3_stream_id, session_id, true);
        }
        Ok(sid)
    }

    pub fn open_uni_stream(
        &mut self,
        conn: &mut quiche::Connection,
        h3_conn: &mut quiche::h3::Connection,
        session_id: u64,
    ) -> Result<u64, Error> {
        let stream_id =
            h3_conn.open_passthrough_uni_stream(conn, WEBTRANSPORT_UNI_STREAM_TYPE)?;
        let mut data = [0u8; 8];
        let mut buf = octets::OctetsMut::with_slice(&mut data);
        buf.put_varint(session_id).unwrap();
        let data = buf.buf();
        let written = h3_conn.send_passthrough_stream_data(
            conn,
            stream_id,
            &data[..buf.off()],
            false,
        )?;
        if written != buf.off() {
            return Err(Error::MissingCapacityForOpeningStream);
        }
        self.stream_id_to_session_id.insert(stream_id, session_id);
        Ok(stream_id)
    }

    pub fn open_bidi_stream(
        &mut self,
        conn: &mut quiche::Connection,
        h3_conn: &mut quiche::h3::Connection,
        session_id: u64,
    ) -> Result<u64, Error> {
        let stream_id =
            h3_conn.open_passthrough_frame_on_request_stream(conn, WEBTRANSPORT_BIDI_FRAME_TYPE)?;
        let mut data = [0u8; 8];
        let mut buf = octets::OctetsMut::with_slice(&mut data);
        buf.put_varint(session_id).unwrap();
        let data = buf.buf();
        let written = h3_conn.send_passthrough_stream_data(
            conn,
            stream_id,
            &data[..buf.off()],
            false,
        )?;
        if written != buf.off() {
            return Err(Error::MissingCapacityForOpeningStream);
        }
        self.stream_id_to_session_id.insert(stream_id, session_id);
        Ok(stream_id)
    }


    pub fn stream_write(
        &mut self,
        conn: &mut quiche::Connection,
        h3_conn: &mut quiche::h3::Connection,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<usize, Error> {
        Ok(h3_conn.send_passthrough_stream_data(conn, stream_id, data, fin)?)
    }

    pub fn stream_recv(
        &mut self,
        conn: &mut quiche::Connection,
        h3_conn: &mut quiche::h3::Connection,
        stream_id: u64,
        session_id: u64,
        data: &mut [u8],
    ) -> Result<usize, Error> {
        match self.stream_id_to_session_id.get(&stream_id) {
            Some(&s) if s == session_id => match h3_conn.recv_body(conn, stream_id, data) {
                Ok(read) => Ok(read),
                Err(quiche::h3::Error::Done) => {
                    self.set_readable_state(stream_id, session_id, false);
                    Err(Error::Done)
                }
                Err(e) => Err(Error::H3Error(e)),
            },
            Some(_) | None => Err(Error::SessionNotFound),
        }
    }

    pub fn new_client_session_request(path: &str) -> Vec<quiche::h3::Header> {
        vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":scheme", b"https"),
            quiche::h3::Header::new(b":authority", b"quic-interop"),
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
