use std::collections::VecDeque;
use std::fs::copy;
use rand::distributions::{Distribution};
use rand::Rng;
use webtransport_quiche::Sessions;

struct Stream {
    data: Vec<u8>,
    sent: usize,
    session_id: u64,
    stream_id: Option<u64>,  // the stream id if it has been opened already
    closed: bool,
}

impl Stream {
    fn new_random(session_id: u64, size: usize) -> Stream {
        let mut res = vec![0; size];
        rand::thread_rng().fill(&mut res[..]);
        Stream{
            data: res,
            sent: 0,
            stream_id: None,
            closed: false,
            session_id,
        }
    }
    fn from_data(session_id: u64, size: usize, data: &[u8]) -> Stream {
        let mut res = vec![0; size];
        let mut added = 0;
        while added != size {
            let to_add = std::cmp::min(size - added, added + data.len());
            res[added..added+to_add].copy_from_slice(data);
            added += to_add;
        }
        Stream{
            data: res,
            sent: 0,
            stream_id: None,
            closed: false,
            session_id,
        }
    }
}

pub struct InteropHandler {
    uni_streams: std::collections::HashMap<u64, Vec<Stream>>,
}

impl InteropHandler {
    pub fn new() -> InteropHandler {
        InteropHandler { uni_streams: std::collections::HashMap::new() }
    }

    pub fn add_random_uni_stream(&mut self, session_id: u64, size: usize) {
        if !self.uni_streams.contains_key(&session_id) {
            self.uni_streams.insert(session_id, Vec::new());
        }
        let mut session_uni_streams = self.uni_streams.get_mut(&session_id).unwrap();
        session_uni_streams.push(Stream::new_random(session_id, size));
    }

    pub fn add_uni_stream_from_data(&mut self, session_id: u64, data: &[u8]) {
        if !self.uni_streams.contains_key(&session_id) {
            self.uni_streams.insert(session_id, Vec::new());
        }
        let mut session_uni_streams = self.uni_streams.get_mut(&session_id).unwrap();
        session_uni_streams.push(Stream::from_data(session_id, data.len(), data));
    }

    pub fn handle_writable_streams(&mut self, sessions: &mut Sessions, h3_conn: &mut quiche::h3::Connection, conn: &mut quiche::Connection) -> Result<(), webtransport_quiche::Error> {
        for (_session_id, streams) in self.uni_streams.iter_mut() {
            for stream in streams {
                if !stream.closed {
                    if stream.stream_id.is_none() {
                        stream.stream_id = Some(sessions.open_uni_stream(conn, h3_conn, stream.session_id)?);
                    }
                    
                    match stream.stream_id {
                        Some(stream_id) => {
                            stream.sent += sessions.uni_stream_write(conn, h3_conn, stream_id, &stream.data[stream.sent..], true)?;
                            stream.closed = stream.sent == stream.data.len();
                        }
                        None => todo!(),
                    }
                }
            }
        }
        Ok(())
    }

    pub fn all_done(&mut self, session_id: u64) -> bool {
        if let Some(streams) = self.uni_streams.get(&session_id) {
            for stream in streams {
                if !stream.closed {
                    return false;
                }
            }
        }
        true
    }

    pub fn drain_done_sessions(&mut self) -> Vec<u64> {
        let done_sessions: Vec<u64> = self.uni_streams.keys().copied().collect::<Vec<u64>>().iter().filter(|&&session_id| self.all_done(session_id)).map(|&val| val).collect();
        for key in done_sessions.iter() {
            self.uni_streams.remove(&key);
        }
        done_sessions
    }

}
