use std::collections::VecDeque;
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
}

pub struct InteropHandler {
    uni_streams: Vec<Stream>,
}

impl InteropHandler {
    pub fn new() -> InteropHandler {
        InteropHandler { uni_streams: Vec::new() }
    }

    pub fn add_uni_stream(&mut self, session_id: u64, size: usize) {
        self.uni_streams.push(Stream::new_random(session_id, size));
    }

    pub fn handle_writable_streams(&mut self, sessions: &mut Sessions, h3_conn: &mut quiche::h3::Connection, conn: &mut quiche::Connection) -> Result<(), webtransport_quiche::Error> {
        for stream in self.uni_streams.iter_mut() {
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
        Ok(())
    }

    pub fn has_data_to_send(&self) -> bool {
        self.uni_streams.iter().any(|s| s.sent < s.data.len())
    }

}
