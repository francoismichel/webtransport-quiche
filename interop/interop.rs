use webtransport_quiche::Sessions;

#[derive(Debug)]
enum StreamDirection {
    Uni,
    Bidi,
}
#[derive(Debug)]
struct Stream {
    direction: StreamDirection,
    data: Vec<u8>,
    sent: usize,
    session_id: u64,
    stream_id: Option<u64>, // the stream id if it has been opened already
    fin: bool,
    closed: bool,
}

impl Stream {
    fn new_uni_from_data(session_id: u64, size: usize, data: &[u8]) -> Stream {
        let mut res = vec![0; size];
        let mut added = 0;
        while added != size {
            let to_add = std::cmp::min(size - added, added + data.len());
            res[added..added + to_add].copy_from_slice(data);
            added += to_add;
        }
        Stream {
            direction: StreamDirection::Uni,
            data: res,
            sent: 0,
            stream_id: None,
            closed: false,
            fin: true,
            session_id,
        }
    }

    fn new_bidi(stream_id: u64, session_id: u64) -> Stream {
        Stream {
            direction: StreamDirection::Bidi,
            data: vec![],
            sent: 0,
            stream_id: Some(stream_id),
            closed: false,
            fin: false,
            session_id,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    StreamNotFound,
    AddedDataOnFinStream,
    WebTransportError(webtransport_quiche::Error),
}

impl From<webtransport_quiche::Error> for Error {
    fn from(err: webtransport_quiche::Error) -> Error {
        Error::WebTransportError(err)
    }
}

pub enum InteropQuery {
    UniStreams((u32, usize)),
    EchoBidiStreams,
}

pub struct UniStreamsInteropHandler {
    streams: std::collections::HashMap<u64, Vec<Stream>>,
    stream_ids_to_indexes: std::collections::HashMap<u64, usize>,
    session_types: std::collections::HashMap<u64, InteropQuery>,
    buf: [u8; 1_000_000],
}

impl UniStreamsInteropHandler {
    pub fn new() -> UniStreamsInteropHandler {
        UniStreamsInteropHandler {
            streams: std::collections::HashMap::new(),
            stream_ids_to_indexes: std::collections::HashMap::new(),
            session_types: std::collections::HashMap::new(),
            buf: [0; 1000000],
        }
    }

    pub fn add_session_type(&mut self, session_id: u64, ty: InteropQuery) {
        self.session_types.insert(session_id, ty);
    }

    pub fn add_uni_stream_from_data(&mut self, session_id: u64, data: &[u8]) {
        if !self.streams.contains_key(&session_id) {
            self.streams.insert(session_id, Vec::new());
        }
        let session_streams = self.streams.get_mut(&session_id).unwrap();
        session_streams.push(Stream::new_uni_from_data(session_id, data.len(), data));
    }

    pub fn add_bidi_stream(&mut self, session_id: u64, stream_id: u64) {
        if !self.streams.contains_key(&session_id) {
            self.streams.insert(session_id, Vec::new());
        }
        let session_streams = self.streams.get_mut(&session_id).unwrap();
        session_streams.push(Stream::new_bidi(stream_id, session_id));
        self.stream_ids_to_indexes
            .insert(stream_id, session_streams.len() - 1);
    }

    fn is_bidi(stream_id: u64) -> bool {
        ((stream_id >> 1) & 1) == 0
    }

    fn add_data_to_stream(
        streams: &mut std::collections::HashMap<u64, Vec<Stream>>,
        stream_ids_to_indexes: &std::collections::HashMap<u64, usize>,
        session_id: u64,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> Result<(), Error> {
        match (
            streams.get_mut(&session_id),
            stream_ids_to_indexes.get(&stream_id),
        ) {
            (Some(streams), Some(&idx)) => {
                let stream = &mut streams[idx];
                if stream.fin && (!fin || data.len() != 0) {
                    Err(Error::AddedDataOnFinStream)
                } else {
                    stream.data.extend_from_slice(data);
                    stream.fin = fin;
                    Ok(())
                }
            }
            _ => Err(Error::StreamNotFound),
        }
    }

    pub fn handle_readable_streams(
        &mut self,
        sessions: &mut Sessions,
        h3_conn: &mut quiche::h3::Connection,
        conn: &mut quiche::Connection,
    ) -> Result<(), Error> {
        for (stream_id, session_id) in sessions.readable() {
            loop {
                let read = match sessions.stream_recv(
                    conn,
                    h3_conn,
                    stream_id,
                    session_id,
                    &mut self.buf[..],
                ) {
                    Ok(read) => read,
                    Err(webtransport_quiche::Error::H3Error(quiche::h3::Error::Done)) => 0,
                    Err(e) => return Err(Error::WebTransportError(e)),
                };

                if let Some(InteropQuery::EchoBidiStreams) = self.session_types.get(&session_id) {
                    // Echo
                    trace!(
                        "interop on bidi streams: echo stream {}, {} bytes for session {}",
                        stream_id,
                        read,
                        session_id
                    );
                    if Self::is_bidi(stream_id) && !self.streams.contains_key(&session_id)
                        || !self.stream_ids_to_indexes.contains_key(&stream_id)
                    {
                        self.add_bidi_stream(session_id, stream_id);
                    }
                    Self::add_data_to_stream(
                        &mut self.streams,
                        &self.stream_ids_to_indexes,
                        session_id,
                        stream_id,
                        &self.buf[..read],
                        sessions.is_stream_finished(stream_id)?,
                    )?;
                }
                if read == 0 {
                    // nothing to read, exit the loop
                    break;
                }
            }
        }
        Ok(())
    }

    pub fn handle_writable_streams(
        &mut self,
        sessions: &mut Sessions,
        h3_conn: &mut quiche::h3::Connection,
        conn: &mut quiche::Connection,
    ) -> Result<(), Error> {
        for (_session_id, streams) in self.streams.iter_mut() {
            for (idx, stream) in streams.iter_mut().enumerate() {
                if !stream.closed {
                    if stream.stream_id.is_none() {
                        match stream.direction {
                            StreamDirection::Uni => {
                                let stream_id =
                                    sessions.open_uni_stream(conn, h3_conn, stream.session_id)?;
                                stream.stream_id = Some(stream_id);
                                self.stream_ids_to_indexes.insert(stream_id, idx);
                            }
                            StreamDirection::Bidi => {
                                warn!("the interop handler is not supposed to open bidi streams");
                                continue;
                            }
                        }
                    }

                    match stream.stream_id {
                        Some(stream_id) => {
                            match sessions.stream_write(
                                conn,
                                h3_conn,
                                stream_id,
                                &stream.data[stream.sent..],
                                stream.fin,
                            ) {
                                Ok(written) => stream.sent += written,
                                Err(webtransport_quiche::Error::H3Error(
                                    quiche::h3::Error::Done,
                                )) => (),
                                Err(e) => return Err(Error::WebTransportError(e)),
                            }
                            stream.closed = stream.fin && stream.sent == stream.data.len();
                        }
                        None => todo!(),
                    }
                }
            }
        }
        Ok(())
    }

    pub fn all_done(&mut self, session_id: u64) -> bool {
        if let Some(streams) = self.streams.get(&session_id) {
            match self.session_types.get(&session_id) {
                Some(InteropQuery::UniStreams(_)) => {
                    for stream in streams {
                        if !stream.closed {
                            return false;
                        }
                    }
                    true
                }
                Some(InteropQuery::EchoBidiStreams) => false,
                None => {
                    error!("Could not find session {}", session_id);
                    true
                }
            }
        } else {
            true
        }
    }

    pub fn drain_done_sessions(&mut self) -> Vec<u64> {
        let done_sessions: Vec<u64> = self
            .streams
            .keys()
            .copied()
            .collect::<Vec<u64>>()
            .iter()
            .filter(|&&session_id| self.all_done(session_id))
            .map(|&val| val)
            .collect();
        for key in done_sessions.iter() {
            self.streams.remove(&key);
        }
        done_sessions
    }
}
