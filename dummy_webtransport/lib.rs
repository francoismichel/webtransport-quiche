// Copyright (C) 2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#[macro_use]
extern crate log;

use mio::net::UdpSocket;
use quiche::ConnectionId;

use std::fs::File;
use std::io;
use std::net::{self, SocketAddr, ToSocketAddrs};

use std::collections::HashMap;

use ring::rand::*;

use quiche::h3::NameValue;
use regex::Regex;

const MAX_DATAGRAM_SIZE: usize = 1350;

struct H3Client {
    conn: quiche::Connection,

    http3_conn: Option<quiche::h3::Connection>,

    webtransport_sessions: webtransport_quiche::Sessions,

    partial_responses: HashMap<u64, PartialResponse>,
}
type ClientMap = HashMap<quiche::ConnectionId<'static>, H3Client>;

struct PartialResponse {
    headers: Option<Vec<quiche::h3::Header>>,

    body: Vec<u8>,

    written: usize,

    is_connect: bool,
}


pub struct DummyWebTransportServer {
    buf: [u8; 65535],
    dgrams_buf: [u8; MAX_DATAGRAM_SIZE],
    quic_config: quiche::Config,
    h3_config: quiche::h3::Config,
    socket: UdpSocket,
    clients: ClientMap,
    poll: mio::Poll,
    events: mio::Events,
    conn_id_seed: ring::hmac::Key,
    keylog: Option<File>,
}

pub struct DummyWebTransportClient {
    buf: [u8; 65535],
    dgrams_buf: [u8; MAX_DATAGRAM_SIZE],
    socket: UdpSocket,
    poll: mio::Poll,
    events: mio::Events,
    conn: quiche::Connection,
    h3_conn: quiche::h3::Connection,
    webtransport_sessions: webtransport_quiche::Sessions,
    session_id: u64,
}

impl DummyWebTransportClient {

    pub fn connect(url: url::Url, mut quic_config: quiche::Config, mut h3_config: quiche::h3::Config, keylog: Option<File>) -> Result<DummyWebTransportClient, Error> {
        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];

        

        // Setup the event loop.
        let mut poll = mio::Poll::new().unwrap();
        let mut events = mio::Events::with_capacity(1024);

        // Create the UDP listening socket, and register it with the event loop.
        let mut socket = mio::net::UdpSocket::bind("0.0.0.0:0".parse()?)?;
        poll.registry()
            .register(&mut socket, mio::Token(0), mio::Interest::READABLE)?;
    
        // Create the configuration for the QUIC connections.

        // Generate a random source connection ID for the connection.
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        SystemRandom::new().fill(&mut scid[..]).unwrap();

        let scid = quiche::ConnectionId::from_ref(&scid);

        // Get local address.
        let local_addr = socket.local_addr()?;

        // Resolve server address.
        let peer_addr = url.to_socket_addrs()?.next().unwrap();

        let mut http3_conn = None;
        let mut webtransport_session_id = None;
        let webtransport_sessions = webtransport_quiche::Sessions::new(false);
        webtransport_sessions.configure_h3_for_webtransport(&mut h3_config)?;

        // Create a QUIC connection and initiate handshake.
        let mut conn =
            quiche::connect(url.domain(), &scid, local_addr, peer_addr, &mut quic_config)?;

        if let Some(keylog) = keylog {
            if let Ok(keylog) = keylog.try_clone() {
                conn.set_keylog(Box::new(keylog));
            }
        }

        info!(
            "connecting to {:} from {:} with scid {}",
            url,
            socket.local_addr()?,
            hex_dump(&scid)
        );

        let (write, send_info) = conn.send(&mut out)?;

        while let Err(e) = socket.send_to(&out[..write], send_info.to) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                debug!("send() would block");
                continue;
            }

            panic!("send() failed: {:?}", e);
        }

        debug!("written {}", write);

        // Prepare request.
        let mut path = String::from(url.path());

        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }

        let req = webtransport_quiche::Sessions::new_client_session_request(url.path());

        let mut req_sent = false;

        let mut webtransport_connected = false;

        loop {
            poll.poll(&mut events, conn.timeout())?;

            // Read incoming UDP packets from the socket and feed them to quiche,
            // until there are no more packets to read.
            'read: loop {
                // If the event loop reported no events, it means that the timeout
                // has expired, so handle it without attempting to read packets. We
                // will then proceed with the send loop.
                if events.is_empty() {
                    debug!("timed out");

                    conn.on_timeout();

                    break 'read;
                }
            
                trace!("recvfrom()");
                let (len, from) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,

                    Err(e) => {
                        // There are no more UDP packets to read, so end the read
                        // loop.
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("recv() would block");
                            break 'read;
                        }

                        panic!("recv() failed: {:?}", e);
                    },
                };

                debug!("got {} bytes", len);

                let recv_info = quiche::RecvInfo {
                    to: local_addr,
                    from,
                };

                // Process potentially coalesced packets.
                let read = match conn.recv(&mut buf[..len], recv_info) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("recv failed: {:?}", e);
                        continue 'read;
                    },
                };

                debug!("processed {} bytes", read);
            }

            debug!("done reading");

            if conn.is_closed() {
                info!("connection closed, {:?}", conn.stats());
                break;
            }

            // Create a new HTTP/3 connection once the QUIC connection is established.
            if conn.is_established() && http3_conn.is_none() {
                let h3_conn = quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size");
                
                http3_conn = Some(h3_conn);
            }

            // Send HTTP requests once the QUIC connection is established, and until
            if let Some(h3_conn) = &mut http3_conn {
                if !req_sent {
                    info!("sending HTTP request {:?}", req);

                    webtransport_session_id = Some(h3_conn.send_request(&mut conn, &req, false)?);

                    req_sent = true;
                }
            }

            if let Some(http3_conn) = &mut http3_conn {
                // Process HTTP/3 events.
                loop {
                    match http3_conn.poll(&mut conn) {
                        Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                            info!(
                                "got response headers {:?} on stream id {}",
                                hdrs_to_strings(&list),
                                stream_id
                            );
                            if webtransport_session_id.is_some() && webtransport_session_id.unwrap() == stream_id {
                                let mut status_ok = false;
                                for hdr in list {
                                    if let b":status" = hdr.name() {
                                        info!("response: status = {}", String::from_utf8(hdr.value().to_vec()).unwrap_or(format!("{:?}", hdr.value())));
                                        if hdr.value() == b"200" {
                                            status_ok = true;
                                        }
                                    }
                                }
                                if status_ok {
                                    webtransport_connected = true;
                                    break;
                                }
                            }
                        },

                        Ok((stream_id, quiche::h3::Event::Data)) => {
                            while let Ok(read) =
                                http3_conn.recv_body(&mut conn, stream_id, &mut buf)
                            {
                                debug!(
                                    "got {} bytes of response data on stream {}",
                                    read, stream_id
                                );
                            }
                        },

                        Ok((_stream_id, quiche::h3::Event::Finished)) => {
                            conn.close(true, 0x00, b"kthxbye")?;
                            return Err(Error::ConnectionClosed(None))
                        },

                        Ok((_stream_id, quiche::h3::Event::Reset(e))) => {
                            error!(
                                "request was reset by peer with {}, closing...",
                                e
                            );

                            conn.close(true, 0x00, b"kthxbye")?;
                            return Err(Error::ConnectionClosed(None));
                        },

                        Ok((_flow_id, quiche::h3::Event::Datagram)) => (),

                        Ok((_, quiche::h3::Event::PriorityUpdate)) => unreachable!(),

                        Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                            info!("GOAWAY id={}", goaway_id);
                        },

                        Ok((_, quiche::h3::Event::PassthroughData(_))) =>
                            unreachable!(),

                        Err(quiche::h3::Error::Done) => {
                            break;
                        },

                        Err(e) => {
                            error!("HTTP/3 processing failed: {:?}", e);

                            break;
                        },
                    }
                }
            }

            // Generate outgoing QUIC packets and send them on the UDP socket, until
            // quiche reports that there are no more packets to be sent.
            loop {
                let (write, send_info) = match conn.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        debug!("done writing");
                        break;
                    },

                    Err(e) => {
                        error!("send failed: {:?}", e);

                        conn.close(false, 0x1, b"fail").ok();
                        break;
                    },
                };

                if let Err(e) = socket.send_to(&out[..write], send_info.to) {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("send() would block");
                        break;
                    }

                    panic!("send() failed: {:?}", e);
                }

                debug!("written {}", write);
            }

            if conn.is_closed() {
                info!("connection closed, {:?}", conn.stats());
                return Err(Error::ConnectionClosed(conn.peer_error().cloned()));
            }
            if webtransport_connected {
                break;
            }
        }



        if let Some(h3_conn) = http3_conn {
            Ok(DummyWebTransportClient {
                buf: buf,
                dgrams_buf: out,
                socket,
                poll,
                events,
                conn,
                h3_conn,
                webtransport_sessions,
                session_id: webtransport_session_id.unwrap(),
            })
        } else {
            Err(Error::CouldNotConnect)
        }

    }


    pub fn poll(&mut self) -> Result<Event, Error> {
        // Process HTTP/3 events.
        loop {
            match self.h3_conn.poll(&mut self.conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    info!("got headers on stream {}, ignoring: {:?}", stream_id, list);
                }

                Ok((stream_id, quiche::h3::Event::Data)) => {
                    info!(
                        "{} got data on stream id {}, ignoring",
                        self.conn.trace_id(),
                        stream_id
                    );
                }

                Ok((stream_id, quiche::h3::Event::Finished)) => {
                    if let Err(e) = self.webtransport_sessions.h3_stream_finished(
                        stream_id,
                        &mut self.h3_conn,
                        &mut self.conn,
                    ) {
                        error!("could not signal finished stream {} to webtransport session: {:?}", stream_id, e);
                    } else {
                        info!("finished stream {}", stream_id);
                        return Ok(Event::StreamData(self.session_id, stream_id));
                    }
                }

                Ok((_stream_id, quiche::h3::Event::Reset { .. })) => todo!(),

                Ok((_flow_id, quiche::h3::Event::Datagram)) => (),

                Ok((_prioritized_element_id, quiche::h3::Event::PriorityUpdate)) => (),

                Ok((_goaway_id, quiche::h3::Event::GoAway)) => {
                    self.conn.close(true, 0, b"Received GO_AWAY")?;
                    return Ok(Event::GoAway);
                },

                Ok((stream_id, quiche::h3::Event::PassthroughData(_))) => {
                    match self.webtransport_sessions.available_h3_stream_data(
                        stream_id,
                        &mut self.h3_conn,
                        &mut self.conn,
                    ) {
                        Err(e) => error!("could not provide stream {} data to webtransport session: {:?}", stream_id, e),
                        Ok(Some(session_id)) => return Ok(Event::StreamData(session_id, stream_id)),
                        e => info!("application pipe returned {:?}", e),
                    }
                }

                Err(quiche::h3::Error::Done) => {
                    break;
                }

                Err(e) => {
                    error!("{} HTTP/3 error {:?}", self.conn.trace_id(), e);
                    return Err(Error::H3Error(e));
                }
            }
        }
        Ok(Event::Done)
    }

    pub fn wait_for_events(&mut self) -> Result<(), Error> {
        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        loop {
            let (write, send_info) = match self.conn.send(&mut self.dgrams_buf) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("done writing");
                    break;
                },

                Err(e) => {
                    error!("send failed: {:?}", e);

                    self.conn.close(false, 0x1, b"fail").ok();
                    break;
                },
            };

            if let Err(e) = self.socket.send_to(&self.dgrams_buf[..write], send_info.to) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    debug!("send() would block");
                    break;
                }

                panic!("send() failed: {:?}", e);
            }

            debug!("written {}", write);
        }

        if self.conn.is_closed() {
            let conn_stats = self.conn.stats();
            info!("connection closed, {:?}", conn_stats);
            self.conn.peer_error();
            return Err(Error::ConnectionClosed(self.conn.peer_error().cloned()));
        }


        self.poll.poll(&mut self.events, self.conn.timeout())?;

        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            // If the event loop reported no events, it means that the timeout
            // has expired, so handle it without attempting to read packets. We
            // will then proceed with the send loop.
            if self.events.is_empty() {
                debug!("timed out");

                self.conn.on_timeout();

                break 'read;
            }

            let (len, from) = match self.socket.recv_from(&mut self.buf) {
                Ok(v) => v,

                Err(e) => {
                    // There are no more UDP packets to read, so end the read
                    // loop.
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            debug!("got {} bytes", len);

            let recv_info = quiche::RecvInfo {
                to: self.socket.local_addr()?,
                from,
            };

            // Process potentially coalesced packets.
            let read = match self.conn.recv(&mut self.buf[..len], recv_info) {
                Ok(v) => v,

                Err(e) => {
                    error!("recv failed: {:?}", e);
                    continue 'read;
                },
            };

            debug!("processed {} bytes", read);
        }

        debug!("done reading");
        Ok(())
    }

    pub fn read(&mut self, stream_id: u64, data: &mut [u8]) -> Result<usize, Error> {
        match self.webtransport_sessions.stream_recv(&mut self.conn, &mut self.h3_conn, stream_id, self.session_id, data) {
            Ok(read) => Ok(read),
            Err(webtransport_quiche::Error::Done) => {
                if self.webtransport_sessions.is_stream_finished(stream_id)? {
                    Err(Error::Finished)
                } else {
                    Err(Error::Done)
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn write(&mut self, stream_id: u64, data: &[u8], fin: bool) -> Result<usize, Error> {
        Ok(self.webtransport_sessions.stream_write(&mut self.conn, &mut self.h3_conn, stream_id, data, fin)?)
    }

    pub fn open_uni_stream(&mut self, session_id: u64) -> Result<u64, Error> {
        Ok(self.webtransport_sessions.open_uni_stream(&mut self.conn, &mut self.h3_conn, session_id)?)
    }

    pub fn open_bidi_stream(&mut self) -> Result<u64, Error> {
        Ok(self.webtransport_sessions.open_bidi_stream(&mut self.conn, &mut self.h3_conn, self.session_id)?)
    }

    pub fn close_session(&mut self) -> Result<(), Error> {
        Ok(self.conn.close(true, 0, b"session closed by the application")?)
    }

}

fn contains_webtransport_connect(
    request: &[quiche::h3::Header],
    uri_regexes: &[Regex],
) -> (bool, Option<String>, Option<usize>) {
    let mut contains_connect = false;
    let mut contains_webtransport = false;
    let mut correct_path = false;
    let mut path_ret = None;
    let mut regex_idx_ret = None;
    for hdr in request {
        if let b":method" = hdr.name() {
            if hdr.value() == b"CONNECT" {
                contains_connect = true;
            }
        }
        if let b":protocol" = hdr.name() {
            if hdr.value() == b"webtransport" {
                contains_webtransport = true;
            }
        }
        if let b":path" = hdr.name() {
            if let Ok(path) = std::str::from_utf8(hdr.value()) {
                if let Some((idx, _)) = uri_regexes.iter().enumerate().find(|(_, re)| re.is_match(path)) {
                    correct_path = true;
                    path_ret = Some(path.to_string());
                    regex_idx_ret = Some(idx);
                }
            }
        }
    }
    (
        contains_connect && contains_webtransport && correct_path,
        path_ret,
        regex_idx_ret
    )
}


/// Handles incoming HTTP/3 requests.
fn handle_request(
    stream_id: u64,
    headers: &[quiche::h3::Header],
    connect_uris: &[Regex],
) -> (Option<String>, Option<usize>) {

    let (contains_webtransport_connect, path_opt, matching_regex_idx) =
        contains_webtransport_connect(headers, connect_uris);

    info!(
        "got request {:?} on stream id {}, contains_webtransport_connect = {}",
        hdrs_to_strings(headers),
        stream_id,
        contains_webtransport_connect
    );

    (path_opt, matching_regex_idx)
}

/// Builds an HTTP/3 response given a request.
fn build_connect_response(status: u64, body: &str) -> Vec<quiche::h3::Header> {
    vec![
        quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
        quiche::h3::Header::new(b"server", b"quiche"),
        quiche::h3::Header::new(b"sec-webtransport-http3-draft", b"draft02"),
        quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
    ]
}

/// Builds an HTTP/3 response given a request.
fn build_response(status: u64, body: &str) -> Vec<quiche::h3::Header> {
    vec![
        quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
        quiche::h3::Header::new(b"server", b"quiche"),
        quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
    ]
}

/// Handles newly writable streams.
fn handle_writable(client: &mut H3Client, stream_id: u64) {
    let conn = &mut client.conn;
    let http3_conn = &mut client.http3_conn.as_mut().unwrap();

    debug!("{} stream {} is writable", conn.trace_id(), stream_id);

    if !client.partial_responses.contains_key(&stream_id) {
        return;
    }

    let resp = client.partial_responses.get_mut(&stream_id).unwrap();

    if let Some(ref headers) = resp.headers {
        match http3_conn.send_response(conn, stream_id, headers, false) {
            Ok(_) => (),

            Err(quiche::h3::Error::StreamBlocked) => {
                return;
            }

            Err(e) => {
                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return;
            }
        }
    }

    resp.headers = None;

    let body = &resp.body[resp.written..];

    let written = match http3_conn.send_body(conn, stream_id, body, !resp.is_connect) {
        Ok(v) => v,

        Err(quiche::h3::Error::Done) => 0,

        Err(e) => {
            client.partial_responses.remove(&stream_id);

            error!("{} stream send failed {:?}", conn.trace_id(), e);
            return;
        }
    };

    resp.written += written;

    if resp.written == resp.body.len() {
        client.partial_responses.remove(&stream_id);
    }
}

pub enum Event {
    /// HTTP3 uri path, matching regex index
    NewSession(String, usize),
    /// session_id, stream_id
    StreamData(u64, u64),
    Done,
    GoAway,
}

#[derive(Debug)]
pub enum Error {
    IOError(io::Error),
    QUICError(quiche::Error),
    H3Error(quiche::h3::Error),
    WebTransportError(webtransport_quiche::Error),
    AddrParseError(std::net::AddrParseError),
    StreamWritingFailed(quiche::h3::Error),
    StreamBlockedDuringConnect,
    ClientNotFound,
    CouldNotConnect,
    ConnectionClosed(Option<quiche::ConnectionError>),
    Done,
    Finished,
}

impl From<std::net::AddrParseError> for Error {
    fn from(err: std::net::AddrParseError) -> Error {
        Error::AddrParseError(err)
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IOError(err)
    }
}

impl From<quiche::Error> for Error {
    fn from(err: quiche::Error) -> Error {
        Error::QUICError(err)
    }
}

impl From<quiche::h3::Error> for Error {
    fn from(err: quiche::h3::Error) -> Error {
        match err {
            quiche::h3::Error::Done => Error::Done,
            e => Error::H3Error(e),
        }
    }
}

impl From<webtransport_quiche::Error> for Error {
    fn from(err: webtransport_quiche::Error) -> Error {
        match err {
            webtransport_quiche::Error::Done => Error::Done,
            webtransport_quiche::Error::H3Error(quiche::h3::Error::Done) => Error::Done,
            e => Error::WebTransportError(e),
        }
    }
}


impl DummyWebTransportServer {

    pub fn with_configs(addr: SocketAddr, quic_config: quiche::Config, h3_config: quiche::h3::Config, keylog: Option<File>) -> DummyWebTransportServer {
    
        // Setup the event loop.
        let poll = mio::Poll::new().unwrap();
        let events = mio::Events::with_capacity(1024);
    
        // Create the UDP listening socket, and register it with the event loop.
        let mut socket = mio::net::UdpSocket::bind(addr).unwrap();
        poll.registry()
            .register(&mut socket, mio::Token(0), mio::Interest::READABLE)
            .unwrap();

    
        let rng = SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

        

        DummyWebTransportServer {
            buf: [0; 65535],
            dgrams_buf: [0; MAX_DATAGRAM_SIZE],
            quic_config: quic_config,
            h3_config: h3_config,
            socket,
            clients:ClientMap::new(),
            poll,
            events,
            conn_id_seed,
            keylog,
        }
    }

    pub fn listen(&mut self) -> Result<Option<Vec<u8>>, Error> {
        loop {

            // Generate outgoing QUIC packets for all active connections and send
            // them on the UDP socket, until quiche reports that there are no more
            // packets to be sent.
            for client in self.clients.values_mut() {
                loop {
                    let (write, send_info) = match client.conn.send(&mut self.dgrams_buf) {
                        Ok(v) => v,

                        Err(quiche::Error::Done) => {
                            debug!("{} done writing", client.conn.trace_id());
                            break;
                        }

                        Err(e) => {
                            error!("{} send failed: {:?}", client.conn.trace_id(), e);

                            client.conn.close(false, 0x1, b"fail").ok();
                            break;
                        }
                    };

                    if let Err(e) = self.socket.send_to(&self.dgrams_buf[..write], send_info.to) {
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("send() would block");
                            break;
                        }

                        panic!("send() failed: {:?}", e);
                    }

                    debug!("{} written {} bytes", client.conn.trace_id(), write);
                }
            }

            // Garbage collect closed connections.
            self.clients.retain(|_, ref mut c| {
                debug!("Collecting garbage");
                if c.conn.is_closed() {
                    info!(
                        "{} connection collected {:?}",
                        c.conn.trace_id(),
                        c.conn.stats()
                    );
                    if let Some(e) = c.conn.peer_error() {
                        info!(
                            "Connection error: peer error reason = {:?}",
                            String::from_utf8(e.reason.clone())
                        );
                    }
                }

                !c.conn.is_closed()
            });


            let local_addr = self.socket.local_addr().unwrap();
            // Find the shorter timeout from all the active connections.
            //
            // TODO: use event loop that properly supports timers
            let timeout = self.clients.values().filter_map(|c| c.conn.timeout()).min();
            // if there are still packets to process on the mio socket (that is non-blocking), process them, otherwise do a poll
            match self.socket.peek(&mut self.buf[..0]) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    self.poll.poll(&mut self.events, timeout).unwrap();
                }
                _ => {
                    trace!("No need to poll, there are still packets to process from the mio socket.")
                }
            }

            // Read incoming UDP packets from the socket and feed them to quiche,
            // until there are no more packets to read.
            'read: loop {
                // If the event loop reported no events, it means that the timeout
                // has expired, so handle it without attempting to read packets. We
                // will then proceed with the send loop.
                if self.events.is_empty() {
                    debug!("timed out");

                    self.clients.values_mut().for_each(|c| c.conn.on_timeout());

                    break 'read;
                }

                let (len, from) = match self.socket.recv_from(&mut self.buf) {
                    Ok(v) => v,

                    Err(e) => {
                        // There are no more UDP packets to read, so end the read
                        // loop.
                        if e.kind() == std::io::ErrorKind::WouldBlock {
                            debug!("recv() would block");
                            break 'read;
                        }

                        panic!("recv() failed: {:?}", e);
                    }
                };

                debug!("got {} bytes", len);

                let pkt_buf = &mut self.buf[..len];

                // Parse the QUIC packet's header.
                let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("Parsing packet header failed: {:?}", e);
                        continue 'read;
                    }
                };

                trace!("got packet {:?}", hdr);

                let conn_id = ring::hmac::sign(&self.conn_id_seed, &hdr.dcid);
                let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
                let conn_id = conn_id.to_vec().into();

                // Lookup a connection based on the packet's connection ID. If there
                // is no connection matching, create a new one.
                let client = if !self.clients.contains_key(&hdr.dcid) && !self.clients.contains_key(&conn_id) {
                    if hdr.ty != quiche::Type::Initial {
                        error!("Packet is not Initial");
                        continue 'read;
                    }

                    if !quiche::version_is_supported(hdr.version) {
                        warn!("Doing version negotiation");

                        let len = if let Ok(l) = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut self.dgrams_buf) {
                            l
                        } else {
                            continue 'read;
                        };

                        let out = &self.dgrams_buf[..len];

                        if let Err(e) = self.socket.send_to(out, from) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                debug!("send() would block");
                                break;
                            }

                            panic!("send() failed: {:?}", e);
                        }
                        continue 'read;
                    }

                    let mut scid = [0; quiche::MAX_CONN_ID_LEN];
                    scid.copy_from_slice(&conn_id);

                    let scid = quiche::ConnectionId::from_ref(&scid);

                    // Token is always present in Initial packets.
                    let token = hdr.token.as_ref().unwrap();

                    // Do stateless retry if the client didn't send a token.
                    if token.is_empty() {
                        warn!("Doing stateless retry");

                        let new_token = mint_token(&hdr, &from);

                        let len = quiche::retry(
                            &hdr.scid,
                            &hdr.dcid,
                            &scid,
                            &new_token,
                            hdr.version,
                            &mut self.dgrams_buf,
                        )
                        .unwrap();

                        let out = &self.dgrams_buf[..len];

                        if let Err(e) = self.socket.send_to(out, from) {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                debug!("send() would block");
                                break;
                            }

                            panic!("send() failed: {:?}", e);
                        }
                        continue 'read;
                    }

                    let odcid = validate_token(&from, token);

                    // The token was not valid, meaning the retry failed, so
                    // drop the packet.
                    if odcid.is_none() {
                        error!("Invalid address validation token");
                        continue 'read;
                    }

                    if scid.len() != hdr.dcid.len() {
                        error!("Invalid destination connection ID");
                        continue 'read;
                    }

                    // Reuse the source connection ID we sent in the Retry packet,
                    // instead of changing it again.
                    let scid = hdr.dcid.clone();

                    debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                    let mut conn =
                        quiche::accept(&scid, odcid.as_ref(), local_addr, from, &mut self.quic_config).unwrap();

                    if let Some(keylog) = &mut self.keylog {
                        if let Ok(keylog) = keylog.try_clone() {
                            conn.set_keylog(Box::new(keylog));
                        }
                    }

                    let client = H3Client {
                        conn,
                        http3_conn: None,
                        partial_responses: HashMap::new(),
                        webtransport_sessions: webtransport_quiche::Sessions::new(true),
                    };

                    client
                        .webtransport_sessions
                        .configure_h3_for_webtransport(&mut self.h3_config)?;

                    self.clients.insert(scid.clone(), client);

                    self.clients.get_mut(&scid).unwrap()
                } else {
                    match self.clients.get_mut(&hdr.dcid) {
                        Some(v) => v,

                        None => self.clients.get_mut(&conn_id).unwrap(),
                    }
                };

                let recv_info = quiche::RecvInfo {
                    to: self.socket.local_addr().unwrap(),
                    from,
                };

                // Process potentially coalesced packets.
                let read = match client.conn.recv(pkt_buf, recv_info) {
                    Ok(v) => v,

                    Err(e) => {
                        error!("{} recv failed: {:?}", client.conn.trace_id(), e);
                        continue 'read;
                    }
                };

                debug!("{} processed {} bytes", client.conn.trace_id(), read);

                // Create a new HTTP/3 connection as soon as the QUIC connection
                // is established.
                if (client.conn.is_in_early_data() || client.conn.is_established())
                    && client.http3_conn.is_none()
                {
                    debug!(
                        "{} QUIC handshake completed, now trying HTTP/3",
                        client.conn.trace_id()
                    );

                    let h3_conn =
                        match quiche::h3::Connection::with_transport(&mut client.conn, &self.h3_config) {
                            Ok(v) => v,

                            Err(e) => {
                                error!("failed to create HTTP/3 connection: {}", e);
                                continue 'read;
                            }
                        };
                    // TODO: sanity check h3 connection before adding to map
                    client.http3_conn = Some(h3_conn);
                }

                if client.http3_conn.is_some() {
                    // Handle writable streams.
                    for stream_id in client.conn.writable() {
                        handle_writable(client, stream_id);
                    }

                    return Ok(Some(client.conn.source_id().to_vec()));
                }
            }
        }
    }

    pub fn poll(&mut self, scid: &Vec<u8>, uri_regexes: &[Regex]) -> Result<Event, Error> {
        let client = match self.clients.get_mut(&ConnectionId::from_vec(scid.clone())) {
            Some(c) => c,
            None => return Err(Error::ClientNotFound),
        };
        let mut h3_conn = client.http3_conn.as_mut().unwrap();

        // Process HTTP/3 events.
        loop {
            match h3_conn.poll(&mut client.conn) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    trace!("got headers {:?}", list);
                    let (path, matching_regex) = handle_request(
                        stream_id,
                        &list,
                        uri_regexes,
                    );
                    let (status, body) = if let (Some(_), Some(_)) = (&path, &matching_regex) {
                        match client.webtransport_sessions.validate_new_webtransport_session(&mut h3_conn) {
                            Ok(()) => (200, ""),
                            Err(_) => (400, "invalid webtransport request"),
                        }
                    } else {
                        (404, "Not found.")
                    };

                    let headers = if status == 200 {
                        build_connect_response(status, &body)
                    } else {
                        build_response(status, &body)
                    };

                    match h3_conn.send_response(&mut client.conn, stream_id, &headers, false) {
                        Ok(v) => v,

                        Err(quiche::h3::Error::StreamBlocked) => {
                            let response = PartialResponse {
                                headers: Some(headers),
                                body: body.as_bytes().to_vec(),
                                written: 0,
                                is_connect: status == 200,
                            };

                            client.partial_responses.insert(stream_id, response);
                            return Err(Error::StreamBlockedDuringConnect);
                        }

                        Err(e) => {
                            error!("{} stream send failed {:?}", client.conn.trace_id(), e);
                            return Err(Error::StreamWritingFailed(e));
                        }
                    }
                    if let (Some(p), Some(regex_idx)) = (path, matching_regex) {
                        return Ok(Event::NewSession(p, regex_idx));
                    }
                }

                Ok((stream_id, quiche::h3::Event::Data)) => {
                    info!(
                        "{} got data on stream id {}, ignoring",
                        client.conn.trace_id(),
                        stream_id
                    );
                }

                Ok((stream_id, quiche::h3::Event::Finished)) => {
                    info!("Stream {} finished", stream_id);
                    if let Err(e) = client.webtransport_sessions.h3_stream_finished(
                        stream_id,
                        &mut h3_conn,
                        &mut client.conn,
                    ) {
                        error!("could not signal finished stream {} to webtransport session: {:?}", stream_id, e);
                    } else {
                        match client.webtransport_sessions.session_id(stream_id) {
                            Some(session_id) => return Ok(Event::StreamData(session_id, stream_id)),
                            None => warn!("could not find session for finished stream {}", stream_id),
                        }
                        
                    }
                }

                Ok((_stream_id, quiche::h3::Event::Reset { .. })) => todo!(),

                Ok((_flow_id, quiche::h3::Event::Datagram)) => (),

                Ok((_prioritized_element_id, quiche::h3::Event::PriorityUpdate)) => (),

                Ok((_goaway_id, quiche::h3::Event::GoAway)) => {
                    client.conn.close(true, 0, b"Received GO_AWAY")?;
                    return Ok(Event::GoAway);
                },

                Ok((stream_id, quiche::h3::Event::PassthroughData(_))) => {
                    info!("Application pipe data on stream {}!", stream_id);
                    match client.webtransport_sessions.available_h3_stream_data(
                        stream_id,
                        &mut h3_conn,
                        &mut client.conn,
                    ) {
                        Ok(Some(session_id)) => return Ok(Event::StreamData(session_id, stream_id)),
                        Err(e) => error!("could not provide stream {} data to webtransport session: {:?}", stream_id, e),
                        e => error!("available stream data returned {:?}", e),
                    }
                }

                Err(quiche::h3::Error::Done) => {
                    break;
                }

                Err(e) => {
                    error!("{} HTTP/3 error {:?}", client.conn.trace_id(), e);
                    return Err(Error::H3Error(e));
                }
            }
        }
        Ok(Event::Done)
    }

    pub fn open_uni_stream(&mut self, client: &Vec<u8>, session_id: u64) -> Result<u64, Error> {
        let client = match self.clients.get_mut(&ConnectionId::from_vec(client.clone())) {
            Some(c) => c,
            None => return Err(Error::ClientNotFound),
        };
        let h3_conn = client.http3_conn.as_mut().unwrap();
        Ok(client.webtransport_sessions.open_uni_stream(&mut client.conn, h3_conn, session_id)?)
    }

    pub fn read(&mut self, client: &Vec<u8>, session_id: u64, stream_id: u64, data: &mut [u8]) -> Result<usize, Error> {
        let client = match self.clients.get_mut(&ConnectionId::from_vec(client.clone())) {
            Some(c) => c,
            None => return Err(Error::ClientNotFound),
        };
        let h3_conn = client.http3_conn.as_mut().unwrap();
        match client.webtransport_sessions.stream_recv(&mut client.conn, h3_conn, stream_id, session_id, data) {
            Ok(read) => Ok(read),
            Err(webtransport_quiche::Error::Done) => {
                if client.webtransport_sessions.is_stream_finished(stream_id)? {
                    Err(Error::Finished)
                } else {
                    Err(Error::Done)
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    pub fn write(&mut self, client: &Vec<u8>, stream_id: u64, data: &[u8], fin: bool) -> Result<usize, Error> {
        let client = match self.clients.get_mut(&&ConnectionId::from_vec(client.clone())) {
            Some(c) => c,
            None => return Err(Error::ClientNotFound),
        };
        let h3_conn = client.http3_conn.as_mut().unwrap();
        Ok(client.webtransport_sessions.stream_write(&mut client.conn, h3_conn, stream_id, data, fin)?)
    }


    pub fn close_session(&mut self, client: &Vec<u8>) -> Result<(), Error> {
        let client = match self.clients.get_mut(&&ConnectionId::from_vec(client.clone())) {
            Some(c) => c,
            None => return Err(Error::ClientNotFound),
        };
        Ok(client.conn.close(true, 0, b"session closed by the application")?)
    }
}


/// Generate a stateless retry token.
///
/// The token includes the static string `"quiche"` followed by the IP address
/// of the client and by the original destination connection ID generated by the
/// client.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

/// Validates a stateless retry token.
///
/// This checks that the ticket includes the `"quiche"` static string, and that
/// the client IP address matches the address stored in the ticket.
///
/// Note that this function is only an example and doesn't do any cryptographic
/// authenticate of the token. *It should not be used in production system*.
fn validate_token<'a>(src: &net::SocketAddr, token: &'a [u8]) -> Option<quiche::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
}


pub fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();

    vec.join("")
}