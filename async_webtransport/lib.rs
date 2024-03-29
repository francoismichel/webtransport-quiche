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
pub extern crate tokio;
pub extern crate regex;
use tokio::io::{AsyncWrite, AsyncRead};
use webtransport_quiche::quiche as quiche;

use tokio::net::UdpSocket;
use webtransport_quiche::quiche::ConnectionId;

use std::fs::File;
use std::task::Waker;
use std::io;
use std::net::{self, SocketAddr, ToSocketAddrs};

use std::collections::{HashMap, VecDeque, HashSet};
use std::sync::Arc;

use std::sync::Mutex;

use ring::rand::*;
use thiserror::Error as Error;
use bytes::{Buf, Bytes};


use webtransport_quiche::quiche::h3::NameValue;
use regex::Regex;

const MAX_DATAGRAM_SIZE: usize = 1350;

struct H3Client {
    conn: quiche::Connection,

    http3_conn: Option<quiche::h3::Connection>,

    webtransport_sessions: webtransport_quiche::Sessions,

    partial_responses: HashMap<u64, PartialResponse>,

    accepted_uni_streams: HashSet<u64>,
    received_non_accepted_uni_streams: HashMap<u64, VecDeque<u64>>,
    accept_blocked_uni_stream_wakers: HashMap<u64, VecDeque<Waker>>,

    accepted_bidi_streams: HashSet<u64>,
    received_non_accepted_bidi_streams: HashMap<u64, VecDeque<u64>>,
    accept_blocked_bidi_stream_wakers: HashMap<u64, VecDeque<Waker>>,

    read_blocked_streams: std::collections::HashMap<u64, Waker>,
    write_blocked_streams: std::collections::HashMap<u64, Waker>,
    open_blocked_streams: Vec<Waker>,
}
type ClientMap = HashMap<quiche::ConnectionId<'static>, H3Client>;

struct PartialResponse {
    headers: Option<Vec<quiche::h3::Header>>,

    body: Vec<u8>,

    written: usize,

    is_connect: bool,
}

type SocketRef = Arc<tokio::net::UdpSocket>;


pub struct AsyncWebTransportServer {
    buf: [u8; 65535],
    dgrams_buf: [u8; MAX_DATAGRAM_SIZE],
    quic_config: quiche::Config,
    h3_config: quiche::h3::Config,
    clients: ClientMap,
    conn_id_seed: ring::hmac::Key,
    keylog: Option<File>,
}

pub struct AsyncWebTransportClient {
    buf: [u8; 65535],
    dgrams_buf: [u8; MAX_DATAGRAM_SIZE],
    socket: UdpSocket,
    conn: quiche::Connection,
    h3_conn: quiche::h3::Connection,
    webtransport_sessions: webtransport_quiche::Sessions,
    session_id: u64,
}

impl AsyncWebTransportClient {

    pub async fn connect(url: url::Url, mut quic_config: quiche::Config, mut h3_config: quiche::h3::Config, keylog: Option<File>) -> Result<AsyncWebTransportClient, Error> {
        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];

        // Create the UDP listening socket, and register it with the event loop.
        let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    
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
            local_addr,
            hex_dump(&scid)
        );

        let (write, send_info) = conn.send(&mut out)?;

        while let Err(e) = socket.send_to(&out[..write], send_info.to).await {
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

            // Read incoming UDP packets from the socket and feed them to quiche,
            // until there are no more packets to read.
            'read: loop {
            
                trace!("recvfrom()");
                let (len, from) = match socket.recv_from(&mut buf).await {
                    Ok(v) => v,

                    Err(e) => {
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

                if conn.is_closed() {
                    info!("connection closed, {:?}", conn.stats());
                } else if conn.is_established() {
                    break;
                }
            }

            debug!("done reading");

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

                if let Err(e) = socket.send_to(&out[..write], send_info.to).await {
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
            Ok(AsyncWebTransportClient {
                buf: buf,
                dgrams_buf: out,
                socket,
                conn,
                h3_conn,
                webtransport_sessions,
                session_id: webtransport_session_id.unwrap(),
            })
        } else {
            Err(Error::CouldNotConnect)
        }

    }


    pub async fn poll(&mut self) -> Result<Event, Error> {
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

    pub async fn wait_for_events(&mut self) -> Result<(), Error> {
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

            if let Err(e) = self.socket.send_to(&self.dgrams_buf[..write], send_info.to).await {
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


        // Read incoming UDP packets from the socket and feed them to quiche,
        // until there are no more packets to read.
        'read: loop {
            let (len, from) = match self.socket.recv_from(&mut self.buf).await {
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

    pub fn open_uni_stream(&mut self) -> Result<u64, Error> {
        Ok(self.webtransport_sessions.open_uni_stream(&mut self.conn, &mut self.h3_conn, self.session_id)?)
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
    /// HTTP3 uri path, session_id, matching regex index
    NewSession(String, u64, usize),
    /// session_id, stream_id
    StreamData(u64, u64),
    Done,
    GoAway,
}

#[derive(Error, Debug)]
#[error("quiche webtransport error: {:?}", self)]
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

pub struct AcceptUni {
    server: ServerRef,
    connection_id: Vec<u8>,
    session_id: u64,
}

impl std::future::Future for AcceptUni {

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>)
        -> std::task::Poll<Result<u64, Error>>
    {
        let mut server = self.server.lock().unwrap();


        let client = match server.clients.get_mut(&ConnectionId::from_vec(self.connection_id.clone())) {
            Some(c) => c,
            None => return std::task::Poll::Ready(Err(Error::ClientNotFound)),
        };

        match client.received_non_accepted_uni_streams.get_mut(&self.session_id).and_then(|v| v.pop_front()) {
            Some(stream_id) => std::task::Poll::Ready(Ok(stream_id)),
            None => {
                if !client.accept_blocked_uni_stream_wakers.contains_key(&self.session_id) {
                    client.accept_blocked_uni_stream_wakers.insert(self.session_id, VecDeque::new());
                }
                let accept_blocked_uni = client.accept_blocked_uni_stream_wakers.get_mut(&self.session_id).unwrap();
                accept_blocked_uni.push_back(cx.waker().clone());
                std::task::Poll::Pending
            },
        }
    }

    type Output = Result<u64, Error>;
}


pub struct AcceptBidi {
    server: ServerRef,
    connection_id: Vec<u8>,
    session_id: u64,
}

impl std::future::Future for AcceptBidi {

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>)
        -> std::task::Poll<Result<u64, Error>>
    {
        let mut server = self.server.lock().unwrap();


        let client = match server.clients.get_mut(&ConnectionId::from_vec(self.connection_id.clone())) {
            Some(c) => c,
            None => return std::task::Poll::Ready(Err(Error::ClientNotFound)),
        };

        match client.received_non_accepted_bidi_streams.get_mut(&self.session_id).and_then(|v| v.pop_front()) {
            Some(stream_id) => std::task::Poll::Ready(Ok(stream_id)),
            None => {
                if !client.accept_blocked_bidi_stream_wakers.contains_key(&self.session_id) {
                    client.accept_blocked_bidi_stream_wakers.insert(self.session_id, VecDeque::new());
                }
                let accept_blocked_bidi = client.accept_blocked_bidi_stream_wakers.get_mut(&self.session_id).unwrap();
                accept_blocked_bidi.push_back(cx.waker().clone());
                std::task::Poll::Pending
            },
        }
    }

    type Output = Result<u64, Error>;
}

pub struct OpenUni {
    server: ServerRef,
    connection_id: Vec<u8>,
    session_id: u64,
}

impl std::future::Future for OpenUni {

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>)
        -> std::task::Poll<Result<u64, Error>>
    {
        let mut server = self.server.lock().unwrap();
        match server.sync_open_uni_stream(&self.connection_id, self.session_id) {
            Ok(stream_id) => std::task::Poll::Ready(Ok(stream_id)),
            Err(Error::Done) => {
                let waker = cx.waker();
                if let Err(e) = server.insert_open_stream_waker(&self.connection_id, waker.clone()) {
                    std::task::Poll::Ready(Err(e))
                } else {
                    std::task::Poll::Pending
                }
            }
            Err(e) => std::task::Poll::Ready(Err(e)),
        }
    }

    type Output = Result<u64, Error>;
}

pub struct OpenBidi {
    server: ServerRef,
    connection_id: Vec<u8>,
    session_id: u64,
}

impl std::future::Future for OpenBidi {

    fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>)
        -> std::task::Poll<Result<u64, Error>>
    {
        let mut server = self.server.lock().unwrap();
        match server.sync_open_bidi_stream(&self.connection_id, self.session_id) {
            Ok(stream_id) => std::task::Poll::Ready(Ok(stream_id)),
            Err(Error::Done) => {
                let waker = cx.waker();
                if let Err(e) = server.insert_open_stream_waker(&self.connection_id, waker.clone()) {
                    std::task::Poll::Ready(Err(e))
                } else {
                    std::task::Poll::Pending
                }
            }
            Err(e) => std::task::Poll::Ready(Err(e)),
        }
    }

    type Output = Result<u64, Error>;
}

impl AsyncWebTransportServer {

    pub fn with_configs(addr: SocketAddr, quic_config: quiche::Config, h3_config: quiche::h3::Config, keylog: Option<File>) -> Result<(AsyncWebTransportServer, tokio::net::UdpSocket), Error> {
    
        // Create the UDP listening socket, and register it with the event loop.
        let socket = std::net::UdpSocket::bind(addr)?;
        socket.set_nonblocking(true)?;
        let socket = tokio::net::UdpSocket::from_std(socket)?;
    
        let rng = SystemRandom::new();
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

        

        Ok((AsyncWebTransportServer {
            buf: [0; 65535],
            dgrams_buf: [0; MAX_DATAGRAM_SIZE],
            quic_config: quic_config,
            h3_config: h3_config,
            clients:ClientMap::new(),
            conn_id_seed,
            keylog,
        }, socket))
    }

    pub async fn listen(&mut self, socket: SocketRef) -> Result<Option<Vec<u8>>, Error> {
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

                    if let Err(e) = socket.send_to(&self.dgrams_buf[..write], send_info.to).await {
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


            let local_addr = socket.local_addr().unwrap();
            let sleep = tokio::time::sleep(tokio::time::Duration::from_millis(1));
            tokio::pin!(sleep);
            // Read incoming UDP packets from the socket and feed them to quiche,
            // until there are no more packets to read.
            'read: loop {
                tokio::select! {
                    res = socket.recv_from(&mut self.buf) => {
                        let (len, from) = match res {
                            Ok(v) => {
                                v
                            }
                            Err(e) => {
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

                                if let Err(e) = socket.send_to(out, from).await {
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

                                if let Err(e) = socket.send_to(out, from).await {
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
                                accepted_uni_streams: HashSet::new(),
                                received_non_accepted_uni_streams: HashMap::new(),
                                accept_blocked_uni_stream_wakers: HashMap::new(),
                                accepted_bidi_streams: HashSet::new(),
                                received_non_accepted_bidi_streams: HashMap::new(),
                                accept_blocked_bidi_stream_wakers: HashMap::new(),
                                read_blocked_streams: std::collections::HashMap::new(),
                                write_blocked_streams: std::collections::HashMap::new(),
                                open_blocked_streams: Vec::new(),
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
                            to: socket.local_addr().unwrap(),
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

                        self.wake_write_streams(&hdr.dcid.to_vec())?;
                        self.wake_open_streams(&hdr.dcid.to_vec())?;
                        // TODO: avoid re-borrowing the client to avoid double borrow due to the line above
                        let client = self.clients.get_mut(&hdr.dcid).unwrap();
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
                    },
                    () = &mut sleep => {
                        break 'read;
                    },
                }
            }
        }
    }

    pub fn create_client_connection(&mut self, cid: &Vec<u8>) -> Result<quiche::h3::Connection, Error> {

        let client = match self.clients.get_mut(&ConnectionId::from_vec(cid.clone())) {
            Some(c) => c,
            None => return Err(Error::ClientNotFound),
        };
        quiche::h3::Connection::with_transport(&mut client.conn, &self.h3_config).map_err(|_| Error::CouldNotConnect)
    }

    pub async fn listen_ref(server: ServerRef, socket: SocketRef, buf: &mut Vec<u8>) -> Result<Option<Vec<u8>>, Error> {
        loop {

            // Generate outgoing QUIC packets for all active connections and send
            // them on the UDP socket, until quiche reports that there are no more
            // packets to be sent.
            {
                let keys = {
                    let server = server.lock().unwrap();
                    server.clients.keys().map(|x| x.to_vec()).collect::<Vec<_>>()
                };
                for cid in keys {
                    loop {
                        let (write, target_addr) = {
                            let mut server = server.lock().unwrap();
                            let client = server.clients.get_mut(&cid.clone().into()).unwrap();
                            let (write, send_info) = match client.conn.send(buf) {
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
                            (write, send_info.to)
                        };
                        if let Err(e) = socket.send_to(&buf[..write], target_addr).await {
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                debug!("send() would block");
                                break;
                            }
    
                            panic!("send() failed: {:?}", e);
                        }
    
                        debug!("written {} bytes", write);
                    }
                }
            }

            // Garbage collect closed connections.
            server.lock().unwrap().clients.retain(|_, ref mut c| {
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


            let local_addr = socket.local_addr().unwrap();
            // Read incoming UDP packets from the socket and feed them to quiche,
            // until there are no more packets to read.
            'read: loop {
                trace!("check if data available on the socket");
                match tokio::time::timeout(tokio::time::Duration::from_millis(1), socket.recv_from(buf)).await {
                    Ok(res) => {
                        debug!("received data on the socket");
                        let (len, from) = match res {
                            Ok(v) => {
                                v
                            }
                            Err(e) => {
                                panic!("recv() failed: {:?}", e);
                            }
                        };
    
                        debug!("got {} bytes", len);
    
                        let pkt_buf = &mut buf[..len];
    
                        // Parse the QUIC packet's header.
                        let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
                            Ok(v) => v,
    
                            Err(e) => {
                                error!("Parsing packet header failed: {:?}", e);
                                continue 'read;
                            }
                        };
    
                        trace!("got packet {:?}", hdr);
    
                        let (conn_id, client_known) = {
                            let server = server.lock().unwrap();
                            let conn_id = ring::hmac::sign(&server.conn_id_seed, &hdr.dcid);
                            let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
                            let conn_id = conn_id.to_vec().into();
                            let client_known = !server.clients.contains_key(&hdr.dcid) && !server.clients.contains_key(&conn_id);
                            (conn_id, client_known)
                        };
    
                        // Lookup a connection based on the packet's connection ID. If there
                        // is no connection matching, create a new one.
                        if client_known {
                            if hdr.ty != quiche::Type::Initial {
                                error!("Packet is not Initial");
                                continue 'read;
                            }
    
                            if !quiche::version_is_supported(hdr.version) {
                                warn!("Doing version negotiation");
    
                                let len = if let Ok(l) = quiche::negotiate_version(&hdr.scid, &hdr.dcid, buf) {
                                    l
                                } else {
                                    continue 'read;
                                };
    
                                let out = &buf[..len];
    
                                if let Err(e) = socket.send_to(out, from).await {
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
                                    buf,
                                )
                                .unwrap();
    
                                let out = &buf[..len];
    
                                if let Err(e) = socket.send_to(out, from).await {
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
                                quiche::accept(&scid, odcid.as_ref(), local_addr, from, &mut server.lock().unwrap().quic_config).unwrap();
    
                            if let Some(keylog) = &mut server.lock().unwrap().keylog {
                                if let Ok(keylog) = keylog.try_clone() {
                                    conn.set_keylog(Box::new(keylog));
                                }
                            }
    
                            let client = H3Client {
                                conn,
                                http3_conn: None,
                                partial_responses: HashMap::new(),
                                webtransport_sessions: webtransport_quiche::Sessions::new(true),
                                accepted_uni_streams: HashSet::new(),
                                received_non_accepted_uni_streams: HashMap::new(),
                                accept_blocked_uni_stream_wakers: HashMap::new(),
                                accepted_bidi_streams: HashSet::new(),
                                received_non_accepted_bidi_streams: HashMap::new(),
                                accept_blocked_bidi_stream_wakers: HashMap::new(),
                                read_blocked_streams: std::collections::HashMap::new(),
                                write_blocked_streams: std::collections::HashMap::new(),
                                open_blocked_streams: Vec::new(),
                            };
                            let mut server = server.lock().unwrap();
                            client
                                .webtransport_sessions
                                .configure_h3_for_webtransport(&mut server.h3_config)?;
    
                                server.clients.insert(scid.clone(), client);
    
                        }
                        let mut server = server.lock().unwrap();
                        let client = match server.clients.get_mut(&hdr.dcid) {
                            Some(v) => v,
    
                            None => server.clients.get_mut(&conn_id).unwrap(),
                        };
    
                        let recv_info = quiche::RecvInfo {
                            to: local_addr,
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
    
                        server.wake_write_streams(&hdr.dcid.to_vec())?;
                        server.wake_open_streams(&hdr.dcid.to_vec())?;
                        // TODO: avoid re-borrowing the client to avoid double borrow due to the line above
                        let client = server.clients.get_mut(&hdr.dcid).unwrap();
                        // Create a new HTTP/3 connection as soon as the QUIC connection
                        // is established.
                        let h3_conn = if (client.conn.is_in_early_data() || client.conn.is_established())
                            && client.http3_conn.is_none()
                        {
                            debug!(
                                "{} QUIC handshake completed, now trying HTTP/3",
                                client.conn.trace_id()
                            );
                            
                            let h3_conn =
                                match server.create_client_connection(&hdr.dcid.to_vec()) {
                                    Ok(v) => v,
    
                                    Err(e) => {
                                        error!("failed to create HTTP/3 connection: {}", e);
                                        continue 'read;
                                    }
                                };
                            // TODO: sanity check h3 connection before adding to map
                            Some(h3_conn)
                        } else {
                            None
                        };
                        
                        let client = server.clients.get_mut(&hdr.dcid).unwrap();
                        if client.http3_conn.is_none() {
                            client.http3_conn = h3_conn;
                        }
    
                        if client.http3_conn.is_some() {
                            // Handle writable streams.
                            for stream_id in client.conn.writable() {
                                handle_writable(client, stream_id);
                            }
    
                            return Ok(Some(client.conn.source_id().to_vec()));
                        }
                    },
                    Err(_) => {
                        trace!("timeout on socket read");
                        break 'read;
                    },
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
                        return Ok(Event::NewSession(p, stream_id, regex_idx));
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
                        Ok(Some(session_id)) => {
                            let bidi = stream_id & 0x02 == 0;
                            if bidi {
                                if !client.received_non_accepted_bidi_streams.contains_key(&session_id) {
                                    client.received_non_accepted_bidi_streams.insert(session_id, VecDeque::new());
                                }
                                let received_non_accepted_bidi = client.received_non_accepted_bidi_streams.get_mut(&session_id).unwrap();
                                if !client.accepted_bidi_streams.contains(&stream_id) && !received_non_accepted_bidi.contains(&stream_id) {
                                    received_non_accepted_bidi.push_back(stream_id);
                                    if let Some(waker) = client.accept_blocked_bidi_stream_wakers.get_mut(&session_id).and_then(|v| v.pop_front()) {
                                        waker.wake();
                                    }
                                }
                            } else {
                                if !client.received_non_accepted_uni_streams.contains_key(&session_id) {
                                    client.received_non_accepted_uni_streams.insert(session_id, VecDeque::new());
                                }
                                let received_non_accepted_uni = client.received_non_accepted_uni_streams.get_mut(&session_id).unwrap();
                                if !client.accepted_uni_streams.contains(&stream_id) && !received_non_accepted_uni.contains(&stream_id) {
                                    received_non_accepted_uni.push_back(stream_id);
                                    if let Some(waker) = client.accept_blocked_uni_stream_wakers.get_mut(&session_id).and_then(|v| v.pop_front()) {
                                        waker.wake();
                                    }
                                }
                            }
                            self.wake_read_stream(scid, stream_id)?;
                            // handle async behaviours
                            return Ok(Event::StreamData(session_id, stream_id));
                        },
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

    pub fn insert_read_waker(&mut self, client: &Vec<u8>, stream_id: u64, waker: Waker) -> Result<(), Error> {
        let client = match self.clients.get_mut(&ConnectionId::from_vec(client.clone())) {
            Some(c) => c,
            None => return Err(Error::ClientNotFound),
        };
        
        client.read_blocked_streams.insert(stream_id, waker);
        Ok(())
    }

    pub fn insert_write_waker(&mut self, client: &Vec<u8>, stream_id: u64, waker: Waker) -> Result<(), Error> {
        let client = match self.clients.get_mut(&ConnectionId::from_vec(client.clone())) {
            Some(c) => c,
            None => return Err(Error::ClientNotFound),
        };
        
        client.write_blocked_streams.insert(stream_id, waker);
        Ok(())
    }

    pub fn insert_open_stream_waker(&mut self, client: &Vec<u8>, waker: Waker) -> Result<(), Error> {
        let client = match self.clients.get_mut(&ConnectionId::from_vec(client.clone())) {
            Some(c) => c,
            None => return Err(Error::ClientNotFound),
        };
        
        client.open_blocked_streams.push(waker);
        Ok(())
    }

    pub fn wake_read_stream(&mut self, client: &Vec<u8>, stream_id: u64) -> Result<(), Error> {
        let client = match self.clients.get_mut(&ConnectionId::from_vec(client.clone())) {
            Some(c) => c,
            None => return Err(Error::ClientNotFound),
        };
        if let Some(waker) = client.read_blocked_streams.remove(&stream_id) {
            trace!("wake stream {} for reading", stream_id);
            waker.wake();
        }
        Ok(())
    }

    pub fn wake_write_stream(&mut self, client: &Vec<u8>, stream_id: u64) -> Result<(), Error> {
        let client = match self.clients.get_mut(&ConnectionId::from_vec(client.clone())) {
            Some(c) => c,
            None => return Err(Error::ClientNotFound),
        };
        
        if let Some(waker) = client.write_blocked_streams.remove(&stream_id) {
            waker.wake();
        }
        Ok(())
    }

    pub fn wake_open_streams(&mut self, client: &Vec<u8>) -> Result<(), Error> {
        let client = match self.clients.get_mut(&ConnectionId::from_vec(client.clone())) {
            Some(c) => c,
            None => return Err(Error::ClientNotFound),
        };
        
        for waker in client.open_blocked_streams.drain(..) {
            waker.wake();
        }
        Ok(())
    }


    pub fn wake_write_streams(&mut self, client: &Vec<u8>) -> Result<(), Error> {
        let client = match self.clients.get_mut(&ConnectionId::from_vec(client.clone())) {
            Some(c) => c,
            None => return Err(Error::ClientNotFound),
        };
        
        for (_stream_id, waker) in client.write_blocked_streams.drain() {
            waker.wake();
        }
        Ok(())
    }

    pub fn sync_open_uni_stream(&mut self, client: &Vec<u8>, session_id: u64) -> Result<u64, Error> {
        let client = match self.clients.get_mut(&ConnectionId::from_vec(client.clone())) {
            Some(c) => c,
            None => return Err(Error::ClientNotFound),
        };
        let h3_conn = client.http3_conn.as_mut().unwrap();
        Ok(client.webtransport_sessions.open_uni_stream(&mut client.conn, h3_conn, session_id)?)
    }

    pub fn sync_open_bidi_stream(&mut self, client: &Vec<u8>, session_id: u64) -> Result<u64, Error> {
        let client = match self.clients.get_mut(&ConnectionId::from_vec(client.clone())) {
            Some(c) => c,
            None => return Err(Error::ClientNotFound),
        };
        let h3_conn = client.http3_conn.as_mut().unwrap();
        Ok(client.webtransport_sessions.open_bidi_stream(&mut client.conn, h3_conn, session_id)?)
    }

    pub fn open_uni_stream_ref(server: ServerRef, client: &Vec<u8>, session_id: u64) -> OpenUni {
        OpenUni {
            server: server.clone(),
            connection_id: client.clone(),
            session_id: session_id,
        }
    }

    pub fn open_bidi_stream_ref(server: ServerRef, client: &Vec<u8>, session_id: u64) -> OpenBidi {
        OpenBidi {
            server: server.clone(),
            connection_id: client.clone(),
            session_id: session_id,
        }
    }

    pub fn accept_uni_stream_ref(server: ServerRef, client: &Vec<u8>, session_id: u64) -> AcceptUni {
        AcceptUni {
            server: server.clone(),
            connection_id: client.clone(),
            session_id: session_id,
        }
    }

    pub fn accept_bidi_stream_ref(server: ServerRef, client: &Vec<u8>, session_id: u64) -> AcceptBidi {
        AcceptBidi {
            server: server.clone(),
            connection_id: client.clone(),
            session_id: session_id,
        }
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

    pub fn is_stream_writable(&mut self, client: &Vec<u8>, stream_id: u64) -> Result<bool, Error> {
        let client = match self.clients.get_mut(&&ConnectionId::from_vec(client.clone())) {
            Some(c) => c,
            None => return Err(Error::ClientNotFound),
        };
        Ok(client.conn.stream_writable(stream_id, 1)?)
    }

    pub fn close_session(&mut self, client: &Vec<u8>, reason: &[u8]) -> Result<(), Error> {
        let client = match self.clients.get_mut(&&ConnectionId::from_vec(client.clone())) {
            Some(c) => c,
            None => return Err(Error::ClientNotFound),
        };
        Ok(client.conn.close(true, 0, reason)?)
    }
}

#[derive(Clone)]
pub struct WebTransportSession {
    server: ServerRef,
    connection_id: Vec<u8>,
    session_id: u64,
}

impl WebTransportSession {

    pub fn new(server: ServerRef, connection_id: Vec<u8>, session_id: u64) -> WebTransportSession {
        WebTransportSession { server, connection_id, session_id }
    }

    fn _poll_open_bidi(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<ServerBidiStream, anyhow::Error>> {
        let fut = AsyncWebTransportServer::open_bidi_stream_ref(self.server.clone(), &self.connection_id, self.session_id);
        let fut = std::pin::pin!(fut);
        std::future::Future::poll(fut, cx)
            .map_ok(|stream_id| ServerBidiStream::new(self.server.clone(), self.connection_id.clone(), self.session_id, stream_id))
            .map_err(|e| e.into())
    }

    fn _poll_open_send(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<ServerSendStream, anyhow::Error>> {
        let fut = AsyncWebTransportServer::open_uni_stream_ref(self.server.clone(), &self.connection_id, self.session_id);
        let fut = std::pin::pin!(fut);
        std::future::Future::poll(fut, cx)
            .map_ok(|stream_id| ServerSendStream::new(self.server.clone(), self.connection_id.clone(), self.session_id, stream_id))
            .map_err(|e| e.into())
    }

    fn close_session(&mut self, _code: u64, reason: &[u8]) -> Result<(), Error> {
        self.server.lock().unwrap().close_session(&self.connection_id, reason)
    }
}

impl std::fmt::Debug for WebTransportSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebTransportSession").field("connection_id", &self.connection_id).field("session_id", &self.session_id).finish()
    }
}

impl moq_generic_transport::Connection for WebTransportSession {
    type BidiStream = ServerBidiStream;

    type SendStream = ServerSendStream;

    type RecvStream = ServerRecvStream;

    fn poll_accept_recv(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Option<Self::RecvStream>, anyhow::Error>> {
        let fut = AsyncWebTransportServer::accept_uni_stream_ref(self.server.clone(), &self.connection_id, self.session_id);
        let fut = std::pin::pin!(fut);
        std::future::Future::poll(fut, cx)
            .map_ok(|stream_id| Some(ServerRecvStream::new(self.server.clone(), self.connection_id.clone(), self.session_id, stream_id)))
            .map_err(|e| e.into())
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Option<Self::BidiStream>, anyhow::Error>> {
        let fut = AsyncWebTransportServer::accept_bidi_stream_ref(self.server.clone(), &self.connection_id, self.session_id);
        let fut = std::pin::pin!(fut);
        std::future::Future::poll(fut, cx)
            .map_ok(|stream_id| Some(ServerBidiStream::new(self.server.clone(), self.connection_id.clone(), self.session_id, stream_id)))
            .map_err(|e| e.into())
    }

    fn poll_open_bidi(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Self::BidiStream, anyhow::Error>> {
        self._poll_open_bidi(cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Self::SendStream, anyhow::Error>> {
        self._poll_open_send(cx)
    }

    fn close(&mut self, code: u64, reason: &[u8]) {
        self.close_session(code, reason);
    }
}

impl moq_generic_transport::OpenStreams for WebTransportSession {
    type BidiStream = ServerBidiStream;

    type SendStream = ServerSendStream;

    type RecvStream = ServerRecvStream;

    fn poll_open_bidi(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Self::BidiStream, anyhow::Error>> {
        self._poll_open_bidi(cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Self::SendStream, anyhow::Error>> {
        self._poll_open_send(cx)
    }

    fn close(&mut self, code: u64, reason: &[u8]) {
        self.close_session(code, reason);
    }
}

pub type ServerRef = Arc<Mutex<AsyncWebTransportServer>>;

pub struct ServerBidiStream {
    send: ServerSendStream,
    recv: ServerRecvStream,
}

impl ServerBidiStream {

    pub fn new(server: ServerRef, connection_id: Vec<u8>, session_id: u64, stream_id: u64) -> ServerBidiStream {
        let send = ServerSendStream::new(server.clone(), connection_id.clone(), session_id, stream_id);
        let recv = ServerRecvStream::new(server.clone(), connection_id.clone(), session_id, stream_id);
        ServerBidiStream {
            send,
            recv,
        }
    }

    pub fn split(self) -> (ServerSendStream, ServerRecvStream) {
        (self.send, self.recv)
    }
}

impl moq_generic_transport::RecvStream for ServerBidiStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Option<Self::Buf>, anyhow::Error>> {
        self.recv.poll_data(cx)
    }

    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code)
    }

    fn recv_id(&self) -> u64 {
        self.recv.recv_id()
    }
}

impl moq_generic_transport::SendStream for ServerBidiStream {
    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), anyhow::Error>> {
        self.send.poll_ready(cx)
    }

    fn poll_finish(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), anyhow::Error>> {
        self.send.poll_finish(cx)
    }

    fn reset(&mut self, reset_code: u64) {
        self.send.reset(reset_code)
    }

    fn send_id(&self) -> u64 {
        self.send.send_id()
    }
}

impl moq_generic_transport::BidiStream for ServerBidiStream {
    type SendStream = ServerSendStream;

    type RecvStream = ServerRecvStream;

    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}


impl AsyncRead for ServerBidiStream {

    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let mut_self: &mut ServerBidiStream = self.get_mut();
        let boxed: std::pin::Pin<&mut ServerRecvStream> = std::pin::Pin::new(&mut mut_self.recv); 
        boxed.poll_read(_cx, buf)
    }
}

impl AsyncWrite for ServerBidiStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        let mut_self: &mut ServerBidiStream = self.get_mut();
        let boxed: std::pin::Pin<&mut ServerSendStream> = std::pin::Pin::new(&mut mut_self.send);
        boxed.poll_write(cx, buf)
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), io::Error>> {
        let mut_self: &mut ServerBidiStream = self.get_mut();
        let boxed: std::pin::Pin<&mut ServerSendStream> = std::pin::Pin::new(&mut mut_self.send);
        boxed.poll_flush(cx)
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), io::Error>> {
        let mut_self: &mut ServerBidiStream = self.get_mut();
        let boxed: std::pin::Pin<&mut ServerSendStream> = std::pin::Pin::new(&mut mut_self.send);
        boxed.poll_shutdown(cx)
    }
}

pub struct ServerRecvStream {
    server: ServerRef,
    stream_id: u64,
    session_id: u64,
    buf: Vec<u8>,
    connection_id: Vec<u8>,
}

impl ServerRecvStream {
    pub fn new(server: ServerRef, connection_id: Vec<u8>, session_id: u64, stream_id: u64) -> ServerRecvStream {
        ServerRecvStream {
            server,
            stream_id,
            session_id,
            connection_id,
            buf: vec![0; 1500],
        }
    }
}


impl AsyncRead for ServerRecvStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        
        let stream = self.get_mut();
        let mut server = stream.server.lock().unwrap();
        match server.read(&stream.connection_id, stream.session_id, stream.stream_id, &mut stream.buf[..buf.remaining()]) {
            Ok(read) => {
                buf.put_slice(&stream.buf[..read]);
                std::task::Poll::Ready(Ok(()))
            },
            Err(Error::Finished) => {
                std::task::Poll::Ready(Ok(()))
            },
            Err(Error::Done) => {
                if let Err(e) = server.insert_read_waker(&stream.connection_id, stream.stream_id, cx.waker().clone()) {
                    std::task::Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e)))
                } else {
                    std::task::Poll::Pending
                }
            }
            Err(e) => std::task::Poll::Ready(Err(std::io::Error::new(io::ErrorKind::Other, e)))
        }
    }
    
}

impl moq_generic_transport::RecvStream for ServerRecvStream {
    type Buf = Bytes;

    fn poll_data(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Option<Self::Buf>, anyhow::Error>> {
        let mut server = self.server.lock().unwrap();
        let mut buf = [0; 10000];
        match server.read(&self.connection_id, self.session_id, self.stream_id, &mut buf[..]) {
            Ok(read) => {
                std::task::Poll::Ready(Ok(Some(bytes::Bytes::copy_from_slice(&buf[..read]))))
            },
            Err(Error::Finished) => {
                std::task::Poll::Ready(Ok(None))
            },
            Err(Error::Done) => {
                if let Err(e) = server.insert_read_waker(&self.connection_id, self.stream_id, cx.waker().clone()) {
                    std::task::Poll::Ready(Err(e.into()))
                } else {
                    std::task::Poll::Pending
                }
            }
            Err(e) => std::task::Poll::Ready(Err(e.into()))
        }
    }

    fn stop_sending(&mut self, _error_code: u64) {
        todo!()
    }

    fn recv_id(&self) -> u64 {
        self.stream_id
    }
}

pub struct ServerSendStream {
    server: ServerRef,
    stream_id: u64,
    _session_id: u64,
    connection_id: Vec<u8>,
}

impl ServerSendStream {
    fn _poll_write(
        &mut self,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
        fin: bool,
    ) -> std::task::Poll<Result<usize, io::Error>> {
        let mut server = self.server.lock().unwrap();
        match server.write(&self.connection_id, self.stream_id, buf, fin) {
            Ok(written) => {
                std::task::Poll::Ready(Ok(written))
            },
            Err(Error::Done) => {
                if let Err(e) = server.insert_write_waker(&self.connection_id, self.stream_id, cx.waker().clone()) {
                    std::task::Poll::Ready(Err(std::io::Error::new(io::ErrorKind::Other, e)))
                } else {
                    std::task::Poll::Pending
                }
            },
            Err(e) => std::task::Poll::Ready(Err(std::io::Error::new(io::ErrorKind::Other, e))),
        }
    }

    pub fn new(server: ServerRef, connection_id: Vec<u8>, _session_id: u64, stream_id: u64) -> ServerSendStream {
        ServerSendStream {
            server,
            _session_id,
            stream_id,
            connection_id,
        }
    }
}

impl Drop for ServerSendStream {

    /// close the stream implicitly on drop
    fn drop(&mut self) {
        let mut server = self.server.lock().unwrap();
        server.write(&self.connection_id, self.stream_id, &[], true);
    }
}

impl moq_generic_transport::SendStream for ServerSendStream {
    fn poll_ready(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), anyhow::Error>> {
        let mut server = self.server.lock().unwrap();
        match server.is_stream_writable(&self.connection_id, self.stream_id) {
            Ok(true) => std::task::Poll::Ready(Ok(())),
            Ok(false) => {
                if let Err(e) = server.insert_write_waker(&self.connection_id, self.stream_id, cx.waker().clone()) {
                    std::task::Poll::Ready(Err(e.into()))
                } else {
                    std::task::Poll::Pending
                }
            }
            Err(e) => {
                std::task::Poll::Ready(Err(e.into()))
            }
        }
    }

    fn poll_finish(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), anyhow::Error>> {
        
        let mut server = self.server.lock().unwrap();
        match server.write(&self.connection_id, self.stream_id, &[], true) {
            Ok(_) => {
                std::task::Poll::Ready(Ok(()))
            },
            Err(Error::Done) => {
                if let Err(e) = server.insert_write_waker(&self.connection_id, self.stream_id, cx.waker().clone()) {
                    std::task::Poll::Ready(Err(e.into()))
                } else {
                    std::task::Poll::Pending
                }
            },
            Err(e) => std::task::Poll::Ready(Err(e.into())),
        }
    }

    fn reset(&mut self, _reset_code: u64) {
        todo!()
    }

    fn send_id(&self) -> u64 {
        self.stream_id
    }
}


/// Allows sending unframed pure bytes to a stream. Similar to [`AsyncWrite`](https://docs.rs/tokio/latest/tokio/io/trait.AsyncWrite.html)
impl moq_generic_transport::SendStreamUnframed for ServerSendStream {
    /// Attempts write data into the stream.
    ///
    /// Returns the number of bytes written.
    ///
    /// `buf` is advanced by the number of bytes written.
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut std::task::Context<'_>,
        buf: &mut D,
    ) -> std::task::Poll<Result<usize, anyhow::Error>> {
        let chunk = buf.chunk();
        match std::task::ready!(self._poll_write(cx, chunk, false)) {
            Ok(written) => {
                buf.advance(written);
                std::task::Poll::Ready(Ok(written))
            }
            Err(e) => std::task::Poll::Ready(Err(e.into()))
        }
    }
}

impl AsyncWrite for ServerSendStream {

    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        let stream = self.get_mut();
        stream._poll_write(cx, buf, false)
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), io::Error>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Result<(), io::Error>> {
        let stream = self.get_mut();
        stream._poll_write(cx, &[], true).map_ok(|_| ())
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