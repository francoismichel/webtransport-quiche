use std::collections::HashMap;

use docopt::Docopt;
use dummy_webtransport_handler::DummyWebTransportServer;
use log::{error, info};
use regex::Regex;

struct BufferedData {
    stream_id: u64,
    data: Vec<u8>,
    sent: usize,
    fin: bool,
}

impl BufferedData {
    fn add_data(&mut self, data: &[u8], fin: bool) {
        self.data.extend_from_slice(&data[..]);
        self.fin = fin;
    }

    fn sent_data(&mut self, n: usize) {
        self.sent += n;
    }
}

pub const USAGE: &str = "Usage:
  dummy_server [options]
  dummy_server -h | --help

Options:
  -h --help        Show this screen.
  --listen <addr>  Listen on the given IP:port [default: 127.0.0.1:4433].
  --cert <file>    TLS certificate path [default: examples/cert.pem].
  --key <file>     TLS certificate key path [default: examples/cert.pem].
";

fn buffer_data_for_client(clients_buffered_data: &mut HashMap<Vec<u8>, HashMap<u64, BufferedData>>, client: Vec<u8>, stream_id: u64, data: &[u8], fin: bool) {
    let data_for_client = match clients_buffered_data.get_mut(&client) {
        Some(hashmap) => hashmap,
        None => {
            clients_buffered_data.insert(client.clone(), HashMap::new());
            clients_buffered_data.get_mut(&client).unwrap()
        }
    };

    let buffered_data = match data_for_client.get_mut(&stream_id) {
        Some(bd) => bd,
        None => {
            data_for_client.insert(stream_id, BufferedData { stream_id: stream_id, data: Vec::new(), sent: 0, fin: fin });
            data_for_client.get_mut(&stream_id).unwrap()
        }
    };

    buffered_data.add_data(data, fin);
}

fn sent_data_for_client(clients_buffered_data: &mut HashMap<Vec<u8>, HashMap<u64, BufferedData>>, client: &Vec<u8>, stream_id: u64, n: usize) {
    let buffered_data = clients_buffered_data.get_mut(client).unwrap().get_mut(&stream_id).unwrap();
    buffered_data.sent_data(n);
    if buffered_data.data.len() == buffered_data.sent {
        clients_buffered_data.get_mut(client).unwrap().remove(&stream_id);
        if clients_buffered_data.get(client).unwrap().len() == 0 {
            clients_buffered_data.remove(client);
        }
    }
}
const MAX_DATAGRAM_SIZE: usize = 1350;
fn main() {
    env_logger::init();

    let mut clients_buffered_data: HashMap<Vec<u8>, HashMap<u64, BufferedData>> = std::collections::HashMap::new();

    let mut buffer = [0; 1_000_000];

    let args = Docopt::new(USAGE)
        .and_then(|dopt| dopt.parse())
        .unwrap_or_else(|e| e.exit());

        
    let mut quic_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    quic_config.load_cert_chain_from_pem_file(args.get_str("--cert")).unwrap();
    quic_config.load_priv_key_from_pem_file(args.get_str("--key")).unwrap();
    quic_config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .unwrap();
    
    quic_config.set_max_idle_timeout(5000);
    quic_config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    quic_config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    quic_config.set_initial_max_data(1_000_000_000);
    quic_config.set_initial_max_stream_data_bidi_local(1_000_000_000);
    quic_config.set_initial_max_stream_data_bidi_remote(1_000_000_000);
    quic_config.set_initial_max_stream_data_uni(1_000_000_000);
    quic_config.set_initial_max_streams_bidi(100);
    quic_config.set_initial_max_streams_uni(100);
    quic_config.set_disable_active_migration(true);
    quic_config.enable_early_data();
    quic_config.grease(false);

    let mut h3_config = quiche::h3::Config::new().unwrap();
    
    let keylog = if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_path)
            .unwrap();

        Some(file)
    } else {
        None
    };

    let mut server = DummyWebTransportServer::with_configs(args.get_str("--listen").parse().unwrap(),
                                                                                    quic_config, h3_config, keylog);
    let regexes = [Regex::new("/test").unwrap()];
    let mut sent_bytes_stream_id = Vec::new();
    let mut total_received = 0;
    let mut total_written = 0;
    loop {
        let cid = server.listen().unwrap();
        loop {
            match server.poll(&cid, &regexes) {
                Ok(dummy_webtransport_handler::Event::NewSession(path, _regex_index)) => info!("New webtransport session on {}", path),
                Ok(dummy_webtransport_handler::Event::StreamData(session_id, stream_id)) => {
                    info!("New webtransport data on session {}, stream {}", session_id, stream_id);
                    loop {
                        let (read, fin) = match server.read(&cid, session_id, stream_id, &mut buffer) {
                            Ok(r) => (r, false),
                            Err(dummy_webtransport_handler::Error::Done) => (0, false),
                            Err(dummy_webtransport_handler::Error::Finished) => (0, true),
                            Err(e) => Err(e).unwrap(),
                        };
                        buffer_data_for_client(&mut clients_buffered_data, cid.clone(), stream_id, &buffer[..read], fin);
                        total_received += read;
                        if read > 0 || fin {
                            info!("received: \"{}\", fin={}", String::from_utf8_lossy(&buffer[..read]), fin);
                        }
                        if fin {
                            info!("total received = {}", total_received);
                        }
                        if read == 0 {
                            break;
                        }
                    }
                }
                Ok(dummy_webtransport_handler::Event::GoAway) => {
                    info!("A client closed its connection");
                    break;
                }
                Ok(dummy_webtransport_handler::Event::Done) => break,
                Err(e) => error!("error encountered: {:?}", e),
            }
        }
        // then, flush the buffered data
        sent_bytes_stream_id.clear();
        match clients_buffered_data.get_mut(&cid) {
            Some(buffered_data_for_client) => {
                for (&stream_id, buffered_data) in buffered_data_for_client.iter_mut() {
                    let data_to_send = &buffered_data.data[buffered_data.sent..];
                    match server.write(&cid, stream_id, data_to_send, buffered_data.fin) {
                        Ok(written) => {
                            sent_bytes_stream_id.push((written, stream_id));
                        }
                        Err(dummy_webtransport_handler::Error::Done) => (),
                        Err(e) => Err(e).unwrap(),
                    }
                }
            }
            None => (),
        };
        for (written, stream_id) in &sent_bytes_stream_id {
            sent_data_for_client(&mut clients_buffered_data, &cid, *stream_id, *written);
        }
    }
}