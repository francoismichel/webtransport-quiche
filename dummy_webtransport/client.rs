use std::collections::HashMap;

use docopt::Docopt;
use dummy_webtransport_handler::DummyWebTransportClient;
use log::{error, info};
use rand::Rng;

struct BufferedData {
    _stream_id: u64,
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
  dummy_client [options] <url>
  dummy_client -h | --help

Arguments:
  url               The url of the webtransport session to create  
  -h --help         Show this screen.
  --size <integer>  the amount of random bytes to transmit. If not set, the client will just send 'hello, world!'          
";

fn buffer_data_for_stream(buffered_data: &mut HashMap<u64, BufferedData>, stream_id: u64, data: &[u8], fin: bool) {

    let buffered_data_for_stream = match buffered_data.get_mut(&stream_id) {
        Some(bd) => bd,
        None => {
            buffered_data.insert(stream_id, BufferedData { _stream_id: stream_id, data: Vec::new(), sent: 0, fin: fin });
            buffered_data.get_mut(&stream_id).unwrap()
        }
    };

    buffered_data_for_stream.add_data(data, fin);
}

fn sent_data_for_stream(buffered_data: &mut HashMap<u64, BufferedData>, stream_id: u64, n: usize) {
    let buffered_data_for_stream = buffered_data.get_mut(&stream_id).unwrap();
    buffered_data_for_stream.sent_data(n);
    if buffered_data_for_stream.data.len() == buffered_data_for_stream.sent {
        buffered_data.remove(&stream_id);
    }
}
const MAX_DATAGRAM_SIZE: usize = 1350;
fn main() {
    env_logger::init();

    let mut buffered_data: HashMap<u64, BufferedData> = std::collections::HashMap::new();

    let mut buffer = [0; 1_000_000];

    let args = Docopt::new(USAGE)
        .and_then(|dopt| dopt.parse())
        .unwrap_or_else(|e| e.exit());

    let payload = match args.get_str("--size").parse() {
        Ok(s) => {
            let mut random_payload = vec![0; s];
            rand::thread_rng().fill(&mut random_payload[..]);
            random_payload
        }
        Err(e) => {
            if args.get_str("--size") == "" {
                b"hello, world!".to_vec()
            } else {
                Err(e).unwrap()
            }
        },
    };

        
    let mut quic_config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    quic_config.verify_peer(false);
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

    let h3_config = quiche::h3::Config::new().unwrap();
    
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

    quic_config.log_keys();

    let url = args.get_str("<url>").parse().unwrap();
    let mut client = DummyWebTransportClient::connect(url, quic_config, h3_config, keylog).unwrap();
    info!("connected !");

    let stream_id = client.open_bidi_stream().unwrap();



    buffer_data_for_stream(&mut buffered_data, stream_id, &payload, true);

    let mut sent_bytes_stream_id = Vec::new();
    let mut response = Vec::new();
    loop {
        sent_bytes_stream_id.clear();
        // first, flush data
        for (&stream_id, buffered_data) in buffered_data.iter_mut() {
            let data_to_send = &buffered_data.data[buffered_data.sent..];
            match client.write(stream_id, data_to_send, buffered_data.fin) {
                Ok(written) => {
                    sent_bytes_stream_id.push((written, stream_id));
                }
                Err(dummy_webtransport_handler::Error::Done) => (),
                Err(e) => Err(e).unwrap(),
            }
        }
            
        for (written, stream_id) in &sent_bytes_stream_id {
            sent_data_for_stream(&mut buffered_data, *stream_id, *written);
        }
        match client.wait_for_events(None) {
            Ok(()) => (),
            Err(dummy_webtransport_handler::Error::ConnectionClosed(Some(peer_error))) => {
                info!("Connection closed, peer error: {:?}", peer_error);
                break;
            }
            Err(dummy_webtransport_handler::Error::ConnectionClosed(None)) => {
                info!("Connection closed, no error.");
                break;
            }
            e => {
                e.unwrap();
            }
        }
        loop {
            match client.poll() {
                Ok(dummy_webtransport_handler::Event::NewSession(path, _regex_index)) => info!("New webtransport session on {}", path),
                Ok(dummy_webtransport_handler::Event::StreamData(session_id, stream_id)) => {
                    info!("New webtransport data on session {}, stream {}", session_id, stream_id);
                    loop {
                       let (read, fin) = match client.read(stream_id, &mut buffer) {
                            Ok(r) => (r, false),
                            Err(dummy_webtransport_handler::Error::Done) => (0, false),
                            Err(dummy_webtransport_handler::Error::Finished) => (0, true),
                            Err(e) => Err(e).unwrap(),
                        };
                        if read > 0 || fin {
                            info!("received {} bytes, fin={}", read, fin);
                            response.extend_from_slice(&buffer[..read]);
                        }
                        if fin {
                            println!("Received {} bytes in total", response.len());
                            if response == payload {
                                println!("All good.")
                            } else {
                                println!("The received paylaod differs with the sent payload.")
                            }
                            info!("Closing.");
                            client.close_session().unwrap();
                        }
                        if read == 0 {
                            break;
                        }
                    }
                }
                Ok(dummy_webtransport_handler::Event::GoAway) => {
                    info!("The peer closed the connection");
                    break;
                }
                Ok(dummy_webtransport_handler::Event::Done) => break,
                Err(e) => error!("error encountered: {:?}", e),
            }
        }
    }
}