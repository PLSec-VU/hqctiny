#![allow(non_snake_case)]

pub mod hqc;
pub mod client;
pub mod server;
pub mod traits;
pub mod encoding;
pub mod error;
pub mod math;
pub use hqc::{hqc1, hqc3, hqc5, Hqc1, Hqc3, Hqc5, HqcScheme};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{Client, PointResult};
    use crate::server::Server;
    use crate::traits::*;
    use rand::Rng;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    struct SharedSessionStore {
        sessions: Arc<Mutex<HashMap<[u8; 32], (u64, [u8; 32])>>>,
    }
    impl SessionStore for SharedSessionStore {
        fn save_session(&self, hash_ek_kem: &[u8; 32], timestamp: u64, k_session: [u8; 32]) {
            self.sessions
                .lock()
                .unwrap()
                .insert(*hash_ek_kem, (timestamp, k_session));
        }
        fn get_session(&self, hash_ek_kem: &[u8; 32]) -> Option<(u64, [u8; 32])> {
            self.sessions.lock().unwrap().get(hash_ek_kem).cloned()
        }
    }

    struct MockEntropy;
    impl EntropyProvider for MockEntropy {
        fn random_bytes(&self, out: &mut [u8]) {
            rand::rng().fill_bytes(out);
        }
    }

    struct MockTime {
        time: u64,
    }
    impl TimeProvider for MockTime {
        fn current_time(&self) -> u64 {
            self.time
        }
    }

    fn test_protocol_flow_generic<SCHEME: HqcScheme>(name: &str) {
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let store = SharedSessionStore {
            sessions: sessions.clone(),
        };
        
        let server = Server::<SCHEME, _, _, _>::new(
            store,
            MockEntropy,
            MockTime { time: 1000 },
            [0x42; 32], // server key
            3600, // timeout
        );

        let client = Client::<SCHEME, _, _, _, _>::new(
            SharedSessionStore {
                sessions: Arc::new(Mutex::new(HashMap::new())),
            },
            MockEntropy,
            MockTime { time: 1000 },
        );

        let mut packets_sent = 0;
        let mut packets_received = 0;

        // 1. Initialize Handshake Request
        let (client, req) = client.initialize();
        
        // Serialize Handshake Request
        let mut buf = vec![0u8; 4096];
        let encoded_req = crate::encoding::encode_packet(&crate::encoding::Packet::HandshakeRequest(req), &mut buf);
        packets_sent += 1;
        println!("[{}] Client -> Server: HandshakeRequest ({} bytes)", name, encoded_req.len());

        // Deserialize Handshake Request on the server side
        let decoded_req_pkt = crate::encoding::decode_packet(encoded_req).unwrap();
        let decoded_req = match decoded_req_pkt {
            crate::encoding::Packet::HandshakeRequest(r) => r,
            _ => panic!("Expected HandshakeRequest"),
        };

        // 2. Server handles Handshake Request
        let res = server.handle_handshake(decoded_req).unwrap();

        // Serialize Handshake Response
        let mut buf = vec![0u8; 4096];
        let encoded_res = crate::encoding::encode_packet(&crate::encoding::Packet::HandshakeResponse(res), &mut buf);
        packets_received += 1;
        println!("[{}] Server -> Client: HandshakeResponse ({} bytes)", name, encoded_res.len());

        // Deserialize Handshake Response on the client side
        let decoded_res_pkt = crate::encoding::decode_packet(encoded_res).unwrap();
        let decoded_res = match decoded_res_pkt {
            crate::encoding::Packet::HandshakeResponse(r) => r,
            _ => panic!("Expected HandshakeResponse"),
        };

        // 3. Client handles Handshake Response
        let (client, point_reqs) = client.handle_handshake_response(decoded_res).unwrap();
        assert_eq!(point_reqs.len(), SCHEME::POINTS_NUM * 2);

        // 4. Point Stream
        let mut client = client;
        let mut client_key = None;
        for req in point_reqs {
            let req_index = req.point_index;
            let req_type = req.point_type;

            // Serialize Point Request
            let mut buf = vec![0u8; 8192];
            let encoded_preq = crate::encoding::encode_packet(&crate::encoding::Packet::PointRequest(req), &mut buf);
            packets_sent += 1;
            println!(
                "[{}] Client -> Server: PointRequest (index={}, type={:?}, {} bytes)",
                name, req_index, req_type, encoded_preq.len()
            );

            // Deserialize Point Request on the server side
            let decoded_preq_pkt = crate::encoding::decode_packet(encoded_preq).unwrap();
            let decoded_preq = match decoded_preq_pkt {
                crate::encoding::Packet::PointRequest(r) => r,
                _ => panic!("Expected PointRequest"),
            };

            // Server processes Point Request
            let point_res = server.handle_point_request(decoded_preq).unwrap();

            // Serialize Point Response
            let mut buf = vec![0u8; 8192];
            let encoded_pres = crate::encoding::encode_packet(&crate::encoding::Packet::PointResponse(point_res), &mut buf);
            packets_received += 1;
            println!(
                "[{}] Server -> Client: PointResponse (index={}, type={:?}, {} bytes)",
                name, req_index, req_type, encoded_pres.len()
            );

            // Deserialize Point Response on the client side
            let decoded_pres_pkt = crate::encoding::decode_packet(encoded_pres).unwrap();
            let decoded_pres = match decoded_pres_pkt {
                crate::encoding::Packet::PointResponse(r) => r,
                _ => panic!("Expected PointResponse"),
            };

            // Client processes Point Response
            match client.handle_point_response(decoded_pres).unwrap() {
                PointResult::Collecting(c) => client = *c,
                PointResult::Completed(_, key) => {
                    client_key = Some(key);
                    break;
                }
            }
        }

        let client_key = client_key.expect("Handshake should complete and return session key");
        assert!(!client_key.iter().all(|&b| b == 0), "Session key should not be all zeros");

        // 5. Verify server has saved the identical session key
        let saved = sessions.lock().unwrap();
        assert_eq!(saved.len(), 1);
        let (_, (_, server_key)) = saved.iter().next().unwrap();

        assert_eq!(client_key.as_slice(), &server_key[..client_key.len()]);

        println!(
            "[{}] Protocol Flow Completed. Packets: {} sent, {} received.",
            name, packets_sent, packets_received
        );
    }

    #[test]
    fn test_protocol_flow_hqc1() {
        test_protocol_flow_generic::<Hqc1>("HQC-1");
    }

    #[test]
    fn test_protocol_flow_hqc3() {
        test_protocol_flow_generic::<Hqc3>("HQC-3");
    }

    #[test]
    fn test_protocol_flow_hqc5() {
        test_protocol_flow_generic::<Hqc5>("HQC-5");
    }
}
