#![allow(non_snake_case)]

pub mod client;
pub mod encoding;
pub mod error;
pub mod hqc;
pub mod math;
pub mod server;
pub mod traits;
pub use hqc::{Hqc1, Hqc3, Hqc5, HqcScheme, hqc1, hqc3, hqc5};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{Client, PointResult};
    use crate::error::Error;
    use crate::server::Server;
    use crate::traits::*;
    use rand::Rng;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, RwLock};

    struct SharedSessionStore {
        sessions: Arc<Mutex<HashMap<[u8; 32], [u8; 32]>>>,
    }
    impl SessionStore for SharedSessionStore {
        fn save_session(&self, hash_ek_kem: &[u8; 32], k_session: [u8; 32]) {
            self.sessions
                .lock()
                .unwrap()
                .insert(*hash_ek_kem, k_session);
        }
        fn get_session(&self, hash_ek_kem: &[u8; 32]) -> Option<[u8; 32]> {
            self.sessions.lock().unwrap().get(hash_ek_kem).cloned()
        }
    }

    struct MockEntropy;
    impl EntropyProvider for MockEntropy {
        fn random_bytes(&self, out: &mut [u8]) {
            rand::rng().fill_bytes(out);
        }
    }

    struct InMemoryKeyProvider {
        current_idx: RwLock<u8>,
        keys: [RwLock<Option<[u8; 32]>>; 2],
    }

    impl InMemoryKeyProvider {
        fn new(entropy: &impl EntropyProvider) -> Self {
            let mut k0 = [0u8; 32];
            let mut k1 = [0u8; 32];
            entropy.random_bytes(&mut k0);
            entropy.random_bytes(&mut k1);
            Self {
                current_idx: RwLock::new(0),
                keys: [RwLock::new(Some(k0)), RwLock::new(Some(k1))],
            }
        }
    }

    impl CookieKeyProvider for InMemoryKeyProvider {
        fn current_key_index(&self) -> u8 {
            *self.current_idx.read().unwrap()
        }

        fn get_key(&self, index: u8) -> Option<[u8; 32]> {
            if index > 1 {
                return None;
            }
            *self.keys[index as usize].read().unwrap()
        }
    }

    fn test_protocol_flow_generic<SCHEME: HqcScheme>(name: &str) {
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let store = SharedSessionStore {
            sessions: sessions.clone(),
        };

        let entropy = MockEntropy;
        let key_provider = InMemoryKeyProvider::new(&entropy);

        let server = Server::<SCHEME, _, _, _>::new(store, MockEntropy, key_provider);

        let client = Client::<SCHEME, _, _, _>::new(
            SharedSessionStore {
                sessions: Arc::new(Mutex::new(HashMap::new())),
            },
            MockEntropy,
        );

        let mut packets_sent = 0;
        let mut packets_received = 0;

        // 1. Initialize Handshake Request
        let (client, req) = client.initialize();

        // Serialize Handshake Request
        let mut buf = vec![0u8; 4096];
        let encoded_req = crate::encoding::encode_packet(
            &crate::encoding::Packet::HandshakeRequest(req),
            &mut buf,
        );
        packets_sent += 1;
        println!(
            "[{}] Client -> Server: HandshakeRequest ({} bytes)",
            name,
            encoded_req.len()
        );

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
        let encoded_res = crate::encoding::encode_packet(
            &crate::encoding::Packet::HandshakeResponse(res),
            &mut buf,
        );
        packets_received += 1;
        println!(
            "[{}] Server -> Client: HandshakeResponse ({} bytes)",
            name,
            encoded_res.len()
        );

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
            let encoded_preq = crate::encoding::encode_packet(
                &crate::encoding::Packet::PointRequest(req),
                &mut buf,
            );
            packets_sent += 1;
            println!(
                "[{}] Client -> Server: PointRequest (index={}, type={:?}, {} bytes)",
                name,
                req_index,
                req_type,
                encoded_preq.len()
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
            let encoded_pres = crate::encoding::encode_packet(
                &crate::encoding::Packet::PointResponse(point_res),
                &mut buf,
            );
            packets_received += 1;
            println!(
                "[{}] Server -> Client: PointResponse (index={}, type={:?}, {} bytes)",
                name,
                req_index,
                req_type,
                encoded_pres.len()
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
        assert!(
            !client_key.iter().all(|&b| b == 0),
            "Session key should not be all zeros"
        );

        // 5. Verify server has saved the identical session key
        let saved = sessions.lock().unwrap();
        assert_eq!(saved.len(), 1);
        let (_, server_key) = saved.iter().next().unwrap();

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

    #[test]
    fn test_cookie_key_rotation() {
        let sessions = Arc::new(Mutex::new(HashMap::new()));
        let store = SharedSessionStore {
            sessions: sessions.clone(),
        };

        let entropy = MockEntropy;
        let key_provider = InMemoryKeyProvider::new(&entropy);

        let server = Server::<Hqc1, _, _, _>::new(store, MockEntropy, key_provider);

        let client = Client::<Hqc1, _, _, _>::new(
            SharedSessionStore {
                sessions: Arc::new(Mutex::new(HashMap::new())),
            },
            MockEntropy,
        );

        // 1. Handshake
        let (client, req) = client.initialize();
        let res = server.handle_handshake(req).unwrap();

        // 2. Rotate keys in server twice (overwriting both keys so the old key is erased)
        let mut new_k = [0u8; 32];
        entropy.random_bytes(&mut new_k);
        *server.key_provider.keys[0].write().unwrap() = Some(new_k);
        entropy.random_bytes(&mut new_k);
        *server.key_provider.keys[1].write().unwrap() = Some(new_k);

        // 3. Client attempts to process response and send point request
        let (_client, point_reqs) = client.handle_handshake_response(res).unwrap();
        let req = point_reqs[0].clone();

        // 4. Server should fail to decrypt cookie (returns SessionExpired because key was overwritten/erased)
        let res = server.handle_point_request(req);
        assert!(matches!(
            res,
            Err(Error::SessionExpired) | Err(Error::DecryptionError)
        ));
    }
}
