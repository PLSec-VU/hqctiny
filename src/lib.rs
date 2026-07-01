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

    fn test_protocol_flow_generic<SCHEME: HqcScheme>() {
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

        // 1. Initialize Handshake Request
        let (client, req) = client.initialize();
        
        // 2. Server handles Handshake Request
        let res = server.handle_handshake(req).unwrap();

        // 3. Client handles Handshake Response
        let (client, point_reqs) = client.handle_handshake_response(res).unwrap();
        assert_eq!(point_reqs.len(), SCHEME::POINTS_NUM * 2);

        // 4. Point Stream
        let mut client = client;
        let mut client_key = None;
        for req in point_reqs {
            let point_res = server.handle_point_request(req).unwrap();
            match client.handle_point_response(point_res).unwrap() {
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
    }

    #[test]
    fn test_protocol_flow_hqc1() {
        test_protocol_flow_generic::<Hqc1>();
    }

    #[test]
    fn test_protocol_flow_hqc3() {
        test_protocol_flow_generic::<Hqc3>();
    }

    #[test]
    fn test_protocol_flow_hqc5() {
        test_protocol_flow_generic::<Hqc5>();
    }
}
