use blake3::Hasher;

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(left);
    h.update(right);
    *h.finalize().as_bytes()
}

fn next_pow2(n: usize) -> usize {
    if n <= 1 {
        return 1;
    }
    let mut p = 1usize;
    while p < n {
        p <<= 1;
    }
    p
}

/// Operations required of a Merkle tree by the protocol.
pub trait MerkleOps: Sized {
    fn build(leaf_hashes: &[[u8; 32]]) -> Self;
    fn root(&self) -> [u8; 32];
    fn proof_len(&self) -> usize;
    fn write_proof(&self, leaf_idx: usize, out: &mut Vec<u8>);
}

/// Flat binary Merkle tree stored in a stack-allocated 1-indexed array of N slots.
///
/// Layout: index 0 is unused; root at index 1; leaves at capacity..2*capacity-1.
/// N must satisfy N >= 2 * next_pow2(num_leaves). Pick N = 2 * next_pow2(POINTS_NUM * 2).
pub struct MerkleTree<const N: usize> {
    nodes: [[u8; 32]; N],
    capacity: usize,
    depth: usize,
}

impl<const N: usize> MerkleOps for MerkleTree<N> {
    fn build(leaf_hashes: &[[u8; 32]]) -> Self {
        let num_leaves = leaf_hashes.len();
        assert!(num_leaves > 0, "MerkleTree requires at least one leaf");
        let capacity = next_pow2(num_leaves);
        assert!(
            2 * capacity <= N,
            "MerkleTree<{N}>: N too small for {num_leaves} leaves (need N >= {})",
            2 * capacity
        );
        let depth = capacity.trailing_zeros() as usize;

        let mut nodes = [[0u8; 32]; N];

        for (i, hash) in leaf_hashes.iter().enumerate() {
            nodes[capacity + i] = *hash;
        }
        // Padding leaves stay zero.

        for i in (1..capacity).rev() {
            nodes[i] = hash_pair(&nodes[2 * i], &nodes[2 * i + 1]);
        }

        Self {
            nodes,
            capacity,
            depth,
        }
    }

    fn root(&self) -> [u8; 32] {
        self.nodes[1]
    }

    fn proof_len(&self) -> usize {
        self.depth * 32
    }

    /// Append the Merkle proof for 0-indexed `leaf_idx` to `out`.
    /// Writes depth * 32 bytes: one sibling hash per level, leaf to root.
    fn write_proof(&self, leaf_idx: usize, out: &mut Vec<u8>) {
        let mut pos = self.capacity + leaf_idx;
        while pos > 1 {
            let sibling = if pos.is_multiple_of(2) {
                pos + 1
            } else {
                pos - 1
            };
            out.extend_from_slice(&self.nodes[sibling]);
            pos /= 2;
        }
    }
}

/// Verify a Merkle proof with no heap allocation.
///
/// `root`         — expected Merkle root
/// `leaf_idx`     — 0-indexed leaf position
/// `leaf_hash`    — hash of the leaf being proven
/// `witness`      — proof bytes from `MerkleTree::write_proof`
/// `total_leaves` — total number of leaves (determines tree capacity)
pub fn verify_proof(
    root: &[u8; 32],
    leaf_idx: usize,
    leaf_hash: [u8; 32],
    witness: &[u8],
    total_leaves: usize,
) -> bool {
    if total_leaves == 0 || !witness.len().is_multiple_of(32) {
        return false;
    }
    let capacity = next_pow2(total_leaves);
    let depth = capacity.trailing_zeros() as usize;
    if witness.len() != depth * 32 {
        return false;
    }

    let mut current = leaf_hash;
    let mut pos = capacity + leaf_idx;

    for sibling in witness.as_chunks::<32>().0 {
        current = if pos.is_multiple_of(2) {
            hash_pair(&current, sibling)
        } else {
            hash_pair(sibling, &current)
        };
        pos /= 2;
    }

    &current == root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(v: u8) -> [u8; 32] {
        let mut h = [0u8; 32];
        h[0] = v;
        h
    }

    #[test]
    fn test_single_leaf() {
        // 1 leaf → capacity 1 → N = 2
        let tree = MerkleTree::<2>::build(&[leaf(1)]);
        assert_eq!(tree.root(), leaf(1));
        assert_eq!(tree.proof_len(), 0);
        let mut w = Vec::new();
        tree.write_proof(0, &mut w);
        assert!(verify_proof(&tree.root(), 0, leaf(1), &w, 1));
        assert!(!verify_proof(&tree.root(), 0, leaf(2), &w, 1));
    }

    #[test]
    fn test_two_leaves() {
        // 2 leaves → capacity 2 → N = 4
        let tree = MerkleTree::<4>::build(&[leaf(1), leaf(2)]);
        let root = tree.root();
        for i in 0..2usize {
            let mut w = Vec::new();
            tree.write_proof(i, &mut w);
            assert_eq!(w.len(), 32);
            assert!(verify_proof(&root, i, [leaf(1), leaf(2)][i], &w, 2));
        }
        let mut w = Vec::new();
        tree.write_proof(0, &mut w);
        assert!(!verify_proof(&root, 0, leaf(99), &w, 2));
    }

    #[test]
    fn test_fourteen_leaves_roundtrip() {
        // 14 leaves → capacity 16 → N = 32
        let leaves: Vec<[u8; 32]> = (0u8..14).map(leaf).collect();
        let tree = MerkleTree::<32>::build(&leaves);
        let root = tree.root();
        // depth = log2(16) = 4 levels × 32 bytes
        assert_eq!(tree.proof_len(), 4 * 32);
        for (i, &leaf_hash) in leaves.iter().enumerate() {
            let mut w = Vec::new();
            tree.write_proof(i, &mut w);
            assert_eq!(w.len(), 4 * 32);
            assert!(verify_proof(&root, i, leaf_hash, &w, 14));
        }
    }

    #[test]
    fn test_tampered_proof_fails() {
        let leaves: Vec<[u8; 32]> = (0u8..14).map(leaf).collect();
        let tree = MerkleTree::<32>::build(&leaves);
        let root = tree.root();
        let mut w = Vec::new();
        tree.write_proof(0, &mut w);
        w[0] ^= 0xff;
        assert!(!verify_proof(&root, 0, leaves[0], &w, 14));
    }
}
