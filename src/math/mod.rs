pub mod gf2_8984;
pub mod hqc_bridge;
pub mod interpolate;
pub mod modulus_points;
pub mod segmentation;

/// Block size: half the extension degree.
pub const W: usize = gf2_8984::DEGREE / 2;
