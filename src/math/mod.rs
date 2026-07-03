pub mod gf2_9009;
pub mod interpolate;
pub mod modulus_points;
pub mod segmentation;

/// Block size: half the extension degree.
pub const W: usize = gf2_9009::DEGREE / 2;
