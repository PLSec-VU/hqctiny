#[derive(Copy, Clone, PartialEq, Eq, Debug, clap::ValueEnum)]
pub enum Variant {
    Hqc1,
    Hqc3,
    Hqc5,
}

impl Variant {
    pub fn name(self) -> &'static str {
        match self {
            Variant::Hqc1 => "hqc1",
            Variant::Hqc3 => "hqc3",
            Variant::Hqc5 => "hqc5",
        }
    }
}

pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

#[macro_export]
macro_rules! dispatch_variant {
    ($variant:expr, $scheme:ident => $body:expr) => {
        match $variant {
            $crate::Variant::Hqc1 => {
                type $scheme = HQCLethe::Hqc1;
                $body
            }
            $crate::Variant::Hqc3 => {
                type $scheme = HQCLethe::Hqc3;
                $body
            }
            $crate::Variant::Hqc5 => {
                type $scheme = HQCLethe::Hqc5;
                $body
            }
        }
    };
}
