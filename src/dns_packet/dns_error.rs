#[derive(Debug)]
pub enum DnsError {
    UnknownQueryClass(String),
    UnknownQueryType(String),
    InvalidPointer,
}

impl std::fmt::Display for DnsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DnsError::UnknownQueryClass(name) => write!(f, "unknown class name: {}", name),
            DnsError::UnknownQueryType(name) => write!(f, "unknown type name: {}", name),
            DnsError::InvalidPointer => write!(f, "invalid pointer"),
        }
    }
}

impl std::error::Error for DnsError {}
