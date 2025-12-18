use crate::dns_packet::dns_error::DnsError;

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum QueryClass {
    IN, // Internet
    CS, // CSNET
    CH, // CHAOS
    HS, // Hesiod
}

impl QueryClass {
    pub fn name(&self) -> &str {
        match self {
            QueryClass::IN => "IN",
            QueryClass::CS => "CS",
            QueryClass::CH => "CH",
            QueryClass::HS => "HS",
        }
    }

    pub fn code(&self) -> u16 {
        match self {
            QueryClass::IN => 1,
            QueryClass::CS => 2,
            QueryClass::CH => 3,
            QueryClass::HS => 4,
        }
    }

    pub fn name_to_class(name: &str) -> Result<QueryClass, DnsError> {
        match name.to_uppercase().as_str() {
            "IN" => Ok(QueryClass::IN),
            "CS" => Ok(QueryClass::CS),
            "CH" => Ok(QueryClass::CH),
            "HS" => Ok(QueryClass::HS),
            _ => Err(DnsError::UnknownQueryClass(String::from(name))),
        }
    }

    pub fn code_to_class(code: u16) -> Result<QueryClass, DnsError> {
        match code {
            1 => Ok(QueryClass::IN),
            2 => Ok(QueryClass::CS),
            3 => Ok(QueryClass::CH),
            4 => Ok(QueryClass::HS),
            _ => Err(DnsError::UnknownQueryClass(code.to_string())),
        }
    }
}
