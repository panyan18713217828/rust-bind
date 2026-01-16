use anyhow::{anyhow, Result};

#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum QueryClass {
    IN, // Internet
    CS, // CSNET
    CH, // CHAOS
    HS, // Hesiod
}

impl Default for QueryClass {
    fn default() -> Self {
        Self::IN
    }
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

    pub fn name_to_class(name: &str) -> Result<QueryClass> {
        match name.to_uppercase().as_str() {
            "IN" => Ok(QueryClass::IN),
            "CS" => Ok(QueryClass::CS),
            "CH" => Ok(QueryClass::CH),
            "HS" => Ok(QueryClass::HS),
            _ => Err(anyhow!("Unknown class name: {}", name)),
        }
    }

    pub fn code_to_class(code: u16) -> Result<QueryClass> {
        match code {
            1 => Ok(QueryClass::IN),
            2 => Ok(QueryClass::CS),
            3 => Ok(QueryClass::CH),
            4 => Ok(QueryClass::HS),
            _ => Err(anyhow!("unknown class code {}", code)),
        }
    }
}
