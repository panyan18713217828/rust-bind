use crate::dns_packet::dns_error::DnsError;
use crate::dns_packet::query_class::QueryClass;
use crate::dns_packet::query_type::QueryType;
use crate::dns_packet::{read_name, read_u16, write_name, write_u16, Serialization};
/*
  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                     QNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QTYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QCLASS                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
#[derive(Debug)]
pub struct DnsQuestion {
    pub name: String,       // 查询的域名
    pub q_class: QueryClass, // 查询类
    pub q_type: QueryType,   // 查询类型
}

impl Serialization for DnsQuestion {
    fn from_bytes(bytes: &[u8], offset: &mut usize) -> Result<Self, DnsError> {
        let question = DnsQuestion {
            name: read_name(bytes, offset)?,
            q_type: QueryType::code_to_type(read_u16(bytes, offset))?,
            q_class: QueryClass::code_to_class(read_u16(bytes, offset))?,
        };
        Ok(question)
    }

    fn to_bytes(&self, bytes: &mut[u8], offset: &mut usize) {
        write_name(bytes, offset, &self.name);
        write_u16(bytes, offset, self.q_type.code());
        write_u16(bytes, offset, self.q_class.code());
    }
}


