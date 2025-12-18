/*
  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                     NAME                      /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     TYPE                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                      |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    RDLENGTH                   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                     RDATA                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
use crate::dns_packet::dns_error::DnsError;
use crate::dns_packet::query_class::QueryClass;
use crate::dns_packet::query_type::QueryType;
use crate::dns_packet::{Serialization, read_name, read_u16, read_u32, write_name, write_u16, write_u32};

#[derive(Debug)]
pub enum DnsRecord {
    StandardDnsRecord {
        name: String,        //域名
        q_type: QueryType,   //记录类型
        q_class: QueryClass, //记录类型
        ttl: u32,            //生存周期
        length: u16,         //数据长度
        data: DnsRecordData, //记录值
    },

    OptDnsRecord {
        name: String,         //域名
        q_type: QueryType,    //记录类型
        udp_size: u16,        //UDP负载大小
        ercv: u32,            //扩展RCODE/版本
        length: u16,          //数据长度
        option: u16,          //选项
        option_length: u16,   //选项长度
        option_data: Vec<u8>, //选项数据
    },
}

#[derive(Debug)]
pub enum DnsRecordData {
    A([u8; 4]),
    AAAA([u8; 16]),
    MX { priority: u16, exchange: String },
    TXT(String),
    CNAME(String),
    NS(String),
}

impl DnsRecordData {
    fn to_bytes(&self, bytes: &mut [u8], offset: &mut usize) {
        match self {
            DnsRecordData::A(arr) => {
                bytes[*offset] = arr[0];
                bytes[*offset + 1] = arr[1];
                bytes[*offset + 2] = arr[2];
                bytes[*offset + 3] = arr[3];
                *offset += 4;
            }
            DnsRecordData::AAAA(_) => {}
            DnsRecordData::MX { .. } => {}
            DnsRecordData::TXT(_) => {}
            DnsRecordData::CNAME(_) => {}
            DnsRecordData::NS(_) => {}
        }
    }
}

impl Serialization for DnsRecord {
    fn from_bytes(bytes: &[u8], offset: &mut usize) -> Result<Self, DnsError> {
        let name = read_name(bytes, offset)?;
        let q_type = QueryType::code_to_type(read_u16(bytes, offset))?;
        let q_class = read_u16(bytes, offset);
        let ttl = read_u32(bytes, offset);
        let length = read_u16(bytes, offset);
        let record = match q_type {
            QueryType::OPT => {
                let option = read_u16(bytes, offset);
                let option_length = read_u16(bytes, offset);
                let option_data = {
                    let mut data = Vec::with_capacity(option_length as usize);
                    for i in 0..option_length {
                        data.push(bytes[*offset + i as usize]);
                    }
                    *offset += option_length as usize;
                    data
                };
                DnsRecord::OptDnsRecord {
                    name,
                    q_type,
                    udp_size: q_class,
                    ercv: ttl,
                    length,
                    option,
                    option_length,
                    option_data,
                }
            }
            _ => DnsRecord::StandardDnsRecord {
                name,
                q_type,
                q_class: QueryClass::code_to_class(q_class)?,
                ttl,
                length,
                data: DnsRecordData::A([127, 0, 0, 1]),
            },
        };
        Ok(record)
    }

    fn to_bytes(&self, bytes: &mut [u8], offset: &mut usize) {
        match self {
            DnsRecord::StandardDnsRecord { name, q_type, q_class, ttl, length, data } => {
                write_name(bytes, offset, name);
                write_u16(bytes, offset, q_type.code());
                write_u16(bytes, offset, q_class.code());
                write_u32(bytes, offset, *ttl);
                write_u16(bytes, offset, *length);
                data.to_bytes(bytes, offset);
            },
            DnsRecord::OptDnsRecord { .. } => {

            }
        }
    }
}

impl DnsRecord {
    pub fn to_string(&self) -> &str {
        ""
    }
}
