use crate::codec::{encode_name, NamePointerCompress};
use crate::dns_packet::{DnsRecord, RecordTrait};

#[derive(Debug, Default)]
pub struct DnsRecordMX {
    pub domain_name: String,
    pub record_type: u16,
    pub record_class: u16,
    pub ttl: u32,
    pub length: u16,
    pub preference: u16,
    pub exchange: String,
}

impl RecordTrait for DnsRecordMX {
    fn domain_name(&self) -> &str {
        self.domain_name.as_str()
    }

    fn class_code(&self) -> u16 {
        self.record_class
    }

    fn type_code(&self) -> u16 {
        0x000f
    }

    fn type_name(&self) -> &'static str {
        "MX"
    }

    fn encode(&self, offset: usize, compress: &mut NamePointerCompress) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend(encode_name(offset, self.domain_name.as_str(), compress));
        data.extend(self.record_type.to_be_bytes());
        data.extend(self.record_class.to_be_bytes());
        data.extend(self.ttl.to_be_bytes());
        //这里获取压缩后的域名数据，才能获取正确的数据段长度
        let r_data = encode_name(offset + data.len() + 4, self.exchange.as_str(), compress);
        //这里的长度以r_data的长度为准
        data.extend(((r_data.len() + 2) as u16).to_be_bytes());
        data.extend(self.preference.to_be_bytes());
        data.extend(r_data);
        data
    }
}

impl From<DnsRecordMX> for DnsRecord {
    fn from(record: DnsRecordMX) -> Self {
        DnsRecord::MX(record)
    }
}