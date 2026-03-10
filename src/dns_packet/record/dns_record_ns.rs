use crate::codec::{DnsEncoder, NamePointerCompress};
use crate::dns_packet::{DnsRecord, RecordTrait};

#[derive(Debug, Default)]
pub struct DnsRecordNS {
    pub domain_name: String,
    pub record_type: u16,
    pub record_class: u16,
    pub ttl: u32,
    pub length: u16,
    pub data: String,
}

impl RecordTrait for DnsRecordNS {
    fn class_code(&self) -> u16 {
        self.record_class
    }

    fn type_code(&self) -> u16 {
        0x0002
    }

    fn type_name(&self) -> &'static str {
        "NS"
    }

    fn encode(&self, offset: usize, compress: &mut NamePointerCompress) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend(DnsEncoder::encode_name(offset, self.domain_name.as_str(), compress));
        data.extend(self.record_type.to_be_bytes());
        data.extend(self.record_class.to_be_bytes());
        data.extend(self.ttl.to_be_bytes());
        //这里获取压缩后的域名数据，才能获取正确的数据段长度
        let r_data = DnsEncoder::encode_name(offset + data.len() + 2, self.data.as_str(), compress);
        //这里的长度以r_data的长度为准
        data.extend((r_data.len() as u16).to_be_bytes());
        data.extend(r_data);
        data
    }
}

impl From<DnsRecordNS> for DnsRecord {
    fn from(record: DnsRecordNS) -> Self {
        DnsRecord::NS(record)
    }
}