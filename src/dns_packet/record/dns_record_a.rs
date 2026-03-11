use crate::codec::{encode_name, NamePointerCompress};
use crate::dns_packet::{DnsRecord, RecordTrait};

#[derive(Debug, Default)]
pub struct DnsRecordA {
    pub domain_name: String,
    pub record_type: u16,
    pub record_class: u16,
    pub ttl: u32,
    pub length: u16,
    pub data: [u8; 4],
}

impl RecordTrait for DnsRecordA {
    fn class_code(&self) -> u16 {
        self.record_class
    }

    fn type_code(&self) -> u16 {
        0x0001
    }

    fn type_name(&self) -> &'static str {
        "A"
    }

    fn encode(&self, offset: usize, compress: &mut NamePointerCompress) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend(encode_name(offset, self.domain_name.as_str(), compress));
        data.extend(self.record_type.to_be_bytes());
        data.extend(self.record_class.to_be_bytes());
        data.extend(self.ttl.to_be_bytes());
        data.extend(self.length.to_be_bytes());
        data.extend(self.data);
        data
    }
}

impl From<DnsRecordA> for DnsRecord {
    fn from(record: DnsRecordA) -> Self {
        DnsRecord::A(record)
    }
}