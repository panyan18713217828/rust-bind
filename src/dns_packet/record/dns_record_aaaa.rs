use crate::codec::{encode_name, NamePointerCompress};
use crate::dns_packet::{DnsRecord, RecordTrait};

#[derive(Debug, Default)]
pub struct DnsRecordAAAA {
    pub domain_name: String,
    pub record_type: u16,
    pub record_class: u16,
    pub ttl: u32,
    pub length: u16,
    pub data: [u8; 16],
}

impl RecordTrait for DnsRecordAAAA {
    fn domain_name(&self) -> &str {
        self.domain_name.as_str()
    }

    fn class_code(&self) -> u16 {
        self.record_class
    }

    fn type_code(&self) -> u16 {
        0x001c
    }

    fn type_name(&self) -> &'static str {
        "AAAA"
    }

    fn encode_record(&self, domain_name: &str, offset: usize, compress: &mut NamePointerCompress) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend(encode_name(offset, domain_name, compress));
        data.extend(self.type_code().to_be_bytes());
        data.extend(self.class_code().to_be_bytes());
        data.extend(self.ttl.to_be_bytes());
        data.extend(self.length.to_be_bytes());
        data.extend(self.data);
        data
    }
}

impl From<DnsRecordAAAA> for DnsRecord {
    fn from(record: DnsRecordAAAA) -> Self {
        DnsRecord::AAAA(record)
    }
}