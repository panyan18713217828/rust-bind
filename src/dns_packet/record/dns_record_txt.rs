use crate::codec::NamePointerCompress;
use crate::dns_packet::{DnsRecord, RecordTrait};

#[derive(Debug, Default)]
pub struct DnsRecordTXT {
    pub domain_name: String,
    pub record_type: u16,
    pub record_class: u16,
    pub ttl: u32,
    pub length: u16,
}

impl RecordTrait for DnsRecordTXT {
    fn class_code(&self) -> u16 {
        self.record_class
    }

    fn type_code(&self) -> u16 {
        0x0010
    }

    fn type_name(&self) -> &'static str {
        "TXT"
    }

    fn encode(&self, offset: usize, compress: &mut NamePointerCompress) -> Vec<u8> {
        todo!()
    }
}

impl From<DnsRecordTXT> for DnsRecord {
    fn from(record: DnsRecordTXT) -> Self {
        DnsRecord::TXT(record)
    }
}