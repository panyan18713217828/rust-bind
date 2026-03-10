use crate::codec::NamePointerCompress;
use crate::dns_packet::{DnsRecord, RecordTrait};

#[derive(Debug, Default)]
pub struct DnsRecordNSEC {
    pub domain_name: String,
    pub record_type: u16,
    pub record_class: u16,
    pub ttl: u32,
    pub length: u16,
}

impl RecordTrait for DnsRecordNSEC {
    fn class_code(&self) -> u16 {
        self.record_class
    }

    fn type_code(&self) -> u16 {
        0x002f
    }

    fn type_name(&self) -> &'static str {
        "NSEC"
    }

    fn encode(&self, offset: usize, compress: &mut NamePointerCompress) -> Vec<u8> {
        todo!()
    }
}

impl From<DnsRecordNSEC> for DnsRecord {
    fn from(record: DnsRecordNSEC) -> Self {
        DnsRecord::NSEC(record)
    }
}