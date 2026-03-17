use crate::codec::NamePointerCompress;
use crate::dns_packet::{DnsRecord, RecordTrait};

#[derive(Debug, Default)]
pub struct DnsRecordNSEC3 {
    pub domain_name: String,
    pub record_type: u16,
    pub record_class: u16,
    pub ttl: u32,
    pub length: u16,
}

impl RecordTrait for DnsRecordNSEC3 {
    fn domain_name(&self) -> &str {
        self.domain_name.as_str()
    }

    fn class_code(&self) -> u16 {
        self.record_class
    }

    fn type_code(&self) -> u16 {
        0x0032
    }

    fn type_name(&self) -> &'static str {
        "NSEC3"
    }

    fn encode_record(&self, domain_name: &str, offset: usize, compress: &mut NamePointerCompress) -> Vec<u8> {
        todo!()
    }
}

impl From<DnsRecordNSEC3> for DnsRecord {
    fn from(record: DnsRecordNSEC3) -> Self {
        DnsRecord::NSEC3(record)
    }
}