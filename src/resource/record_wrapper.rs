use crate::codec::NamePointerCompress;
use crate::dns_packet::{DnsRecord, RecordTrait};

#[derive(Debug)]
pub struct RecordWrapper<'a> {
    domain_name: &'a str,
    record: &'a DnsRecord,
} 

impl RecordWrapper<'_> {
    pub fn new<'a>(domain_name: &'a str, record: &'a DnsRecord) -> RecordWrapper<'a> {
        RecordWrapper { domain_name, record }
    }
}

impl RecordTrait for RecordWrapper<'_> {
    fn domain_name(&self) -> &str {
        self.domain_name
    }

    fn class_code(&self) -> u16 {
        self.record.class_code()
    }

    fn type_code(&self) -> u16 {
        self.record.type_code()
    }

    fn type_name(&self) -> &'static str {
        self.record.type_name()
    }
    
    fn encode_record(&self, _: &str, offset: usize, compress: &mut NamePointerCompress) -> Vec<u8> {
        self.record.encode_record(self.domain_name, offset, compress)
    }
}