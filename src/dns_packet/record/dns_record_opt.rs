use crate::codec::NamePointerCompress;
use crate::dns_packet::{DnsRecord, RecordTrait};

#[derive(Debug, Default)]
pub struct DnsRecordOPT {
    pub domain_name: String,
    pub record_type: u16,
    pub record_class: u16,
}

impl RecordTrait for DnsRecordOPT {
    fn class_code(&self) -> u16 {
        self.record_class
    }

    fn type_code(&self) -> u16 {
        0x0029
    }

    fn type_name(&self) -> &'static str {
        "OPT"
    }

    fn encode(&self, offset: usize, compress: &mut NamePointerCompress) -> Vec<u8> {
        todo!()
    }
}

impl From<DnsRecordOPT> for DnsRecord {
    fn from(record: DnsRecordOPT) -> Self {
        DnsRecord::OPT(record)
    }
}