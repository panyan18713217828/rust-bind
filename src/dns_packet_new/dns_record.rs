use crate::dns_packet_new::dns_packet::RawDnsRecord;
use crate::dns_packet_new::name_pointer_lookup::{NamePointerCompress, NamePointerLookup};
use crate::dns_packet_new::query_class::QueryClass;
use crate::dns_packet_new::query_type::QueryType;

#[derive(Debug, Default)]
pub struct DnsRecordInfo {
    pub names: String,
    pub q_type: QueryType,
    pub q_class: QueryClass,
    pub ttl: u32,
    pub length: u16,
    
}

impl From<(RawDnsRecord, &mut NamePointerLookup)> for DnsRecordInfo {
    fn from(
        (raw_record, mut lookup): (RawDnsRecord, &mut NamePointerLookup)
    ) -> Self {
        DnsRecordInfo::default()
    }
}

// impl<'a, 'b> From<(&'a DnsRecordInfo, &'b mut NamePointerLookup)> for RawDnsRecord<'a> {
//     fn from((info, mut lookup): (&'a DnsRecordInfo, &'b mut NamePointerLookup)) -> Self {
//         RawDnsRecord::default()
//     }
// }

impl Into<RawDnsRecord> for &DnsRecordInfo {
    fn into(self) -> RawDnsRecord {
        RawDnsRecord::default()
    }
}