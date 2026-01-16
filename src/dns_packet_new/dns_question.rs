use crate::dns_packet_new::dns_packet::RawDnsQuestion;
use crate::dns_packet_new::name_pointer_lookup::{NamePointerCompress, NamePointerLookup};
use crate::dns_packet_new::query_class::QueryClass;
use crate::dns_packet_new::query_type::QueryType;

#[derive(Debug, Default)]
pub struct DnsQuestionInfo {
    pub names: String,
    pub q_type: QueryType,
    pub q_class: QueryClass,
}

impl TryFrom<&RawDnsQuestion> for DnsQuestionInfo {
    type Error = anyhow::Error;
    fn try_from(raw: &RawDnsQuestion) -> Result<Self, Self::Error> {
        let mut info = DnsQuestionInfo::default();
        info.names = raw.domain_name.clone();
        info.q_type = QueryType::code_to_type(raw.q_type)?;
        info.q_class = QueryClass::code_to_class(raw.q_class)?;
        Ok(info)
    }
}

impl TryFrom<&DnsQuestionInfo> for RawDnsQuestion {
    type Error = anyhow::Error;
    fn try_from(value: &DnsQuestionInfo) -> Result<Self, Self::Error> {
        let mut raw = RawDnsQuestion::default();
        raw.domain_name = value.names.clone();
        raw.q_type = value.q_type.code();
        raw.q_class = value.q_class.code();
        Ok(raw)
    }
}
