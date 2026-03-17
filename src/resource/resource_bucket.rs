use std::collections::HashMap;
use crate::dns_packet::{DnsQuestion, DnsRecord, QuestionTrait, RecordTrait};
use crate::resource::record_wrapper::RecordWrapper;

#[derive(Debug, Default)]
pub struct ResourceBucket {
    record: HashMap<u16, Vec<DnsRecord>>,
}

impl ResourceBucket {

    pub fn add_resource(&mut self, record: DnsRecord) {
        self.record.entry(record.type_code()).or_insert(Vec::new()).push(record);
    }

    pub fn select_record<'a>(&'a self, question: &'a DnsQuestion) -> Vec<RecordWrapper<'a>> {
        let mut result = Vec::new();
        if let Some(data) = self.record.get(&question.q_type) {
            for record in data.iter() {
                result.push(RecordWrapper::new(question.domain_name(), record));
            }
        }
        result
    }
}
