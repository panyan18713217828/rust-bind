use crate::dns_packet::{DnsRecord, QuestionTrait};

pub trait ResourceTrait<'a> {

    fn select(&'a self, question: impl QuestionTrait) -> Vec<&'a DnsRecord>;
}