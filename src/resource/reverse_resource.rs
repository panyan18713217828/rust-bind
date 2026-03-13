use crate::dns_packet::{DnsRecord, QuestionTrait};
use crate::resource::ResourceTrait;

/** 反向记录的资源，主要用于查询PTR记录 */
pub struct ReverseResource {
    
}

impl<'a> ResourceTrait<'a> for ReverseResource {
    
    fn select(&'a self, question: impl QuestionTrait) -> Vec<&'a DnsRecord> {
        todo!()
    }
}