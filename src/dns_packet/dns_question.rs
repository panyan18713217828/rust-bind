
/*
  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                     QNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QTYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QCLASS                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
use std::fmt::Debug;
use crate::dns_packet::QuestionTrait;

#[derive(Debug, Default)]
pub struct DnsQuestion {
    /** 域名 */
    pub domain_name: String,
    /** 记录类型 */
    pub q_type: u16,
    /** 查询类 */
    pub q_class: u16,
}

impl QuestionTrait for DnsQuestion {
    fn domain_name(&self) -> &str {
        self.domain_name.as_str()
    }
    
    fn q_type(&self) -> u16 {
        self.q_type
    }
    
    fn q_class(&self) -> u16 {
        self.q_class
    }
}