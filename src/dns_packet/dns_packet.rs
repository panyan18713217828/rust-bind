use crate::dns_packet::Serialization;
use crate::dns_packet::dns_error::DnsError;
use crate::dns_packet::dns_header::DnsHeader;
use crate::dns_packet::dns_question::DnsQuestion;
use crate::dns_packet::dns_record::DnsRecord;

#[derive(Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,           // 头部
    pub questions: Vec<DnsQuestion>, // 问题区域
    pub answers: Vec<DnsRecord>,     // 回答区域
    pub authorities: Vec<DnsRecord>, // 权威区域
    pub additions: Vec<DnsRecord>,   // 附加区域
}

impl Serialization for DnsPacket {
    fn from_bytes(bytes: &[u8], offset: &mut usize) -> Result<DnsPacket, DnsError> {
        let header = DnsHeader::from_bytes(bytes, offset)?;
        let mut questions = Vec::with_capacity(header.qd_count as usize);
        for _ in 0..header.qd_count {
            let question = DnsQuestion::from_bytes(bytes, offset)?;
            questions.push(question);
        }
        let mut answers = Vec::with_capacity(header.an_count as usize);
        for _ in 0..header.an_count {
            let answer = DnsRecord::from_bytes(bytes, offset)?;
            answers.push(answer);
        }
        let mut authorities = Vec::with_capacity(header.ns_count as usize);
        for _ in 0..header.ns_count {
            let author = DnsRecord::from_bytes(bytes, offset)?;
            authorities.push(author);
        }
        let mut additions = Vec::with_capacity(header.ar_count as usize);
        for _ in 0..header.ar_count {
            let addition = DnsRecord::from_bytes(bytes, offset)?;
            additions.push(addition);
        }
        Ok(DnsPacket {
            header,
            questions,
            answers,
            authorities,
            additions,
        })
    }

    fn to_bytes(&self, bytes: &mut [u8], offset: &mut usize) {
        self.header.to_bytes(bytes, offset);
        for question in &self.questions {
            question.to_bytes(bytes, offset);
        }
        for answer in &self.answers {
            answer.to_bytes(bytes, offset);
        }
        for authority in &self.authorities {
            authority.to_bytes(bytes, offset);
        }
        for addition in &self.additions {
            addition.to_bytes(bytes, offset);
        }
    }
}
