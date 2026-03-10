use crate::codec::name_pointer::{NamePointerData, NamePointerEntry};
use crate::codec::name_pointer_compress::NamePointerCompress;
use crate::dns_packet::{DnsHeader, DnsPacket, DnsQuestion, RecordTrait};

#[derive(Debug, Default)]
pub struct DnsEncoder ();

impl DnsEncoder {

    pub fn new() -> DnsEncoder {
        DnsEncoder::default()
    }

    pub fn encode(&self, packet: &DnsPacket) -> Vec<u8> {
        let mut compress = NamePointerCompress::new();
        let mut data = Self::encode_header(&packet.header);
        for question in packet.questions.iter() {
            data.extend(Self::encode_question(&question, data.len(), &mut compress))
        }
        for answer in packet.answers.iter() {
            data.extend(answer.encode(data.len(), &mut compress))
        }
        for authority in packet.authorities.iter() {
            data.extend(authority.encode(data.len(), &mut compress))
        }
        for addition in packet.additions.iter() {
            data.extend(addition.encode(data.len(), &mut compress))
        }
        data
    }

    fn encode_header(header: &DnsHeader) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend(header.id.to_be_bytes());
        data.extend(u16::from(&header.flags).to_be_bytes());
        data.extend(header.qd_count.to_be_bytes());
        data.extend(header.an_count.to_be_bytes());
        data.extend(header.ns_count.to_be_bytes());
        data.extend(header.ar_count.to_be_bytes());
        data
    }
    
    fn encode_question(question: &DnsQuestion, offset: usize, compress: &mut NamePointerCompress) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend(Self::encode_name(offset, question.domain_name.as_str(), compress));
        data.extend(question.q_type.to_be_bytes());
        data.extend(question.q_class.to_be_bytes());
        data
    }
    
    pub fn encode_name(offset: usize, name: &str, compress: &mut NamePointerCompress) -> Vec<u8> {
        let mut result = Vec::new();
        let data_list = compress.compress_name(name);
        let mut entry = NamePointerEntry::default();
        let mut has_pointer = false;
        let mut length = 0usize;
        for name_fragment in data_list {
            let true_offset = (offset  + length) as u16;
            match name_fragment {
                NamePointerData::DATA(name) => {
                    entry.add_name_pointer(true_offset, NamePointerData::DATA(name.clone()));
                    result.push(name.len() as u8);
                    result.extend(name.as_bytes());
                    length += name.len() + 1; //这里加1是因为name的长度占了一个字符
                }
                NamePointerData::POINTER(pointer) => {
                    entry.add_name_pointer(true_offset, NamePointerData::POINTER(pointer.clone()));
                    result.extend((pointer | 0xC000).to_be_bytes());
                    length += 2;
                    has_pointer = true;
                }
            }
        }
        if !has_pointer {
            result.push(0x00);
        }
        compress.add_entry(entry);
        result
    }
}