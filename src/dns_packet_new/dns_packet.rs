use crate::dns_packet_new::name_pointer_lookup::{
    NamePointerCompress, NamePointerData, NamePointerEntry, NamePointerLookup,
};
use std::fmt::Debug;
use std::rc::Rc;

#[derive(Default)]
pub struct RawDnsPacket {
    pub header: RawDnsHeader,           // 头部
    pub questions: Vec<RawDnsQuestion>, // 问题区域
    pub answers: Vec<RawDnsRecord>,     // 回答区域
    pub authorities: Vec<RawDnsRecord>, // 权威区域
    pub additions: Vec<RawDnsRecord>,   // 附加区域
}

/*
  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|  Opcode   |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
*/
#[derive(Debug, Default)]
pub struct RawDnsHeader {
    /** 事务ID */
    pub id: u16,
    /** Flags 标志 */
    pub flags: u16,
    /** QDCOUNT: 问题数 */
    pub qd_count: u16,
    /** ANCOUNT: 回答数 */
    pub an_count: u16,
    /** NSCOUNT: 权威记录数 */
    pub ns_count: u16,
    /** ARCOUNT: 附加记录数 */
    pub ar_count: u16,
}

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
#[derive(Debug, Default)]
pub struct RawDnsQuestion {
    /** 域名 */
    pub domain_name: String,
    /** 记录类型 */
    pub q_type: u16,
    /** 查询类 */
    pub q_class: u16,
}

/*
  0  1  2  3  4  5  6  7  0  1  2  3  4  5  6  7
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                     NAME                      /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     TYPE                      |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     CLASS                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      TTL                      |
|                                               |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    RDLENGTH                   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/                     RDATA                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
 */
#[derive(Default)]
pub struct RawDnsRecord {
    pub domain_name: String,
    pub q_type: u16,
    pub q_class: u16,
    pub ttl: u32,
    pub length: u16,
    pub data: Box<dyn RawRecordData>,
}

impl Default for Box<dyn RawRecordData> {
    fn default() -> Self {
        Box::new(Vec::new())
    }
}

// pub struct RawRecordData(dyn Fn(usize, &mut NamePointerCompress) -> Vec<u8>);

pub trait RawRecordData {
    fn to_vec(&self, offset: usize, compress: &mut NamePointerCompress) -> Vec<u8>;
}

impl RawRecordData for Vec<u8> {
    fn to_vec(&self, offset: usize, compress: &mut NamePointerCompress) -> Vec<u8> {
        self.to_owned()
    }
}

impl TryFrom<(&[u8], &mut NamePointerLookup)> for RawDnsPacket {
    type Error = anyhow::Error;
    fn try_from((data, lookup): (&[u8], &mut NamePointerLookup)) -> Result<Self, Self::Error> {
        let mut result = RawDnsPacket::default();
        let mut offset = 0;
        result.header = (data, &mut offset).into();
        for _ in 0..result.header.qd_count {
            result.questions.push((data, &mut offset, &mut *lookup).try_into()?);
        }
        for _ in 0..result.header.an_count {
            result.answers.push((data, &mut offset, &mut *lookup).try_into()?);
        }
        for _ in 0..result.header.ns_count {
            result.authorities.push((data, &mut offset, &mut *lookup).try_into()?);
        }
        for _ in 0..result.header.ar_count {
            result.additions.push((data, &mut offset, &mut *lookup).try_into()?);
        }
        Ok(result)
    }
}

impl From<(&[u8], &mut usize)> for RawDnsHeader {
    fn from((data, offset): (&[u8], &mut usize)) -> Self {
        let mut header = RawDnsHeader::default();
        header.id = u16::from_be_bytes([data[*offset + 0], data[*offset + 1]]);
        header.flags = u16::from_be_bytes([data[*offset + 2], data[*offset + 3]]);
        header.qd_count = u16::from_be_bytes([data[*offset + 4], data[*offset + 5]]);
        header.an_count = u16::from_be_bytes([data[*offset + 6], data[*offset + 7]]);
        header.ns_count = u16::from_be_bytes([data[*offset + 8], data[*offset + 9]]);
        header.ar_count = u16::from_be_bytes([data[*offset + 10], data[*offset + 11]]);
        *offset += 12;
        header
    }
}

impl TryFrom<(&[u8], &mut usize, &mut NamePointerLookup)> for RawDnsQuestion {
    type Error = anyhow::Error;
    fn try_from((data, offset, lookup): (&[u8], &mut usize, &mut NamePointerLookup)) -> Result<Self, Self::Error> {
        let mut question = RawDnsQuestion::default();
        question.domain_name = get_name(data, offset, lookup);
        question.q_type = u16::from_be_bytes([data[*offset + 0], data[*offset + 1]]);
        question.q_class = u16::from_be_bytes([data[*offset + 2], data[*offset + 3]]);
        *offset += 4;
        Ok(question)
    }
}

impl TryFrom<(&[u8], &mut usize, &mut NamePointerLookup)> for RawDnsRecord {
    type Error = anyhow::Error;
    fn try_from((data, offset, lookup): (&[u8], &mut usize, &mut NamePointerLookup)) -> Result<Self, Self::Error> {
        let mut record = RawDnsRecord::default();
        record.domain_name = get_name(data, offset, lookup);
        record.q_type = u16::from_be_bytes([data[*offset + 0], data[*offset + 1]]);
        record.q_class = u16::from_be_bytes([data[*offset + 2], data[*offset + 3]]);
        record.ttl = u32::from_be_bytes([
            data[*offset + 4],
            data[*offset + 5],
            data[*offset + 6],
            data[*offset + 7],
        ]);
        record.length = u16::from_be_bytes([data[*offset + 8], data[*offset + 9]]);
        let record_data = Vec::from(&data[*offset + 10..*offset + 10 + record.length as usize]);
        record.data = Box::new(record_data);
        *offset += 10 + record.length as usize;
        Ok(record)
    }
}

fn get_name(data: &[u8], offset: &mut usize, lookup: &mut NamePointerLookup) -> String {
    let mut name_vec: Vec<u8> = Vec::new();
    loop {
        match data[*offset] {
            0x00 => {
                *offset += 1;
                break;
            }
            pmod if pmod & 0xC0 == 0xC0 => {
                let pointer = u16::from_be_bytes([data[*offset] & 0x3F, data[*offset + 1]]);
                let name = lookup.get_name(pointer).unwrap();
                *offset += 2;
                return if name_vec.is_empty() {
                    name
                } else {
                    String::from_utf8(name_vec).unwrap() + "." + name.as_str()
                };
            }
            len => {
                //len已经使用了一个字节，这里需要向后移动一位
                *offset += 1;
                //循环读取len个ascii码
                for i in 0..len {
                    name_vec.push(data[*offset + i as usize]);
                }
                //拼接上句号
                name_vec.push(0x2E);
                //更新偏移量
                *offset += len as usize;
            }
        }
    }
    String::from_utf8(name_vec).unwrap()
}

impl TryFrom<RawDnsPacket> for Vec<u8> {
    type Error = anyhow::Error;
    fn try_from(raw_packet: RawDnsPacket) -> Result<Self, Self::Error> {
        let mut compress = NamePointerCompress::default();
        let mut result: Vec<u8> = Vec::new();
        let header_data: Vec<u8> = (&raw_packet.header).try_into()?;
        result.extend(header_data);
        for question in raw_packet.questions.iter() {
            let question_data: Vec<u8> =
                RawDnsFragmentWrapper::new(result.len(), question, &mut compress).try_into()?;
            result.extend(question_data);
        }
        for answer in raw_packet.answers.iter() {
            let answer_data: Vec<u8> =
                RawDnsFragmentWrapper::new(result.len(), answer, &mut compress).try_into()?;
            result.extend(answer_data);
        }
        for authority in raw_packet.authorities.iter() {
            let authority_data: Vec<u8> =
                RawDnsFragmentWrapper::new(result.len(), authority, &mut compress).try_into()?;
            result.extend(authority_data);
        }
        for addition in raw_packet.additions.iter() {
            let addition_data: Vec<u8> =
                RawDnsFragmentWrapper::new(result.len(), addition, &mut compress).try_into()?;
            result.extend(addition_data);
        }
        Ok(result)
    }
}

trait GetName {
    fn get_name(&self) -> &str;
}

impl GetName for RawDnsQuestion {
    fn get_name(&self) -> &str {
        self.domain_name.as_str()
    }
}

impl GetName for RawDnsRecord {
    fn get_name(&self) -> &str {
        self.domain_name.as_str()
    }
}

struct RawDnsFragmentWrapper<'a, T: GetName> {
    offset: usize,
    fragment: &'a T,
    compress: &'a mut NamePointerCompress,
}

impl<'a, T: GetName> RawDnsFragmentWrapper<'a, T> {
    fn new(offset: usize, fragment: &'a T, compress: &'a mut NamePointerCompress) -> Self {
        RawDnsFragmentWrapper {
            offset,
            fragment,
            compress,
        }
    }

    fn name(&mut self) -> Result<Vec<u8>, anyhow::Error> {
        let mut offset = self.offset;
        let mut result = Vec::new();
        let name = self.fragment.get_name();
        let data_list = self.compress.compress_name(name);
        let mut entry = NamePointerEntry::default();
        let mut has_pointer = false;
        for name_fragment in data_list {
            match name_fragment {
                NamePointerData::DATA(name) => {
                    entry.add_name_pointer(offset as u16, NamePointerData::DATA(name.clone()));
                    result.push(name.len() as u8);
                    result.extend(name.as_bytes());
                }
                NamePointerData::POINTER(pointer) => {
                    entry
                        .add_name_pointer(offset as u16, NamePointerData::POINTER(pointer.clone()));
                    result.extend((pointer | 0xC0).to_be_bytes());
                    has_pointer = true;
                }
            }
            offset += result.len();
        }
        if !has_pointer {
            result.push(0x00);
        }
        self.compress.add_entry(entry);
        Ok(result)
    }
}

impl TryFrom<&RawDnsHeader> for Vec<u8> {
    type Error = anyhow::Error;
    fn try_from(header: &RawDnsHeader) -> Result<Self, Self::Error> {
        let mut result = Vec::new();
        result.extend(header.id.to_be_bytes());
        result.extend(header.flags.to_be_bytes());
        result.extend(header.qd_count.to_be_bytes());
        result.extend(header.an_count.to_be_bytes());
        result.extend(header.ns_count.to_be_bytes());
        result.extend(header.ar_count.to_be_bytes());
        Ok(result)
    }
}

impl TryFrom<RawDnsFragmentWrapper<'_, RawDnsQuestion>> for Vec<u8> {
    type Error = anyhow::Error;
    fn try_from(mut wrapper: RawDnsFragmentWrapper<RawDnsQuestion>) -> Result<Self, Self::Error> {
        let mut result = Vec::new();
        let fragment = wrapper.fragment;
        let name_data = wrapper.name()?;
        result.extend(name_data);
        result.extend(fragment.q_type.to_be_bytes());
        result.extend(fragment.q_class.to_be_bytes());
        Ok(result)
    }
}

impl TryFrom<RawDnsFragmentWrapper<'_, RawDnsRecord>> for Vec<u8> {
    type Error = anyhow::Error;
    fn try_from(mut wrapper: RawDnsFragmentWrapper<RawDnsRecord>) -> Result<Self, Self::Error> {
        let mut result = Vec::new();
        let fragment = wrapper.fragment;
        result.extend(wrapper.name()?);
        result.extend(fragment.q_type.to_be_bytes());
        result.extend(fragment.q_class.to_be_bytes());
        result.extend(fragment.ttl.to_be_bytes());
        result.extend(fragment.length.to_be_bytes());
        result.extend(fragment.data.to_vec(wrapper.offset, wrapper.compress));
        Ok(result)
    }
}
