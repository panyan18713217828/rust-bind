use crate::codec::name_pointer_lookup::NamePointerLookup;
use crate::dns_packet::{DnsHeader, DnsPacket, DnsQuestion, DnsRecord, DnsRecordOPT, Flags};

#[derive(Debug, Default)]
pub struct DnsDecoder();

impl DnsDecoder {
    pub fn new() -> DnsDecoder {
        DnsDecoder::default()
    }

    pub fn decode(&self, data: &[u8]) -> Result<DnsPacket, anyhow::Error> {
        let mut lookup = NamePointerLookup::new();
        let (header, mut length) = Self::decode_header(data)?;
        let mut questions = Vec::<DnsQuestion>::new();
        for _ in 0..header.qd_count {
            let (question, len) = Self::decode_question(length, data, &mut lookup)?;
            length += len;
            questions.push(question);
        }
        let mut answers = Vec::<DnsRecord>::new();
        for _ in 0..header.an_count {
            let (answer, len) = Self::decode_record(length, data, &mut lookup)?;
            length += len;
            answers.push(answer);
        }
        let mut authorities = Vec::<DnsRecord>::new();
        for _ in 0..header.ar_count {
            let (authority, len) = Self::decode_record(length, data, &mut lookup)?;
            length += len;
            authorities.push(authority);
        }
        let mut additions = Vec::<DnsRecord>::new();
        for _ in 0..header.an_count {
            let (addition, len) = Self::decode_record(length, data, &mut lookup)?;
            length += len;
            additions.push(addition);
        }
        Ok(DnsPacket { header, questions, answers, authorities, additions, })
    }

    fn decode_header(data: &[u8]) -> Result<(DnsHeader, usize), anyhow::Error> {
        if data.len() < 12 {
            return Err(anyhow::anyhow!("Header data too short"));
        }
        let id = u16::from_be_bytes([data[0], data[1]]);
        let flags = Flags::try_from(u16::from_be_bytes([data[2], data[3]]))?;
        let dns_header = DnsHeader {
            id,
            flags,
            qd_count: u16::from_be_bytes([data[4], data[5]]),
            an_count: u16::from_be_bytes([data[6], data[7]]),
            ns_count: u16::from_be_bytes([data[8], data[9]]),
            ar_count: u16::from_be_bytes([data[10], data[11]]),
        };
        Ok((dns_header, 12))
    }

    fn decode_question(offset: usize, data: &[u8], lookup: &mut NamePointerLookup) -> Result<(DnsQuestion, usize), anyhow::Error> {
        let (domain_name, length) = Self::decode_name(offset, data, lookup)?;
        let q_type = Self::decode_u16(offset + length, data)?;
        let q_class = Self::decode_u16(offset + length + 2, data)?;
        Ok((DnsQuestion { domain_name, q_type, q_class, }, length + 4))
    }

    fn decode_record(offset: usize, data: &[u8], lookup: &mut NamePointerLookup) -> Result<(DnsRecord, usize), anyhow::Error> {
        let mut length = 0;
        let (domain_name, length) = Self::decode_name(offset, data, lookup)?;
        let record_type = Self::decode_u16(offset + length, data)?;
        let record_class = Self::decode_u16(offset + length + 2, data)?;
        if record_type == 0x0029 {
            let record = DnsRecordOPT::default();
            Ok((record.into(), length))
        } else {
            Err(anyhow::anyhow!("Unable to parse data with record type {}", record_type))
        }
    }

    pub fn decode_name(offset: usize, data: &[u8], lookup: &mut NamePointerLookup) -> Result<(String, usize), anyhow::Error> {
        let mut name_vec: Vec<u8> = Vec::new();
        let mut length = 0;
        loop {
            match data[offset + length] {
                0x00 => {
                    length += 1;
                    break;
                }
                pmod if pmod & 0xC0 == 0xC0 => {
                    let pointer = u16::from_be_bytes([data[offset + length] & 0x3F, data[offset + length + 1]]);
                    let option = lookup.get_name(pointer);
                    match option {
                        Some(name) => {
                            length += 2;
                            return if name_vec.is_empty() {
                                Ok((name, length))
                            } else {
                                Ok((String::from_utf8(name_vec)? + "." + name.as_str(), length))
                            };
                        }
                        None => return Err(anyhow::anyhow!("Invalid domain name pointer")),
                    }
                }
                len => {
                    //len已经使用了一个字节，这里需要向后移动一位
                    length += 1;
                    //循环读取len个ascii码
                    for i in 0..len {
                        name_vec.push(data[offset + length + i as usize]);
                    }
                    //拼接上句号
                    name_vec.push(0x2E);
                    //更新偏移量
                    length += len as usize;
                }
            }
        }
        Ok((String::from_utf8(name_vec)?, length))
    }

    pub fn decode_u16(offset: usize, data: &[u8]) -> Result<u16, anyhow::Error> {
        if data.len() < offset + 2 {
            Err(anyhow::anyhow!("data too short"))
        } else {
            Ok(u16::from_be_bytes([data[offset], data[offset + 1]]))
        }
    }

    pub fn decode_u32(offset: usize, data: &[u8]) -> Result<u32, anyhow::Error> {
        if data.len() < offset + 4 {
            Err(anyhow::anyhow!("data too short"))
        } else {
            Ok(u32::from_be_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]))
        }
    }
}
