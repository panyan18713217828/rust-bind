mod dns_error;
mod dns_header;
mod dns_packet;
mod dns_question;
mod dns_record;
mod query_class;
mod query_type;

use crate::dns_packet::dns_error::DnsError;
pub(crate) use dns_packet::DnsPacket;
pub(crate) use dns_record::DnsRecord;
pub(crate) use dns_record::DnsRecordData;
pub(crate) use query_class::QueryClass;
pub(crate) use query_type::QueryType;

pub trait Serialization {
    fn from_bytes(bytes: &[u8], offset: &mut usize) -> Result<Self, DnsError>
    where
        Self: Sized;

    fn to_bytes(&self, bytes: &mut [u8], offset: &mut usize);
}

fn read_u16(bytes: &[u8], offset: &mut usize) -> u16 {
    let data = u16::from_be_bytes(bytes[*offset..*offset + 2].try_into().unwrap());
    *offset += 2;
    data
}

fn read_u32(bytes: &[u8], offset: &mut usize) -> u32 {
    let data = u32::from_be_bytes(bytes[*offset..*offset + 4].try_into().unwrap());
    *offset += 4;
    data
}

fn write_u16(bytes: &mut [u8], offset: &mut usize, value: u16) {
    let data = value.to_be_bytes();
    (bytes[*offset], bytes[*offset + 1]) = (data[0], data[1]);
    *offset += 2;
}

fn write_u32(bytes: &mut [u8], offset: &mut usize, value: u32) {
    let data = value.to_be_bytes();
    (
        bytes[*offset],
        bytes[*offset + 1],
        bytes[*offset + 2],
        bytes[*offset + 3],
    ) = (data[0], data[1], data[2], data[3]);
    *offset += 4;
}

fn read_name(bytes: &[u8], offset: &mut usize) -> Result<String, DnsError> {
    let mut name_vec: Vec<u8> = Vec::new();
    loop {
        match bytes[*offset] {
            //结束符直接结束循环
            0x00 => {
                *offset += 1;
                break;
            }
            //判断是否是压缩指针
            pmod if pmod & 0xC0 == 0xC0 => {
                //获取压缩指针
                let mut pointer =
                    u16::from_be_bytes([bytes[*offset] & 0x3F, bytes[*offset + 1]]) as usize;
                //压缩指针只能指向之前出现的位置
                if pointer > *offset {
                    return Err(DnsError::InvalidPointer);
                }
                //用指针代替偏移量读取name字段
                let name = read_name(bytes, &mut pointer)?;
                //压缩指针后没有结束符，这里直接加2就可以了
                *offset += 2;
                //需要加上未用指针解析的前半部分
                return if !name_vec.is_empty() {
                    Ok(String::from_utf8(name_vec).unwrap() + &name)
                } else {
                    Ok(name)
                };
            }
            //需要读取的长度
            len => {
                //len已经使用了一个字节，这里需要向后移动一位
                *offset += 1;
                //循环读取len个ascii码
                for i in 0..len {
                    name_vec.push(bytes[*offset + i as usize]);
                }
                //拼接上句号
                name_vec.push(0x2E);
                //更新偏移量
                *offset += len as usize;
            }
        }
    }
    Ok(String::from_utf8(name_vec).unwrap())
}

fn write_name(bytes: &mut [u8], offset: &mut usize, name: &str) {
    let name_arr = name.as_bytes();
    let name_vec_len = name_arr.len();
    let mut p = *offset + name_vec_len;
    let mut len = 0u8;
    for byte in name_arr.iter().rev() {
        match byte {
            0x2E => {
                bytes[p] = len;
                len = 0;
            }
            _ => {
                bytes[p] = *byte;
                len += 1;
            }
        }
        p -= 1;
    }
    bytes[p] = len;
    *offset += name_vec_len + if name.ends_with(".") { 1 } else { 2 };
}
