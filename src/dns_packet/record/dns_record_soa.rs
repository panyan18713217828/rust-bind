use crate::codec::{encode_name, NamePointerCompress};
use crate::dns_packet::{DnsRecord, RecordTrait};

#[derive(Debug, Default)]
pub struct DnsRecordSOA {
    pub domain_name: String,
    pub record_type: u16,
    pub record_class: u16,
    pub ttl: u32,
    pub length: u16,
    pub mname: String,  //主域名服务器
    pub rname: String,  //管理员的邮箱地址
    pub serial: u32,    //序列号
    pub refresh: u32,   //刷新间隔（秒）
    pub retry: u32,     //重试间隔（秒）
    pub expire: u32,    //过期时间（秒）
    pub minimum: u32,   //最小 TTL（秒）
}

impl RecordTrait for DnsRecordSOA {
    fn class_code(&self) -> u16 {
        self.record_class
    }

    fn type_code(&self) -> u16 {
        0x0006
    }

    fn type_name(&self) -> &'static str {
        "SOA"
    }

    fn encode(&self, offset: usize, compress: &mut NamePointerCompress) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend(encode_name(offset, self.domain_name.as_str(), compress));
        data.extend(self.record_type.to_be_bytes());
        data.extend(self.record_class.to_be_bytes());
        data.extend(self.ttl.to_be_bytes());
        //这里获取压缩后的域名数据，才能获取正确的数据段长度
        let mut offset = offset + data.len() + 2; //这里的2是length的字节数
        let mut r_data = encode_name(offset, self.mname.as_str(), compress);
        offset += r_data.len();
        r_data.extend(encode_name(offset, self.rname.replace('@', ".").as_str(), compress));
        r_data.extend(self.serial.to_be_bytes());
        r_data.extend(self.refresh.to_be_bytes());
        r_data.extend(self.retry.to_be_bytes());
        r_data.extend(self.expire.to_be_bytes());
        r_data.extend(self.minimum.to_be_bytes());
        //这里的长度以r_data的长度为准
        data.extend((r_data.len() as u16).to_be_bytes());
        data.extend(r_data);
        data
    }
}

impl From<DnsRecordSOA> for DnsRecord {
    fn from(record: DnsRecordSOA) -> Self {
        DnsRecord::SOA(record)
    }
}