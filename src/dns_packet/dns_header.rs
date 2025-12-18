use crate::dns_packet::dns_error::DnsError;
use crate::dns_packet::{Serialization, write_u16};
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
#[derive(Debug)]
pub struct DnsHeader {
    pub id: u16,       // 事务 ID
    pub flags: Flags,  // Flags 标志
    pub qd_count: u16, // QDCOUNT: 问题数
    pub an_count: u16, // ANCOUNT: 回答数
    pub ns_count: u16, // NSCOUNT: 权威记录数
    pub ar_count: u16, // ARCOUNT: 附加记录数
}

#[derive(Debug)]
pub struct Flags {
    pub qr: bool, // QR: 0=查询, 1=响应
    pub oc: u8,   // 操作码, 0=标准查询, 1=反向查询, 2=服务器状态查询
    pub aa: bool, // AA: 权威回答, 1=权威服务器, 0=不是权威服务器
    pub tc: bool, // TC: 截断, 1=消息被截断, 0=消息未被截断
    pub rd: bool, // RD: 递归期望, 1=使用递归查询, 2=不使用递归查询
    pub ra: bool, // RA: 递归可用, 在应答数据包中设置是否支持递归查询
    pub z: u8,    // Z:  Z区未使用，EDNS中与RCODE组合形成新的RCODE
    pub rc: u8, // RCODE: 响应码, 0=无差错, 1=格式错误, 2=服务器失败, 3=名字错误|域名不存在, 4=没有实现, 5=请求被拒绝
}

impl Flags {
    pub fn from_u16(flags: u16) -> Flags {
        Flags {
            qr: (flags >> 15) & 0x1 == 1,
            oc: ((flags >> 11) & 0xF) as u8,
            aa: ((flags >> 10) & 0x1) == 1,
            tc: ((flags >> 9) & 0x1) == 1,
            rd: ((flags >> 8) & 0x1) == 1,
            ra: ((flags >> 7) & 0x1) == 1,
            z: ((flags >> 4) & 0x7) as u8,
            rc: (flags & 0xF) as u8,
        }
    }

    pub fn to_u16(&self) -> u16 {
        let mut flags: u16 = 0;
        if self.qr {
            flags |= 1 << 15;
        }
        flags |= (self.oc as u16) << 11;
        if self.aa {
            flags |= 1 << 10;
        }
        if self.tc {
            flags |= 1 << 9;
        }
        if self.rd {
            flags |= 1 << 8;
        }
        if self.ra {
            flags |= 1 << 7;
        }
        flags |= (self.z as u16) << 4;
        flags |= self.rc as u16;
        flags
    }
}

impl Serialization for DnsHeader {
    fn from_bytes(bytes: &[u8], offset: &mut usize) -> Result<Self, DnsError> {
        let id = u16::from_be_bytes([bytes[*offset], bytes[*offset + 1]]);
        let flags = Flags::from_u16(u16::from_be_bytes([bytes[*offset + 2], bytes[*offset + 3]]));
        let dns_header = DnsHeader {
            id,
            flags,
            qd_count: u16::from_be_bytes([bytes[*offset + 4], bytes[*offset + 5]]),
            an_count: u16::from_be_bytes([bytes[*offset + 6], bytes[*offset + 7]]),
            ns_count: u16::from_be_bytes([bytes[*offset + 8], bytes[*offset + 9]]),
            ar_count: u16::from_be_bytes([bytes[*offset + 10], bytes[*offset + 11]]),
        };
        *offset += 12;
        Ok(dns_header)
    }

    fn to_bytes(&self, bytes: &mut [u8], offset: &mut usize) {
        write_u16(bytes, offset, self.id);
        write_u16(bytes, offset, self.flags.to_u16());
        write_u16(bytes, offset, self.qd_count);
        write_u16(bytes, offset, self.an_count);
        write_u16(bytes, offset, self.ns_count);
        write_u16(bytes, offset, self.ar_count);
    }
}
