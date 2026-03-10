
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
use anyhow::anyhow;

#[derive(Debug, Default)]
pub struct DnsHeader {
    /** 事务ID */
    pub id: u16,
    /** Flags 标志 */
    pub flags: Flags,
    /** QDCOUNT: 问题数 */
    pub qd_count: u16,
    /** ANCOUNT: 回答数 */
    pub an_count: u16,
    /** NSCOUNT: 权威记录数 */
    pub ns_count: u16,
    /** ARCOUNT: 附加记录数 */
    pub ar_count: u16,
}

#[derive(Debug, Default)]
pub struct Flags {
    /** QR: 0=查询, 1=响应 */
    pub qr: bool,
    /** 操作码</br> 0=标准查询, 1=反向查询, 2=服务器状态查询 */
    pub oc: Opcode,
    /** AA: 权威回答, 1=权威服务器, 0=不是权威服务器 */
    pub aa: bool,
    /** TC: 截断, 1=消息被截断, 0=消息未被截断 */
    pub tc: bool,
    /** RD: 递归期望, 1=使用递归查询, 2=不使用递归查询 */
    pub rd: bool,
    /** RA: 递归可用, 在应答数据包中设置是否支持递归查询 */
    pub ra: bool,
    /** Z:  Z区未使用 */
    pub z: u8,
    /** RCODE: 响应码, 0=无差错, 1=格式错误, 2=服务器失败, 3=名字错误|域名不存在, 4=没有实现, 5=请求被拒绝 */
    pub rc: Rcode,
}

#[repr(u16)]
#[derive(Debug, Copy, Clone)]
pub enum Opcode {
    QUERY,      //标准查询
    IQUERY,     //反向查询
    STATUS,     //服务器状态请求
    NOTIFY,     //区域变更通知
    UPDATE      //动态更新
}

#[repr(u16)]
#[derive(Debug, Copy, Clone)]
pub enum Rcode {
    NOERROR,    //没有错误，查询成功，答案在 Answer 部分
    FORMERR,    //格式错误，DNS 服务器因为请求报文格式错误而无法解析请求
    SERVFAIL,   //服务器失败，DNS 服务器因为内部问题无法处理该请求
    NXDOMAIN,   //不存在的域名
    NOTIMP,     //未实现，DNS 服务器不支持所请求的 Opcode
    REFUSED,    //拒绝。DNS 服务器出于策略原因拒绝执行该操作
}

impl Default for Opcode {
    fn default() -> Self {
        Opcode::QUERY
    }
}

impl Default for Rcode {
    fn default() -> Self {
        Rcode::NOERROR
    }
}

impl TryFrom<u16> for Opcode {
    type Error = anyhow::Error;
    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Opcode::QUERY),
            1 => Ok(Opcode::IQUERY),
            2 => Ok(Opcode::STATUS),
            3 => Ok(Opcode::NOTIFY),
            4 => Ok(Opcode::UPDATE),
            _ => Err(anyhow!("Unknown opcode: {}", value))
        }
    }
}

impl TryFrom<u16> for Rcode {
    type Error = anyhow::Error;
    fn try_from(code: u16) -> Result<Self, Self::Error> {
        match code {
            0 => Ok(Rcode::NOERROR),
            1 => Ok(Rcode::FORMERR),
            2 => Ok(Rcode::SERVFAIL),
            3 => Ok(Rcode::NXDOMAIN),
            4 => Ok(Rcode::NOTIMP),
            5 => Ok(Rcode::REFUSED),
            _ => Err(anyhow::anyhow!("Unknown Rcode: {}", code)),
        }
    }
}

impl TryFrom<u16> for Flags {
    type Error = anyhow::Error;
    fn try_from(raw_flags: u16) -> Result<Self, Self::Error> {
        let mut info = Flags::default();
        info.qr = (raw_flags >> 15) & 0x1 == 1;
        info.oc = Opcode::try_from((raw_flags >> 11) & 0xF)?;
        info.aa = (raw_flags >> 10) & 0x1 == 1;
        info.tc = (raw_flags >> 9) & 0x1 == 1;
        info.rd = (raw_flags >> 6) & 0x1 == 1;
        info.ra = (raw_flags >> 4) & 0x1 == 1;
        info.z = ((raw_flags >> 4) & 0x7) as u8;
        info.rc = Rcode::try_from (raw_flags & 0xF)?;
        Ok(info)
    }
}

impl From<&Flags> for u16 {
    fn from(info: &Flags) -> Self {
        let mut flags: u16 = 0;
        if info.qr {
            flags |= 1 << 15;
        }
        flags |= (info.oc as u16) << 11;
        if info.aa {
            flags |= 1 << 10;
        }
        if info.tc {
            flags |= 1 << 9;
        }
        if info.rd {
            flags |= 1 << 8;
        }
        if info.ra {
            flags |= 1 << 7;
        }
        flags |= (info.z as u16) << 4;
        flags |= info.rc as u16;
        flags
    }
}