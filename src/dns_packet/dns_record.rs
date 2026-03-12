use crate::codec::NamePointerCompress;
use crate::dns_packet::record::*;
use std::fmt::Debug;
use crate::dns_packet::RecordTrait;
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

#[derive(Debug)]
pub enum DnsRecord {
    A(DnsRecordA),
    NS(DnsRecordNS),
    CNAME(DnsRecordCNAME),
    SOA(DnsRecordSOA),
    AAAA(DnsRecordAAAA),
    TXT(DnsRecordTXT),
    MX(DnsRecordMX),
    OPT(DnsRecordOPT),
    DNSKEY(DnsRecordDNSKEY),
    RRSIG(DnsRecordRRSIG),
    DS(DnsRecordDS),
    NSEC(DnsRecordNSEC),
    NSEC3(DnsRecordNSEC3),
    //因为需要多线程读取，所以这里约束为Send+Sync
    Other(Box<dyn RecordTrait + Send + Sync>),
}

impl RecordTrait for DnsRecord {
    fn class_code(&self) -> u16 {
        match self {
            DnsRecord::A(record) => record.class_code(),
            DnsRecord::NS(record) => record.class_code(),
            DnsRecord::CNAME(record) => record.class_code(),
            DnsRecord::SOA(record) => record.class_code(),
            DnsRecord::AAAA(record) => record.class_code(),
            DnsRecord::TXT(record) => record.class_code(),
            DnsRecord::MX(record) => record.class_code(),
            DnsRecord::OPT(record) => record.class_code(),
            DnsRecord::DNSKEY(record) => record.class_code(),
            DnsRecord::RRSIG(record) => record.class_code(),
            DnsRecord::DS(record) => record.class_code(),
            DnsRecord::NSEC(record) => record.class_code(),
            DnsRecord::NSEC3(record) => record.class_code(),
            DnsRecord::Other(record) => record.class_code(),
        }
    }

    fn class_name(&self) -> &'static str {
        match self {
            DnsRecord::A(record) => record.class_name(),
            DnsRecord::NS(record) => record.class_name(),
            DnsRecord::CNAME(record) => record.class_name(),
            DnsRecord::SOA(record) => record.class_name(),
            DnsRecord::AAAA(record) => record.class_name(),
            DnsRecord::TXT(record) => record.class_name(),
            DnsRecord::MX(record) => record.class_name(),
            DnsRecord::OPT(record) => record.class_name(),
            DnsRecord::DNSKEY(record) => record.class_name(),
            DnsRecord::RRSIG(record) => record.class_name(),
            DnsRecord::DS(record) => record.class_name(),
            DnsRecord::NSEC(record) => record.class_name(),
            DnsRecord::NSEC3(record) => record.class_name(),
            DnsRecord::Other(record) => record.class_name(),
        }
    }

    fn type_code(&self) -> u16 {
        match self {
            DnsRecord::A(record) => record.type_code(),
            DnsRecord::NS(record) => record.type_code(),
            DnsRecord::CNAME(record) => record.type_code(),
            DnsRecord::SOA(record) => record.type_code(),
            DnsRecord::AAAA(record) => record.type_code(),
            DnsRecord::TXT(record) => record.type_code(),
            DnsRecord::MX(record) => record.type_code(),
            DnsRecord::OPT(record) => record.type_code(),
            DnsRecord::DNSKEY(record) => record.type_code(),
            DnsRecord::RRSIG(record) => record.type_code(),
            DnsRecord::DS(record) => record.type_code(),
            DnsRecord::NSEC(record) => record.type_code(),
            DnsRecord::NSEC3(record) => record.type_code(),
            DnsRecord::Other(record) => record.type_code(),
        }
    }

    fn type_name(&self) -> &'static str {
        match self {
            DnsRecord::A(record) => record.type_name(),
            DnsRecord::NS(record) => record.type_name(),
            DnsRecord::CNAME(record) => record.type_name(),
            DnsRecord::SOA(record) => record.type_name(),
            DnsRecord::AAAA(record) => record.type_name(),
            DnsRecord::TXT(record) => record.type_name(),
            DnsRecord::MX(record) => record.type_name(),
            DnsRecord::OPT(record) => record.type_name(),
            DnsRecord::DNSKEY(record) => record.type_name(),
            DnsRecord::RRSIG(record) => record.type_name(),
            DnsRecord::DS(record) => record.type_name(),
            DnsRecord::NSEC(record) => record.type_name(),
            DnsRecord::NSEC3(record) => record.type_name(),
            DnsRecord::Other(record) => record.type_name(),
        }
    }

    fn encode(&self, offset: usize, compress: &mut NamePointerCompress) -> Vec<u8> {
        match self {
            DnsRecord::A(record) => record.encode(offset, compress),
            DnsRecord::NS(record) => record.encode(offset, compress),
            DnsRecord::CNAME(record) => record.encode(offset, compress),
            DnsRecord::SOA(record) => record.encode(offset, compress),
            DnsRecord::AAAA(record) => record.encode(offset, compress),
            DnsRecord::TXT(record) => record.encode(offset, compress),
            DnsRecord::MX(record) => record.encode(offset, compress),
            DnsRecord::OPT(record) => record.encode(offset, compress),
            DnsRecord::DNSKEY(record) => record.encode(offset, compress),
            DnsRecord::RRSIG(record) => record.encode(offset, compress),
            DnsRecord::DS(record) => record.encode(offset, compress),
            DnsRecord::NSEC(record) => record.encode(offset, compress),
            DnsRecord::NSEC3(record) => record.encode(offset, compress),
            DnsRecord::Other(record) => record.encode(offset, compress),
        }
    }
}


