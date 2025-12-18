use crate::dns_packet::dns_error::DnsError;

#[derive(Debug, Clone)]
pub enum QueryType {
    A,          //
    NS,         //
    CNAME,      //
    SOA,        //
    PTR,        //
    MX,         //
    TXT,        //
    RP,         //
    AFSDB,      //
    SIG,        //
    KEY,        //
    AAAA,       //
    LOC,        //
    SRV,        //
    NAPTR,      //
    KX,         //
    CERT,       //
    DNAME,      //
    OPT,        //
    APL,        //
    DS,         //
    SSHFP,      //
    IPSECKEY,   //
    RRSIG,      //
    NSEC,       //
    DNSKEY,     //
    DHCID,      //
    NSEC3,      //
    NSEC3PARAM, //
    TLSA,       //
    HIP,        //
    SPF,        //
    TKEY,       //
    TSIG,       //
    IXFR,       //
    AXFR,       //
    ANY,        //
    CAA,        //
    TA,         //
    DLV,        //
    SVCB,       //
    HTTPS,      //
}

impl QueryType {
    #[rustfmt::skip]
    pub fn name(&self) -> &str {
        match self {
            QueryType::A          => "A",
            QueryType::NS         => "NS",
            QueryType::CNAME      => "CNAME",
            QueryType::SOA        => "SOA",
            QueryType::PTR        => "PTR",
            QueryType::MX         => "MX",
            QueryType::TXT        => "TXT",
            QueryType::AAAA       => "AAAA",
            QueryType::RP         => "RP",
            QueryType::AFSDB      => "AFSDB",
            QueryType::SIG        => "SIG",
            QueryType::KEY        => "KEY",
            QueryType::LOC        => "LOC",
            QueryType::SRV        => "SRV",
            QueryType::NAPTR      => "NAPTR",
            QueryType::KX         => "KX",
            QueryType::CERT       => "CERT",
            QueryType::DNAME      => "DNAME",
            QueryType::OPT        => "OPT",
            QueryType::APL        => "APL",
            QueryType::DS         => "DS",
            QueryType::SSHFP      => "SSHFP",
            QueryType::IPSECKEY   => "IPSECKEY",
            QueryType::RRSIG      => "RRSIG",
            QueryType::NSEC       => "NSEC",
            QueryType::DNSKEY     => "DNSKEY",
            QueryType::DHCID      => "DHCID",
            QueryType::NSEC3      => "NSEC3",
            QueryType::NSEC3PARAM => "NSEC3PARAM",
            QueryType::TLSA       => "TLSA",
            QueryType::HIP        => "HIP",
            QueryType::SPF        => "SPF",
            QueryType::TKEY       => "TKEY",
            QueryType::TSIG       => "TSIG",
            QueryType::IXFR       => "IXFR",
            QueryType::AXFR       => "AXFR",
            QueryType::ANY        => "ANY",
            QueryType::CAA        => "CAA",
            QueryType::TA         => "TA",
            QueryType::DLV        => "DLV",
            QueryType::SVCB       => "SVCB",
            QueryType::HTTPS      => "HTTPS",
        }
    }

    #[rustfmt::skip]
    pub fn name_to_type(name: &str) -> Result<QueryType, DnsError> {
        match name {
            "A"          => Ok(QueryType::A),
            "NS"         => Ok(QueryType::NS),
            "CNAME"      => Ok(QueryType::CNAME),
            "SOA"        => Ok(QueryType::SOA),
            "PTR"        => Ok(QueryType::PTR),
            "MX"         => Ok(QueryType::MX),
            "TXT"        => Ok(QueryType::TXT),
            "AAAA"       => Ok(QueryType::AAAA),
            "RP"         => Ok(QueryType::RP),
            "AFSDB"      => Ok(QueryType::AFSDB),
            "SIG"        => Ok(QueryType::SIG),
            "KEY"        => Ok(QueryType::KEY),
            "LOC"        => Ok(QueryType::LOC),
            "SRV"        => Ok(QueryType::SRV),
            "NAPTR"      => Ok(QueryType::NAPTR),
            "KX"         => Ok(QueryType::KX),
            "CERT"       => Ok(QueryType::CERT),
            "DNAME"      => Ok(QueryType::DNAME),
            "OPT"        => Ok(QueryType::OPT),
            "APL"        => Ok(QueryType::APL),
            "DS"         => Ok(QueryType::DS),
            "SSHFP"      => Ok(QueryType::SSHFP),
            "IPSECKEY"   => Ok(QueryType::IPSECKEY),
            "RRSIG"      => Ok(QueryType::RRSIG),
            "NSEC"       => Ok(QueryType::NSEC),
            "DNSKEY"     => Ok(QueryType::DNSKEY),
            "DHCID"      => Ok(QueryType::DHCID),
            "NSEC3"      => Ok(QueryType::NSEC3),
            "NSEC3PARAM" => Ok(QueryType::NSEC3PARAM),
            "TLSA"       => Ok(QueryType::TLSA),
            "HIP"        => Ok(QueryType::HIP),
            "SPF"        => Ok(QueryType::SPF),
            "TKEY"       => Ok(QueryType::TKEY),
            "TSIG"       => Ok(QueryType::TSIG),
            "IXFR"       => Ok(QueryType::IXFR),
            "AXFR"       => Ok(QueryType::AXFR),
            "ANY"        => Ok(QueryType::ANY),
            "CAA"        => Ok(QueryType::CAA),
            "TA"         => Ok(QueryType::TA),
            "DLV"        => Ok(QueryType::DLV),
            "SVCB"       => Ok(QueryType::SVCB),
            "HTTPS"      => Ok(QueryType::HTTPS),
            _            => Err(DnsError::UnknownQueryType(String::from(name))),
        }
    }

    #[rustfmt::skip]
    pub fn code(&self) -> u16 {
        match self {
            QueryType::A          => 0x0001,
            QueryType::NS         => 0x0002,
            QueryType::CNAME      => 0x0005,
            QueryType::SOA        => 0x0006,
            QueryType::PTR        => 0x000c,
            QueryType::MX         => 0x000f,
            QueryType::TXT        => 0x0010,
            QueryType::RP         => 0x0011,
            QueryType::AFSDB      => 0x0012,
            QueryType::SIG        => 0x0018,
            QueryType::KEY        => 0x0019,
            QueryType::AAAA       => 0x001c,
            QueryType::LOC        => 0x001d,
            QueryType::SRV        => 0x0021,
            QueryType::NAPTR      => 0x0023,
            QueryType::KX         => 0x0024,
            QueryType::CERT       => 0x0025,
            QueryType::DNAME      => 0x0027,
            QueryType::OPT        => 0x0029,
            QueryType::APL        => 0x002a,
            QueryType::DS         => 0x002b,
            QueryType::SSHFP      => 0x002c,
            QueryType::IPSECKEY   => 0x002d,
            QueryType::RRSIG      => 0x002e,
            QueryType::NSEC       => 0x002f,
            QueryType::DNSKEY     => 0x0030,
            QueryType::DHCID      => 0x0031,
            QueryType::NSEC3      => 0x0032,
            QueryType::NSEC3PARAM => 0x0033,
            QueryType::TLSA       => 0x0034,
            QueryType::HIP        => 0x0037,
            QueryType::SPF        => 0x0063,
            QueryType::TKEY       => 0x00f9,
            QueryType::TSIG       => 0x00fa,
            QueryType::IXFR       => 0x00fb,
            QueryType::AXFR       => 0x00fc,
            QueryType::ANY        => 0x00ff,
            QueryType::CAA        => 0x0101,
            QueryType::TA         => 0x8000,
            QueryType::DLV        => 0x8001,
            QueryType::SVCB       => 0x0040,
            QueryType::HTTPS      => 0x0041,
        }
    }

    #[rustfmt::skip]
    pub fn code_to_type(code: u16) -> Result<QueryType, DnsError> {
        match code {
            0x0001 => Ok(QueryType::A),
            0x0002 => Ok(QueryType::NS),
            0x0005 => Ok(QueryType::CNAME),
            0x0006 => Ok(QueryType::SOA),
            0x000c => Ok(QueryType::PTR),
            0x000f => Ok(QueryType::MX),
            0x0010 => Ok(QueryType::TXT),
            0x0011 => Ok(QueryType::RP),
            0x0012 => Ok(QueryType::AFSDB),
            0x0018 => Ok(QueryType::SIG),
            0x0019 => Ok(QueryType::KEY),
            0x001c => Ok(QueryType::AAAA),
            0x001d => Ok(QueryType::LOC),
            0x0021 => Ok(QueryType::SRV),
            0x0023 => Ok(QueryType::NAPTR),
            0x0024 => Ok(QueryType::KX),
            0x0025 => Ok(QueryType::CERT),
            0x0027 => Ok(QueryType::DNAME),
            0x0029 => Ok(QueryType::OPT),
            0x002a => Ok(QueryType::APL),
            0x002b => Ok(QueryType::DS),
            0x002c => Ok(QueryType::SSHFP),
            0x002d => Ok(QueryType::IPSECKEY),
            0x002e => Ok(QueryType::RRSIG),
            0x002f => Ok(QueryType::NSEC),
            0x0030 => Ok(QueryType::DNSKEY),
            0x0031 => Ok(QueryType::DHCID),
            0x0032 => Ok(QueryType::NSEC3),
            0x0033 => Ok(QueryType::NSEC3PARAM),
            0x0034 => Ok(QueryType::TLSA),
            0x0037 => Ok(QueryType::HIP),
            0x0063 => Ok(QueryType::SPF),
            0x00f9 => Ok(QueryType::TKEY),
            0x00fa => Ok(QueryType::TSIG),
            0x00fb => Ok(QueryType::IXFR),
            0x00fc => Ok(QueryType::AXFR),
            0x00ff => Ok(QueryType::ANY),
            0x0101 => Ok(QueryType::CAA),
            0x8000 => Ok(QueryType::TA),
            0x8001 => Ok(QueryType::DLV),
            0x0040 => Ok(QueryType::SVCB),
            0x0041 => Ok(QueryType::HTTPS),
            _      => Err(DnsError::UnknownQueryType(code.to_string())),
        }
    }
}
