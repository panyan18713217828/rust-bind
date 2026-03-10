#[derive(Default)]
struct DnsPacket {
    dns_questions: Vec<DnsQuestion>,
    dns_records: Vec<DnsRecordEnum>
}

#[derive(Default)]
struct DnsQuestion {}


trait DnsRecord {
    fn t(&self);
}

struct DnsRecordA {}
impl DnsRecord for DnsRecordA {
    fn t(&self) {}
}

struct DnsRecordAAAA {}
impl DnsRecord for DnsRecordAAAA {
    fn t(&self) {}
}

enum DnsRecordEnum {
    A(DnsRecordA),
    AAAA(DnsRecordAAAA),
    TXT(),
    CNAME(),
    NS(),
    MX(),
    OPT(),
    DNSKEY(),
    RRSIG(),
    DS(),
    NSEC(),
    NSEC3(),
    Other(Box<dyn DnsRecord>)
}

impl DnsRecord for DnsRecordEnum {
    fn t(&self) {
        match &self {
            DnsRecordEnum::A(record) => record.t(),
            DnsRecordEnum::AAAA(record) => record.t(),
            DnsRecordEnum::TXT() => return,
            DnsRecordEnum::CNAME() => return,
            DnsRecordEnum::NS() => return,
            DnsRecordEnum::MX() => return,
            DnsRecordEnum::OPT() => return,
            DnsRecordEnum::DNSKEY() => return,
            DnsRecordEnum::RRSIG() => return,
            DnsRecordEnum::DS() => return,
            DnsRecordEnum::NSEC() => return,
            DnsRecordEnum::NSEC3() => return,
            DnsRecordEnum::Other(record) => record.t(),
        }
    }
}

impl From<DnsRecordA> for DnsRecordEnum {
    fn from(record: DnsRecordA) -> Self {
        DnsRecordEnum::A(record)
    }
}

#[derive(Default)]
struct DnsDecoder {}
impl DnsDecoder {
    fn decode(&self, data: &[u8]) -> DnsPacket {
        DnsPacket::default()
    }
}

#[derive(Default)]
struct DnsEncoder {}
impl DnsEncoder {
    fn encode(&self, data: &DnsPacket) -> Vec<u8> {
        Vec::new()
    }
}

#[derive(Default)]
struct RecordSelector {}
impl RecordSelector {
    fn select(&self, question: &DnsQuestion) -> Vec<DnsRecordEnum> {
        Vec::new()
    }
}

fn main() {
    let dns_request = [0u8; 4096];
    let decoder = DnsDecoder::default();
    let encoder = DnsEncoder::default();
    let selector = RecordSelector::default();

    let dns_packet = decoder.decode(&dns_request);
    let mut records = Vec::<DnsRecordEnum>::new();
    for question in dns_packet.dns_questions.iter() {
        records.extend(selector.select(question));
    }

    encoder.encode(&dns_packet);
}