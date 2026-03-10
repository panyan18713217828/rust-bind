use crate::dns_packet::{DnsHeader, Flags, DnsQuestion, DnsRecord};

#[derive(Debug, Default)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additions: Vec<DnsRecord>,
}

#[derive(Debug, Default)]
pub struct DnsPacketBuilder {
    info: DnsPacket,
}

impl DnsPacketBuilder {
    pub fn new() -> DnsPacketBuilder {
        DnsPacketBuilder::default()
    }

    pub fn id(&mut self, id: u16) -> &mut Self {
        self.info.header.id = id;
        self
    }

    pub fn flag(&mut self, flags: Flags) -> &mut Self {
        self.info.header.flags = flags;
        self
    }

    pub fn add_question(&mut self, question: DnsQuestion) -> &mut Self {
        self.info.questions.push(question);
        self
    }

    pub fn add_answer(&mut self, answer: DnsRecord) -> &mut Self {
        self.info.answers.push(answer);
        self
    }

    pub fn add_authority(&mut self, authority: DnsRecord) -> &mut Self {
        self.info.authorities.push(authority);
        self
    }

    pub fn add_additional(&mut self, additional: DnsRecord) -> &mut Self {
        self.info.additions.push(additional);
        self
    }

    pub fn build(mut self) -> DnsPacket {
        self.info.header.qd_count = self.info.questions.len() as u16;
        self.info.header.an_count = self.info.answers.len() as u16;
        self.info.header.ns_count = self.info.authorities.len() as u16;
        self.info.header.ar_count = self.info.additions.len() as u16;
        self.info
    }
}
