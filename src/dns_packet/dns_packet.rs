use std::fmt::Debug;
use crate::dns_packet::{DnsHeader, Flags, DnsQuestion, DnsRecord, PacketTrait};

#[derive(Debug, Default)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additions: Vec<DnsRecord>,
}

impl PacketTrait for DnsPacket {
    type Question = DnsQuestion;
    type Record = DnsRecord;
    fn header(&mut self) -> &mut DnsHeader {
        &mut self.header
    }
    fn question(&mut self) -> &mut Vec<DnsQuestion> {
        &mut self.questions
    }
    fn answer(&mut self) -> &mut Vec<DnsRecord> {
        &mut self.answers
    }
    fn authorities(&mut self) -> &mut Vec<DnsRecord> {
        &mut self.authorities
    }
    fn additions(&mut self) -> &mut Vec<DnsRecord> {
        &mut self.additions
    }
}

#[derive(Debug, Default)]
pub struct DnsPacketRef<'a> {
    pub header: DnsHeader,
    pub questions: Vec<&'a DnsQuestion>,
    pub answers: Vec<&'a DnsRecord>,
    pub authorities: Vec<&'a DnsRecord>,
    pub additions: Vec<&'a DnsRecord>,
}

impl<'a> PacketTrait for DnsPacketRef<'a> {
    type Question = &'a DnsQuestion;
    type Record = &'a DnsRecord;
    fn header(&mut self) -> &mut DnsHeader {
        &mut self.header
    }
    fn question(&mut self) -> &mut Vec<&'a DnsQuestion> {
        &mut self.questions
    }
    fn answer(&mut self) -> &mut Vec<&'a DnsRecord> {
        &mut self.answers
    }
    fn authorities(&mut self) -> &mut Vec<&'a DnsRecord> {
        &mut self.authorities
    }
    fn additions(&mut self) -> &mut Vec<&'a DnsRecord> {
        &mut self.additions
    }
}

#[derive(Debug, Default)]
pub struct PacketBuilder<T: PacketTrait> {
    info: T,
}

impl <T: PacketTrait> PacketBuilder<T> {

    pub fn id(&mut self, id: u16) -> &mut Self {
        self.info.header().id = id;
        self
    }

    pub fn flag(&mut self, flags: Flags) -> &mut Self {
        self.info.header().flags = flags;
        self
    }

    pub fn add_question(&mut self, question: T::Question) -> &mut Self {
        self.info.question().push(question);
        self
    }

    pub fn add_answer(&mut self, answer: T::Record) -> &mut Self {
        self.info.answer().push(answer);
        self
    }

    pub fn add_authority(&mut self, authority: T::Record) -> &mut Self {
        self.info.authorities().push(authority);
        self
    }

    pub fn add_additional(&mut self, additional: T::Record) -> &mut Self {
        self.info.additions().push(additional);
        self
    }

    pub fn build(mut self) -> T {
        self.info.header().qd_count = self.info.question().len() as u16;
        self.info.header().an_count = self.info.answer().len() as u16;
        self.info.header().ns_count = self.info.authorities().len() as u16;
        self.info.header().ar_count = self.info.additions().len() as u16;
        self.info
    }
}
