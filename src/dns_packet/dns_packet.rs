use std::fmt::Debug;
use crate::dns_packet::{DnsHeader, Flags, DnsQuestion, DnsRecord, PacketTrait, QuestionTrait, RecordTrait};

#[derive(Debug)]
pub struct DnsPacket<Question = DnsQuestion, Record = DnsRecord>
where
    Question: QuestionTrait,
    Record: RecordTrait,
{
    pub header: DnsHeader,
    pub questions: Vec<Question>,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub additions: Vec<Record>,
}

impl<Q, R> PacketTrait for DnsPacket<Q, R>
where
    Q: QuestionTrait,
    R: RecordTrait,
{
    type Question = Q;
    type Record = R;
    fn header(&mut self) -> &mut DnsHeader {
        &mut self.header
    }
    fn question(&mut self) -> &mut Vec<Self::Question> {
        &mut self.questions
    }
    fn answer(&mut self) -> &mut Vec<Self::Record> {
        &mut self.answers
    }
    fn authorities(&mut self) -> &mut Vec<Self::Record> {
        &mut self.authorities
    }
    fn additions(&mut self) -> &mut Vec<Self::Record> {
        &mut self.additions
    }
}

impl<Q, R> Default for DnsPacket<Q, R>
where
    Q: QuestionTrait,
    R: RecordTrait,{
    fn default() -> Self {
        Self {
            header: DnsHeader::default(),
            questions: Vec::default(),
            answers: Vec::default(),
            authorities: Vec::default(),
            additions: Vec::default(),
        }
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
