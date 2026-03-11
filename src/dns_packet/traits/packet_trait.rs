use std::fmt::Debug;
use crate::dns_packet::{DnsHeader, QuestionTrait, RecordTrait};

pub trait PacketTrait: Debug {
    type Question: QuestionTrait;
    type Record: RecordTrait;

    fn header(&mut self) -> &mut DnsHeader;
    fn question(&mut self) -> &mut Vec<Self::Question>;
    fn answer(&mut self) -> &mut Vec<Self::Record>;
    fn authorities(&mut self) -> &mut Vec<Self::Record>;
    fn additions(&mut self) -> &mut Vec<Self::Record>;
}

impl<T: PacketTrait> PacketTrait for &mut T {
    type Question = T::Question;
    type Record = T::Record;

    fn header(&mut self) -> &mut DnsHeader {
        (*self).header()
    }

    fn question(&mut self) -> &mut Vec<Self::Question> {
        (*self).question()
    }

    fn answer(&mut self) -> &mut Vec<Self::Record> {
        (*self).answer()
    }

    fn authorities(&mut self) -> &mut Vec<Self::Record> {
        (*self).authorities()
    }

    fn additions(&mut self) -> &mut Vec<Self::Record> {
        (*self).additions()
    }
}