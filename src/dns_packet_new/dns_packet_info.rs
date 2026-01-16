use crate::dns_packet_new::dns_header::{FlagInfo, DnsHeaderInfo};
use crate::dns_packet_new::dns_packet::{RawDnsPacket};
use crate::dns_packet_new::dns_question::DnsQuestionInfo;
use crate::dns_packet_new::dns_record::DnsRecordInfo;
use crate::dns_packet_new::name_pointer_lookup::{NamePointerCompress, NamePointerLookup};

#[derive(Debug, Default)]
pub struct DnsPacketInfo {
    /** 头部 */
    pub header: DnsHeaderInfo,
    /** 问题区域 */
    pub question: Vec<DnsQuestionInfo>,
    /** 回答区域 */
    pub answer: Vec<DnsRecordInfo>,
    /** 权威区域 */
    pub authorities: Vec<DnsRecordInfo>,
    /** 附加区域 */
    pub additions: Vec<DnsRecordInfo>,
}

#[derive(Debug, Default)]
pub struct DnsPacketInfoBuilder {
    pub info: DnsPacketInfo,

    _marker: std::marker::PhantomData<DnsPacketInfo>,
}

impl DnsPacketInfoBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn id(&mut self, id: u16) -> &mut Self {
        self.info.header.id = id;
        self
    }

    pub fn flag(&mut self, flag: FlagInfo) -> &mut Self {
        self.info.header.flags = flag;
        self
    }

    pub fn add_question(&mut self, question: DnsQuestionInfo) -> &mut Self {
        self.info.question.push(question);
        self
    }

    pub fn add_answer(&mut self, answer: DnsRecordInfo) -> &mut Self {
        self.info.answer.push(answer);
        self
    }

    pub fn add_authority(&mut self, authority: DnsRecordInfo) -> &mut Self {
        self.info.authorities.push(authority);
        self
    }

    pub fn add_additional(&mut self, additional: DnsRecordInfo) -> &mut Self {
        self.info.additions.push(additional);
        self
    }

    pub fn build(mut self) -> DnsPacketInfo {
        self.info.header.qd_count = self.info.question.len() as u16;
        self.info.header.an_count = self.info.answer.len() as u16;
        self.info.header.ns_count = self.info.authorities.len() as u16;
        self.info.header.ar_count = self.info.additions.len() as u16;
        self.info
    }
}

impl TryFrom<RawDnsPacket> for DnsPacketInfo {
    type Error = anyhow::Error;
    fn try_from(raw_packet: RawDnsPacket) -> Result<Self, Self::Error> {
        let mut builder = DnsPacketInfoBuilder::new();
        let mut lookup = NamePointerLookup::default();
        builder.id(raw_packet.header.id);
        builder.flag(raw_packet.header.flags.try_into()?);
        for question in raw_packet.questions.iter() {
            builder.add_question(question.try_into()?);
        }
        for answer in raw_packet.answers {
            builder.add_answer((answer, &mut lookup).into());
        }
        for authority in raw_packet.authorities {
            builder.add_authority((authority, &mut lookup).into());
        }
        for addition in raw_packet.additions {
            builder.add_additional((addition, &mut lookup).into());
        }
        Ok(builder.build())
    }
}

impl TryFrom<&DnsPacketInfo> for RawDnsPacket {
    type Error = anyhow::Error;
    fn try_from(info: &DnsPacketInfo) -> Result<Self, Self::Error> {
        let mut raw_packet = RawDnsPacket::default();
        raw_packet.header = (&info.header).into();
        for question in info.question.iter() {
            raw_packet.questions.push(question.try_into()?);
        }
        for answer in info.answer.iter() {
            raw_packet.answers.push(answer.into());
        }
        for authority in info.authorities.iter() {
            raw_packet.authorities.push(authority.into());
        }
        for additional in info.additions.iter() {
            raw_packet.additions.push(additional.into());
        }
        Ok(raw_packet)
    }
}