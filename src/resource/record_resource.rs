use crate::dns_packet::{DnsRecord, QuestionTrait};
use crate::resource::ResourceTrait;
use crate::resource::trie_tree::TrieTree;

#[derive(Debug, Default)]
pub struct RecordResource {
    root: TrieTree,
}

impl <'a> ResourceTrait<'a> for RecordResource {
    fn select(&'a self, question: impl QuestionTrait) -> Vec<&'a DnsRecord> {
        let b: Box<str> = Box::from("asd");
        let a: &str = "";//&self.a;
        if b == Box::from(a) {

        }
        todo!()
    }
}