use crate::codec::name_pointer::{
    DataIndex, DataList, ListIndex, NamePointerData, NamePointerEntry, Offset,
};
use std::collections::{HashMap};

use crate::codec::DnsEncoder;
use crate::codec::DnsDecoder;

#[derive(Debug, Default)]
pub struct NamePointerLookup {
    // <偏移量, <列表索引, 节点索引>>
    map: HashMap<Offset, (ListIndex, DataIndex)>,
    list: Vec<DataList>,
}

impl NamePointerLookup {
    pub fn new() -> NamePointerLookup {
        NamePointerLookup::default()
    }

    pub fn get_name(&self, offset: Offset) -> Option<String> {
        let list = self.get_fragments(offset);
        if !list.is_empty() {
            Some(list.into_iter().collect::<Vec<&str>>().join("."))
        } else {
            None
        }
    }

    pub fn get_fragments(&self, offset: Offset) -> Vec<&str> {
        let mut result: Vec<&str> = Vec::new();
        if let Some((list_index, data_index)) = self.map.get(&offset) {
            let list = &self.list[*list_index];
            let mut index = *data_index;
            while index < list.len() {
                match list[index] {
                    NamePointerData::DATA(ref data) => {
                        result.push(data.as_str());
                    }
                    NamePointerData::POINTER(pointer) => {
                        result.append(&mut self.get_fragments(pointer));
                    }
                }
                index += 1;
            }
        }
        result
    }

    pub fn add_entry(&mut self, entry: NamePointerEntry) {
        self.list.push(entry.data);
        let list_index: ListIndex = self.list.len() - 1;
        for (key, value) in entry.map.iter() {
            self.map.insert(*key, (list_index, *value));
        }
    }
}
