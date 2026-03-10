use std::collections::{HashMap, VecDeque};

pub type DataList = VecDeque<NamePointerData>;
pub type Offset = u16;
pub type ListIndex = usize;
pub type DataIndex = usize;

#[derive(Debug)]
pub enum NamePointerData {
    DATA(String),
    POINTER(Offset),
}

#[derive(Debug, Default)]
pub struct NamePointerEntry {
    pub map: HashMap<Offset, DataIndex>,
    pub data: DataList,
}

impl NamePointerEntry {
    pub fn add_name_pointer(&mut self, offset: Offset, data: NamePointerData) {
        self.data.push_back(data);
        let pointer_index: DataIndex = self.data.len() - 1;
        self.map.insert(offset, pointer_index);
    }
}