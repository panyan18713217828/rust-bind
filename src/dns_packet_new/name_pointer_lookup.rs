use std::collections::{HashMap, VecDeque};
use std::iter::Rev;

pub type DataList = VecDeque<NamePointerData>;
type Offset = u16;
type ListIndex = usize;
type DataIndex = usize;

#[derive(Debug, Default)]
pub struct NamePointerLookup {
    // <偏移量, <列表索引, 节点索引>>
    map: HashMap<Offset, (ListIndex, DataIndex)>,
    list: Vec<DataList>,
}

#[derive(Debug, Default)]
pub struct NamePointerCompress {
    // <偏移量, <列表索引, 节点索引>>
    map: HashMap<(ListIndex, DataIndex), Offset>,
    list: Vec<DataList>,
}

#[derive(Debug, Default)]
pub struct NamePointerEntry {
    map: HashMap<Offset, DataIndex>,
    data: DataList,
}

#[derive(Debug)]
pub enum NamePointerData {
    DATA(String),
    POINTER(Offset),
}

impl NamePointerLookup {
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

impl NamePointerCompress {
    
    pub fn compress_name(&self, domain_name: &str) -> DataList {
        let mut result_data_list = DataList::default();
        //对map进行反向映射，方便根据索引获取偏移量
        // let rev_map: HashMap<(ListIndex, DataIndex), Offset> =
        //     self.map.iter().map(|(k, v)| (*v, *k)).collect();
        //对域名进行分割
        let fragments: Vec<&str> = domain_name.split(".").filter(|s| !s.is_empty()).collect();

        //列表索引，指向当前正在匹配的列表
        let mut list_index = 0;
        //当offset为None时，说明还没有匹配上相同后缀的域名
        //当offset有值时，就需要寻找一个具有相同指针为结尾的DataList，再次匹配后缀，看是否可以匹配上更多
        //直到所有DataList匹配完，offset为None说明这个域名没有相同后缀，为Some说明有相同匹配，这个Some的值就是最长的后缀匹配指针
        let mut offset = None;
        //最大后缀匹配数
        let mut max_suffix_match_size = 0;

        while list_index < self.list.len() {
            let data_list = &self.list[list_index];
            match offset {
                None => {
                    //获取最大后缀匹配长度
                    max_suffix_match_size = max_suffix_match((data_list, 0), (&fragments, 0));
                    if max_suffix_match_size > 0 {
                        //最大后缀匹配长度不为0，找到最大匹配的数据索引
                        let pointer_index = data_list.len() - max_suffix_match_size;
                        //根据当前列表索引和最大匹配的数据索引，就能在map的反向映射中获取对应的偏移值
                        offset = self.map.get(&(list_index, pointer_index));
                    }
                }
                Some(data) => {
                    //寻找最后一个数据为指针（如果存在指针，其必定处于列表中的最后一项），并且这个指针与最大匹配数据偏移量相同的列表
                    if !data_list.is_empty()
                        && let NamePointerData::POINTER(pointer) = data_list[data_list.len() - 1]
                        && pointer == *data
                    {
                        //从具有相同指针的域名接着匹配，domain_pointers跳过一个（因为最后一个是指针），fragments跳过上次匹配的最大匹配数
                        let new_match_size =
                            max_suffix_match((data_list, 1), (&fragments, max_suffix_match_size));
                        if new_match_size > 0 {
                            //又匹配上了，更新最大后缀匹配数
                            max_suffix_match_size += new_match_size;
                            //获取数据索引，多减1是因为最后一项是指针，指针不包括在max_suffix_match方法匹配的范围内，所以需要排除
                            let pointer_index = data_list.len() - new_match_size - 1;
                            offset = self.map.get(&(list_index, pointer_index));
                        }
                    }
                }
            }
            list_index += 1;
        }
        //存在指针，就向返回值末尾加入一个指针
        if let Some(offset_data) = offset {
            result_data_list.push_back(NamePointerData::POINTER(*offset_data))
        }
        //最大匹配数小于域名段的长度，说明除了指针还有其它未匹配上的数据
        //就需要将这些未匹配上的数据写入返回值开头
        if max_suffix_match_size < fragments.len() {
            for fragment in fragments.iter().rev().skip(max_suffix_match_size) {
                result_data_list.push_front(NamePointerData::DATA((*fragment).to_string()));
            }
        }
        result_data_list
    }

    pub fn add_entry(&mut self, entry: NamePointerEntry) {
        self.list.push(entry.data);
        let list_index: ListIndex = self.list.len() - 1;
        for (key, value) in entry.map.iter() {
            self.map.insert((list_index, *value), *key);
        }
    }

    pub fn update_offset(&mut self, index: (ListIndex, DataIndex), offset: Offset) {
        if self.map.contains_key(&index) {
            let old_offset = self.map.insert(index, offset).unwrap();
            for data_list in self.list.iter_mut() {
                if !data_list.is_empty()
                    && let NamePointerData::POINTER(pointer) = data_list[data_list.len() - 1]
                    && pointer == old_offset
                {
                    let last = data_list.len() - 1;
                    data_list[last] = NamePointerData::POINTER(offset);
                }
            }
        }
    }
}

impl From<NamePointerCompress> for NamePointerLookup {
    fn from(compress: NamePointerCompress) -> Self {
        NamePointerLookup {
            map: compress.map.iter().map(|(k, v)| (*v, *k)).collect(),
            list: compress.list,
        }
    }
}

impl From<NamePointerLookup> for NamePointerCompress {
    fn from(lookup: NamePointerLookup) -> Self {
        NamePointerCompress {
            map: lookup.map.iter().map(|(k, v)| (*v, *k)).collect(),
            list: lookup.list,
        }
    }
}

fn max_suffix_match(domain_pointers: (&DataList, usize), fragments: (&Vec<&str>, usize)) -> usize {
    let iter1 = domain_pointers.0.iter().rev().skip(domain_pointers.1);
    let iter2 = fragments.0.iter().rev().skip(fragments.1);
    let iter = iter1.zip(iter2);
    let iter = iter.take_while(|(a, b)| matches!(a, NamePointerData::DATA(s) if s.eq(*b)));
    iter.count()
}

impl NamePointerEntry {
    pub fn add_name_pointer(&mut self, offset: Offset, data: NamePointerData) {
        self.data.push_back(data);
        let pointer_index: DataIndex = self.data.len() - 1;
        self.map.insert(offset, pointer_index);
    }
}

// #[test]
// fn test() {
//     let mut lookup = NamePointerLookup::default();
//     let mut offset = 0 as usize;
//     add_domain_name(&mut lookup, "www.guokeyun.com", &mut offset);
//     add_domain_name(&mut lookup, "test.guokeyun.com", &mut offset);
//     add_domain_name(&mut lookup, "aaa.bbb.test.guokeyun.com", &mut offset);
//     add_domain_name(&mut lookup, "aaa.bbb.test.guokeyun.com", &mut offset);
//     let name1 = lookup.get_name(15);
//     println!("name1: {:?}", name1);
//     let name2 = lookup.get_name(15);
//     println!("name2: {:?}", name2);
//     println!();
//
//     let v: Vec<u8> = Vec::new();
//     v.as_slice();
// }

// fn add_domain_name(lookup: &mut NamePointerLookup, domain_name: &str, offset: &mut usize) {
//     let mut entry: NamePointerLookupEntry = NamePointerLookupEntry::default();
//     let pointers: DataList = lookup.compress_name(domain_name);
//     for data in pointers {
//         entry.add_name_pointer(*offset, data);
//         *offset += 3;
//     }
//     lookup.add_lookup_entry(entry);
// }
