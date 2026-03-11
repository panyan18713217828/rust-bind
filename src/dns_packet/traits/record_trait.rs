use std::fmt::Debug;
use crate::codec::NamePointerCompress;

pub trait RecordTrait: Debug {
    fn class_code(&self) -> u16;
    fn class_name(&self) -> &'static str {
        match self.class_code() {
            1 => "IN",
            2 => "CS",
            3 => "CH",
            4 => "HS",
            _ => "UNKNOWN",
        }
    }
    fn type_code(&self) -> u16;
    fn type_name(&self) -> &'static str;
    fn encode(&self, offset: usize, compress: &mut NamePointerCompress) -> Vec<u8>;
}

impl<T:RecordTrait> RecordTrait for &T {
    fn class_code(&self) -> u16 {
        (*self).class_code()
    }

    fn type_code(&self) -> u16 {
        (*self).type_code()
    }

    fn type_name(&self) -> &'static str {
        (*self).type_name()
    }

    fn encode(&self, offset: usize, compress: &mut NamePointerCompress) -> Vec<u8> {
        (*self).encode(offset, compress)
    }
}