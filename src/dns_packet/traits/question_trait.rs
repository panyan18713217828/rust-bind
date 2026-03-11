use std::fmt::Debug;

pub trait QuestionTrait: Debug {
    fn domain_name(&self) -> &str;
    fn q_type(&self) -> u16;
    fn q_class(&self) -> u16;
}

impl<T: QuestionTrait> QuestionTrait for &T {
    fn domain_name(&self) -> &str {
        (*self).domain_name()
    }
    fn q_type(&self) -> u16 {
        (*self).q_type()
    }
    fn q_class(&self) -> u16 {
        (*self).q_class()
    }
}