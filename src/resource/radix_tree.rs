use crate::dns_packet::{DnsQuestion, DnsRecord, QuestionTrait};
use crate::resource::record_wrapper::RecordWrapper;
use crate::resource::resource_bucket::ResourceBucket;

#[derive(Debug)]
pub struct RadixTree {
    root: RadixNode,
}

#[derive(Debug)]
struct RadixNode {
    prefix: Box<str>,
    is_endpoint: bool,
    bucket: ResourceBucket,
    children: Vec<RadixNode>
}

impl Default for RadixTree {
    fn default() -> Self {
        Self {
            root: RadixNode::new("."),
        }
    }
}

impl RadixTree {

    pub fn add_record(&mut self, domain_name: String, record: DnsRecord) {
        self.root.insert(domain_name.as_str(), record);
    }

    pub fn select_record<'a>(&'a self, question: &'a DnsQuestion) -> Vec<RecordWrapper> {
        if let Some(bucket) = self.select_bucket(question.domain_name()) {
            bucket.select_record(question)
        } else {
            Vec::new()
        }
    }

    fn select_bucket(&self, mut domain_name: &str) -> Option<&ResourceBucket> {
        if domain_name.ends_with(".") {
            domain_name = &domain_name[..(domain_name.len() - 1)];
        }
        let segments = domain_name.rsplit(".").collect::<Vec<&str>>();
        self.root.search_bucket(&segments, 0)
    }

    fn select_bucket_mut(&mut self, mut domain_name: &str) -> Option<&mut ResourceBucket> {
        if domain_name.ends_with(".") {
            domain_name = &domain_name[..(domain_name.len() - 1)];
        }
        let segments = domain_name.rsplit(".").collect::<Vec<&str>>();
        self.root.search_bucket_mut(&segments, 0)
    }
}

impl RadixNode {
    fn new(prefix: &str) -> Self {
        Self {
            prefix: Box::from(prefix),
            is_endpoint: false,
            bucket: ResourceBucket::default(),
            children: Vec::new(),
        }
    }

    fn insert(&mut self, mut pattern: &str, record: DnsRecord) {
        if pattern.ends_with(".") {
            pattern = &pattern[..pattern.len() - 1];
        }
        let segments = pattern.rsplit(".").collect::<Vec<&str>>();
        self.insert_segments(&segments, 0, record);
    }

    fn insert_segments(&mut self, segments: &[&str], idx: usize, record: DnsRecord) {
        if idx >= segments.len() {
            self.is_endpoint = true;
            self.bucket.add_resource(record);
            return;
        }
        let segment = segments[idx];
        for child in &mut self.children {
            if child.prefix == Box::from(segment) {
                child.insert_segments(segments, idx + 1, record);
                return;
            }
        }
        let mut new_child = RadixNode::new(segment);
        new_child.insert_segments(segments, idx + 1, record);
        if let Some(last) = self.children.last() && last.prefix == Box::from("*") {
            self.children.insert(self.children.len() - 1, new_child);
        } else {
            self.children.push(new_child);
        }
    }

    fn search_bucket<'a>(&'a self, segments: &[&str], idx: usize) -> Option<&'a ResourceBucket> {
        if idx >= segments.len() {
            if self.is_endpoint {
                return Some(&self.bucket);
            }
            return None;
        }
        let segment = segments[idx];
        for child in &self.children {
            if child.prefix == Box::from(segment) || child.prefix == Box::from("*") {
                if let Some(bucket) = child.search_bucket(segments, idx + 1) {
                    return Some(bucket);
                }
            }
        }
        None
    }

    fn search_bucket_mut<'a>(&'a mut self, segments: &[&str], idx: usize) -> Option<&'a mut ResourceBucket> {
        if idx >= segments.len() {
            if self.is_endpoint {
                return Some(&mut self.bucket);
            }
            return None;
        }
        let segment = segments[idx];
        for child in &mut self.children {
            if child.prefix == Box::from(segment) {
                if let Some(bucket) = child.search_bucket_mut(segments, idx + 1) {
                    return Some(bucket);
                }
            }
        }
        None
    }
}