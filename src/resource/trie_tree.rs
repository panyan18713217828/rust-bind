use crate::resource::resource_bucket::ResourceBucket;

#[derive(Debug, Default)]
pub struct TrieTree {
    nodes: Vec<TreeNode>,
    root: Vec<usize>,
}

#[derive(Debug)]
pub struct TreeNode {
    name: Box<str>,
    child: NodeChild
}

#[derive(Debug)]
enum NodeChild {
    NodeList(Vec<usize>),
    Bucket(ResourceBucket),
}

impl TrieTree {

    pub fn push(&mut self, domain_name: String) {
        let names = domain_name.rsplit(".");

    }

    fn push_node<'a>(&'a mut self, name: &str, child: &'a mut Vec<usize>) {
        if child.is_empty() {

        }
    }
}