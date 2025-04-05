#[derive(Debug)]
pub struct Trie {
    root: Node,
}

#[derive(Debug)]
pub struct Node {
    next: Vec<Node>,
    letter: Option<char>,
    is_word: bool,
}

impl Node {
    pub fn new_root() -> Self {
        Self {
            next: vec![],
            letter: None,
            is_word: false,
        }
    }
    pub fn new(letter: char) -> Self {
        Self {
            next: vec![],
            letter: Some(letter),
            is_word: false,
        }
    }
}

impl Default for Trie {
    fn default() -> Self {
        Self::new()
    }
}

impl Trie {
    pub fn new() -> Self {
        Self {
            root: Node::new_root(),
        }
    }

    pub fn insert<W: AsRef<str>>(&mut self, word: W) {
        let mut node = &mut self.root;
        for letter in word.as_ref().chars() {
            if !node.next.iter().any(|n| n.letter == Some(letter)) {
                node.next.push(Node::new(letter));
            }
            node = node
                .next
                .iter_mut()
                .find(|n| n.letter == Some(letter))
                .unwrap();
        }
        node.is_word = true;
    }

    pub fn extend<W: AsRef<str>>(&mut self, words: impl IntoIterator<Item = W>) {
        for word in words.into_iter() {
            self.insert(word);
        }
    }

    pub fn suggest<W: AsRef<str>>(&self, input: W) -> Vec<String> {
        let mut node = &self.root;
        let mut curr = String::new();
        for letter in input.as_ref().chars() {
            if !node.next.iter().any(|n| n.letter == Some(letter)) {
                return vec![];
            }
            node = node.next.iter().find(|n| n.letter == Some(letter)).unwrap();
            curr.push(letter);
        }

        let mut suggestions = vec![];
        suggest_helper(node, &mut suggestions, curr);
        suggestions
    }
}

fn suggest_helper(node: &Node, suggestions: &mut Vec<String>, curr: String) {
    if node.is_word {
        suggestions.push(curr.clone());
    }
    if node.next.is_empty() {
        return;
    }

    for child in &node.next {
        let mut child_str = curr.clone();
        child_str.push(child.letter.unwrap());
        suggest_helper(child, suggestions, child_str);
    }
}
