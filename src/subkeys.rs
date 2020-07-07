use std::cmp::Ordering;
use std::collections::HashMap;
use std::hash::Hash;
use std::marker::PhantomData;

///Compare to something else, in a lexicographical order
pub trait LexOrder<O: ?Sized = Self>: Eq {
    fn lex_cmp(&self, other: &O) -> Ordering;
}

pub struct Storage<K, KL, V>
where
    K: Hash + LexOrder<KL>,
{
    map: HashMap<K, V>,
    keys: Vec<K>,
    phantom: std::marker::PhantomData<KL>,
}

impl<K, KL, V> Storage<K, KL, V>
where
    K: Hash + Ord + Clone + LexOrder<KL>,
{
    fn index_of(&self, key_like: &KL) -> Result<usize, usize> {
        self.keys.binary_search_by(|entry| entry.lex_cmp(key_like))
    }

    pub fn key_of(&self, key_like: &KL) -> Option<K> {
        let key = self.index_of(key_like).ok()?;
        Some(self.keys[key].clone())
    }

    pub fn new() -> Self {
        Storage {
            map: HashMap::new(),
            keys: vec![],
            phantom: PhantomData,
        }
    }

    pub fn get_with(&self, key_like: &KL) -> Option<&V> {
        let key = self.key_of(key_like)?;
        self.get(&key)
    }

    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key)
    }

    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        self.map.get_mut(key)
    }

    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        if let Err(index) = self.keys.binary_search(&key) {
            self.keys.insert(index, key.clone());
        }
        self.map.insert(key, value)
    }
}
