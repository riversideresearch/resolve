use std::collections::*;

use crate::schema::*;

#[derive(Default)]
pub struct Interner {
    ids: HashMap<String, Interned>,
    bytes: Vec<u8>,
}

impl Interner {
    pub fn intern(&mut self, value: &str) -> Interned {
        if let Some(&id) = self.ids.get(value) {
            return id;
        }

        let offset = u32::try_from(self.bytes.len()).expect("intern pool exceeds 4 GiB");
        let bytes = value.as_bytes();
        let len = u32::try_from(bytes.len()).expect("interned string exceeds 4 GiB");

        self.bytes.extend_from_slice(&len.to_le_bytes());
        self.bytes.extend_from_slice(bytes);

        let id = Interned(offset);
        self.ids.insert(value.to_owned(), id);
        id
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}
