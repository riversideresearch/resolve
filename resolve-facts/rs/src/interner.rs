use std::collections::HashMap;

// TODO: I think we are paying double string cost for storage in this,
//       but might not matter since we don't serialize the hash map?
#[derive(Default)]
pub struct Interner {
    ids: HashMap<String, u32>,
    strings: Vec<String>,
}

impl Interner {
    pub fn intern(&mut self, value: &str) -> u32 {
        if let Some(&id) = self.ids.get(value) {
            return id;
        }

        let id = u32::try_from(self.strings.len()).expect("too many interned strings");
        self.strings.push(value.to_owned());
        self.ids.insert(value.to_owned(), id);
        id
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        // u32: number of strings
        buf.extend_from_slice(
            &u32::try_from(self.strings.len())
                .expect("TOO MANY STRINGS")
                .to_le_bytes(),
        );

        for text in &self.strings {
            let bytes = text.as_bytes();
            buf.extend_from_slice(
                &u32::try_from(bytes.len())
                    .expect("STRING IS WAY TOO BIG")
                    .to_le_bytes(),
            );
            buf.extend_from_slice(bytes);
        }

        buf
    }
}