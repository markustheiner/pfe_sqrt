use crate::paillier_crypto::{Cryptosystem, DEBUG_KEYS};
use crate::traits::CryptoDecrypt;
use crate::Result;
use log::debug;
use paillier_common::DecryptionKey;
use std::fmt::Debug;
use std::ops::Deref;
use tokio::sync::mpsc;

pub fn debug_decrypt<CT, PT, T>(name: &str, ct: CT) -> T
where
    Cryptosystem: CryptoDecrypt<DecryptionKey, CT, Result<PT>>,
    PT: ToPlaintext<T>,
    T: Debug,
{
    let res = Cryptosystem::decrypt(&DEBUG_KEYS.1, ct)
        .expect("decryption failed")
        .to_plaintext();
    debug!("Decrypted {name}: {res:?}");
    res
}

pub trait ToPlaintext<T> {
    fn to_plaintext(&self) -> T;
}

impl<T, PT> ToPlaintext<Vec<T>> for Vec<PT>
where
    PT: ToPlaintext<T>,
{
    fn to_plaintext(&self) -> Vec<T> {
        self.iter().map(|pt| pt.to_plaintext()).collect()
    }
}
#[macro_export]
macro_rules! debug_current_span {
    ($msg:expr) => {
        {
            let span = tracing::Span::current();
            if let Some(meta) = span.metadata() {
                println!("{} — In span: {:?}",
                    $msg, meta.name(), );
            } else {
                println!("{} — Not in any span", $msg);
            }
            println!();
        }
    };
}


#[derive(Debug)]
pub struct DebugSender<T> {
    pub(crate) id: String,
    pub(crate) sender: mpsc::Sender<T>,
}

impl<T> Clone for DebugSender<T> {
    fn clone(&self) -> Self {
        //println!("Cloning sender: {}", self.id);
        Self {
            id: self.id.clone(),
            sender: self.sender.clone(),
        }
    }
}

impl<T> Drop for DebugSender<T> {
    fn drop(&mut self) {
        //println!("Dropping sender: {}", self.id);
    }
}

impl<T> Deref for DebugSender<T> {
    type Target = mpsc::Sender<T>;
    fn deref(&self) -> &Self::Target {
        &self.sender
    }
}