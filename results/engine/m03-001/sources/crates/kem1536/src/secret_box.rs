//! Fixed-size owned allocation: no growth/reallocation API, wipe before freeing.
use std::ops::{Deref, DerefMut};
use zeroize::Zeroize;

#[derive(Clone)]
pub(crate) struct SecretBox<const N: usize>(Box<[u8; N]>);
impl<const N: usize> SecretBox<N> {
    pub(crate) fn zero() -> Self {
        Self(Box::new([0; N]))
    }
    fn wipe(&mut self) {
        self.0.as_mut().zeroize();
    }
}
impl<const N: usize> Deref for SecretBox<N> {
    type Target = [u8; N];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<const N: usize> DerefMut for SecretBox<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl<const N: usize> Drop for SecretBox<N> {
    fn drop(&mut self) {
        self.wipe();
    }
}
impl<const N: usize> zeroize::ZeroizeOnDrop for SecretBox<N> {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wipe_keeps_storage_and_clears_every_owned_byte() {
        let mut value = SecretBox::<5088>::zero();
        let address = value.as_ptr();
        value.fill(0xa5);
        value.wipe();
        assert_eq!(address, value.as_ptr());
        assert!(value.iter().all(|&b| b == 0));
    }
}
