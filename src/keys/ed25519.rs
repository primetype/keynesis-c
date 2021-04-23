use crate::rng::Rng;
use keynesis::key::ed25519;
use std::ptr::NonNull;

/// An Ed25519 secret key
pub struct Ed25519SecretKey(pub(crate) ed25519::SecretKey);

/// An Ed25519 Public Key
pub struct Ed25519PublicKey(pub(crate) ed25519::PublicKey);

/// An Ed25519 Signature
pub struct Ed25519Signature(pub(crate) ed25519::Signature);

/// convenient alias for non null pointer
///
/// Don't forget to release the allocated resource with [`ed25519_delete_secret`].
pub type Ed25519SecretKeyPtr = NonNull<Ed25519SecretKey>;

/// convenient alias for non null pointer
///
/// don't forget to release the resource with [`ed25519_delete_public`]
pub type Ed25519PublicKeyPtr = NonNull<Ed25519PublicKey>;

/// convenient alias for non null pointer
///
/// Don't forget to release the allocated resource with [`ed25519_delete_signature`].
pub type Ed25519SignaturePtr = NonNull<Ed25519Signature>;

impl Ed25519PublicKey {
    pub(crate) fn new(key: ed25519::PublicKey) -> Ed25519PublicKeyPtr {
        unsafe { NonNull::new_unchecked(Box::into_raw(Box::new(Self(key)))) }
    }
}

/// Generate a new [`Ed25519SecretKey`] from the given [`Rng`]
///
/// Don't forget to release the resource with [`ed25519_delete_secret`]
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_generate(rng: &mut Rng) -> Ed25519SecretKeyPtr {
    let ptr = Box::into_raw(Box::new(Ed25519SecretKey(ed25519::SecretKey::new(
        rng.rng(),
    ))));

    NonNull::new_unchecked(ptr)
}

/// retrieve the [`Ed25519SecretKey`] from the given key and password
///
/// This function may be rather long to execute as it performs multiple
/// PBKDF2 iterations.
///
/// The key should not be less than 32 bytes. However it is possible to use
/// an empty password.
///
/// Don't forget to release the resource with [`ed25519_delete_secret`]
///
/// # Safety
///
/// `key` and `password` must be valid for reads. Even if the effective `_size`
/// is `0`, the pointers must be non-NULL and properly aligned.
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_derive_from_key(
    key: NonNull<u8>,
    key_size: usize,
    password: NonNull<u8>,
    password_size: usize,
) -> Ed25519SecretKeyPtr {
    let key = std::slice::from_raw_parts_mut(key.as_ptr(), key_size);
    let password = std::slice::from_raw_parts_mut(password.as_ptr(), password_size);

    let seed = keynesis::Seed::derive_from_key(key, password);
    let key = ed25519::SecretKey::new(seed.into_rand_chacha());

    let ptr = Box::into_raw(Box::new(Ed25519SecretKey(key)));

    NonNull::new_unchecked(ptr)
}

/// get the public key out of the secret key
#[no_mangle]
pub extern "C" fn ed25519_to_public_key(key: &Ed25519SecretKey) -> Ed25519PublicKeyPtr {
    Ed25519PublicKey::new(key.0.public_key())
}

/// fill the given `public_key_ptr` with the 32 bytes of the public key
/// associated to the given `key`.
///
/// # Safety
///
/// `key` must be valid to read from and `public_key_ptr` must be valid to
/// write 32 bytes to.
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_public_key_to_bytes(key: &Ed25519PublicKey, out: NonNull<u8>) {
    let out = std::slice::from_raw_parts_mut(out.as_ptr(), ed25519::PublicKey::SIZE);

    out.copy_from_slice(key.0.as_ref());
}

/// generate the signature with the given [`Ed25519SecretKey`] and the given [`data`]
///
/// Don't forget to release the [`Ed25519Signature`] with [`ed25519_delete_signature`].
///
/// # Safety
///
/// Expect the data starting from pointer `data` to `data + data_size` to be
/// valid to read from.
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_sign(
    key: &Ed25519SecretKey,
    data: NonNull<u8>,
    data_size: usize,
) -> Ed25519SignaturePtr {
    let data = std::slice::from_raw_parts(data.as_ptr(), data_size);

    let signature = Ed25519Signature(key.0.sign(data));

    let ptr = Box::into_raw(Box::new(signature));

    NonNull::new_unchecked(ptr)
}

/// verify the [`Ed25519Signature`] with the given [`Ed25519PublicKey`] and the given [`data`]
///
/// # Safety
///
/// Expect the data starting from pointer `data` to `data + data_size` to be
/// valid to read from.
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_verify(
    key: &Ed25519PublicKey,
    signature: &Ed25519Signature,
    data: NonNull<u8>,
    data_size: usize,
) -> bool {
    let data = std::slice::from_raw_parts(data.as_ptr(), data_size);

    key.0.verify(data, &signature.0)
}

/// fill the given `signature_ptr` with the 64 bytes of the public key
/// associated to the given `key`.
///
/// # Safety
///
/// `key` must be valid to read from and `signature_ptr` must be valid to
/// write 64 bytes to.
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_signature_to_bytes(
    signature: &Ed25519Signature,
    out: NonNull<u8>,
) {
    let out = std::slice::from_raw_parts_mut(out.as_ptr(), ed25519::Signature::SIZE);

    out.copy_from_slice(signature.0.as_ref());
}

/// Drop the [`Ed25519SecretKey`] and release the resource.
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_delete_secret(key: Ed25519SecretKeyPtr) {
    let _ = Box::from_raw(key.as_ptr());
}

/// Drop the [`Ed25519PublicKey`] and release the resource.
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_delete_public(key: Ed25519PublicKeyPtr) {
    let _ = Box::from_raw(key.as_ptr());
}

/// Drop the [`Ed25519Signature`] and release the resource.
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_delete_signature(signature: Ed25519SignaturePtr) {
    let _ = Box::from_raw(signature.as_ptr());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "We don't have a way to actually show attempting to delete a null pointer will raise a SIGILL"]
    fn delete_null() {
        let key_ptr = unsafe { NonNull::new_unchecked(std::ptr::null_mut()) };

        unsafe { ed25519_delete_secret(key_ptr) }
    }

    #[test]
    fn sign() {
        let mut data = vec![0x8F; 12];

        let mut rng = Rng::new([]);
        let sec_key = unsafe { ed25519_generate(&mut rng) };
        let pub_key = unsafe { ed25519_to_public_key(sec_key.as_ref()) };

        let signature = unsafe {
            ed25519_sign(
                sec_key.as_ref(),
                NonNull::new_unchecked(data.as_mut_ptr()),
                data.len(),
            )
        };

        let verified = unsafe {
            ed25519_verify(
                pub_key.as_ref(),
                signature.as_ref(),
                NonNull::new_unchecked(data.as_mut_ptr()),
                data.len(),
            )
        };

        unsafe { ed25519_delete_secret(sec_key) };
        unsafe { ed25519_delete_public(pub_key) };
        unsafe { ed25519_delete_signature(signature) };

        assert!(
            verified,
            "the public key of the signing secret key didn't verify the signature properly"
        );
    }

    #[test]
    fn derive_from_key_null_pwd() {
        let mut key = vec![0; 32];
        let mut pwd = vec![];

        let seed_ptr = unsafe {
            ed25519_derive_from_key(
                NonNull::new_unchecked(key.as_mut_ptr()),
                key.len(),
                NonNull::new_unchecked(pwd.as_mut_ptr()),
                pwd.len(),
            )
        };

        unsafe { ed25519_delete_secret(seed_ptr) }
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "It is highly unsafe to use key with less than 32bytes")]
    fn derive_from_small_key() {
        let mut key = vec![0; 30];
        let mut pwd = vec![];

        let seed_ptr = unsafe {
            ed25519_derive_from_key(
                NonNull::new_unchecked(key.as_mut_ptr()),
                key.len(),
                NonNull::new_unchecked(pwd.as_mut_ptr()),
                pwd.len(),
            )
        };

        unsafe { ed25519_delete_secret(seed_ptr) }
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn derive_from_small_key() {
        let mut key = vec![0; 30];
        let mut pwd = vec![];

        let seed_ptr = unsafe {
            ed25519_derive_from_key(
                NonNull::new_unchecked(key.as_mut_ptr()),
                key.len(),
                NonNull::new_unchecked(pwd.as_mut_ptr()),
                pwd.len(),
            )
        };

        unsafe { ed25519_delete_secret(seed_ptr) }
    }

    #[test]
    fn derive_from_key() {
        let mut key = "012345678901234567890123456789++".to_owned().into_bytes();
        let mut pwd = "password".to_string().into_bytes();
        let mut pk = [0; 32];

        let seed_ptr = unsafe {
            ed25519_derive_from_key(
                NonNull::new_unchecked(key.as_mut_ptr()),
                key.len(),
                NonNull::new_unchecked(pwd.as_mut_ptr()),
                pwd.len(),
            )
        };

        let pub_key = unsafe { ed25519_to_public_key(seed_ptr.as_ref()) };
        unsafe {
            ed25519_public_key_to_bytes(pub_key.as_ref(), NonNull::new_unchecked(pk.as_mut_ptr()))
        };

        unsafe { ed25519_delete_secret(seed_ptr) }
        unsafe { ed25519_delete_public(pub_key) }

        assert_eq!(
            pk,
            [
                109, 186, 236, 106, 137, 88, 197, 0, 188, 75, 16, 216, 199, 89, 192, 129, 229, 161,
                238, 206, 12, 138, 70, 170, 190, 35, 40, 54, 177, 185, 117, 10
            ]
        );
    }

    #[test]
    fn public_key() {
        let mut public = vec![0; 32];

        let mut rng = Rng::new([]);

        let key_ptr = unsafe { ed25519_generate(&mut rng) };

        let pub_key = unsafe { ed25519_to_public_key(key_ptr.as_ref()) };
        unsafe {
            ed25519_public_key_to_bytes(
                pub_key.as_ref(),
                NonNull::new_unchecked(public.as_mut_ptr()),
            )
        };

        unsafe { ed25519_delete_secret(key_ptr) }
        unsafe { ed25519_delete_public(pub_key) }

        assert_ne!(public, vec![0; 32]);
    }
}
