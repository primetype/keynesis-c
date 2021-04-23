use crate::{
    keys::ed25519::{Ed25519PublicKey, Ed25519PublicKeyPtr, Ed25519Signature, Ed25519SignaturePtr},
    rng::Rng,
};
use keynesis::key::ed25519_extended;
use std::ptr::NonNull;

/// An Ed25519Extended secret key
pub struct Ed25519ExtendedSecretKey(ed25519_extended::SecretKey);

/// convenient alias for non null pointer
///
/// Don't forget to release the allocated resource with [`ed25519_extended_delete`].
pub type Ed25519ExtendedSecretKeyPtr = NonNull<Ed25519ExtendedSecretKey>;

/// Generate a new [`Ed25519ExtendedSecretKey`] from the given [`Rng`]
///
/// Don't forget to release the resource with [`ed25519_extended_delete`]
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_extended_generate(rng: &mut Rng) -> Ed25519ExtendedSecretKeyPtr {
    let ptr = Box::into_raw(Box::new(Ed25519ExtendedSecretKey(
        ed25519_extended::SecretKey::new(rng.rng()),
    )));

    NonNull::new_unchecked(ptr)
}

/// retrieve the [`Ed25519ExtendedSecretKey`] from the given key and password
///
/// This function may be rather long to execute as it performs multiple
/// PBKDF2 iterations.
///
/// The key should not be less than 32 bytes. However it is possible to use
/// an empty password.
///
/// Don't forget to release the resource with [`ed25519_extended_delete`]
///
/// # Safety
///
/// `key` and `password` must be valid for reads. Even if the effective `_size`
/// is `0`, the pointers must be non-NULL and properly aligned.
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_extended_derive_from_key(
    key: NonNull<u8>,
    key_size: usize,
    password: NonNull<u8>,
    password_size: usize,
) -> Ed25519ExtendedSecretKeyPtr {
    let key = std::slice::from_raw_parts_mut(key.as_ptr(), key_size);
    let password = std::slice::from_raw_parts_mut(password.as_ptr(), password_size);

    let seed = keynesis::Seed::derive_from_key(key, password);
    let key = ed25519_extended::SecretKey::new(seed.into_rand_chacha());

    let ptr = Box::into_raw(Box::new(Ed25519ExtendedSecretKey(key)));

    NonNull::new_unchecked(ptr)
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
pub unsafe extern "C" fn ed25519_extended_to_public_key(
    key: &Ed25519ExtendedSecretKey,
) -> Ed25519PublicKeyPtr {
    Ed25519PublicKey::new(key.0.public_key())
}

/// generate the signature with the given [`Ed25519ExtendedSecretKey`] and the given [`data`]
///
/// Don't forget to release the [`Ed25519Signature`] with [`ed25519_delete_signature`].
///
/// # Safety
///
/// Expect the data starting from pointer `data` to `data + data_size` to be
/// valid to read from.
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_extended_sign(
    key: &Ed25519ExtendedSecretKey,
    data: NonNull<u8>,
    data_size: usize,
) -> Ed25519SignaturePtr {
    let data = std::slice::from_raw_parts(data.as_ptr(), data_size);

    let signature = Ed25519Signature(key.0.sign(data));

    let ptr = Box::into_raw(Box::new(signature));

    NonNull::new_unchecked(ptr)
}

/// Drop the [`Ed25519ExtendedSecretKey`] and release the resource.
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_extended_delete(key: Ed25519ExtendedSecretKeyPtr) {
    let _ = Box::from_raw(key.as_ptr());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ed25519::{
        ed25519_delete_public, ed25519_delete_signature, ed25519_public_key_to_bytes,
        ed25519_verify,
    };

    #[test]
    #[ignore = "We don't have a way to actually show attempting to delete a null pointer will raise a SIGILL"]
    fn delete_null() {
        let key_ptr = unsafe { NonNull::new_unchecked(std::ptr::null_mut()) };

        unsafe { ed25519_extended_delete(key_ptr) }
    }

    #[test]
    fn sign() {
        let mut data = vec![0x8F; 12];

        let mut rng = Rng::new([]);
        let sec_key = unsafe { ed25519_extended_generate(&mut rng) };
        let pub_key = unsafe { ed25519_extended_to_public_key(sec_key.as_ref()) };

        let signature = unsafe {
            ed25519_extended_sign(
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

        unsafe { ed25519_extended_delete(sec_key) };
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
            ed25519_extended_derive_from_key(
                NonNull::new_unchecked(key.as_mut_ptr()),
                key.len(),
                NonNull::new_unchecked(pwd.as_mut_ptr()),
                pwd.len(),
            )
        };

        unsafe { ed25519_extended_delete(seed_ptr) }
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "It is highly unsafe to use key with less than 32bytes")]
    fn derive_from_small_key() {
        let mut key = vec![0; 30];
        let mut pwd = vec![];

        let seed_ptr = unsafe {
            ed25519_extended_derive_from_key(
                NonNull::new_unchecked(key.as_mut_ptr()),
                key.len(),
                NonNull::new_unchecked(pwd.as_mut_ptr()),
                pwd.len(),
            )
        };

        unsafe { ed25519_extended_delete(seed_ptr) }
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn derive_from_small_key() {
        let mut key = vec![0; 30];
        let mut pwd = vec![];

        let seed_ptr = unsafe {
            ed25519_extended_derive_from_key(
                NonNull::new_unchecked(key.as_mut_ptr()),
                key.len(),
                NonNull::new_unchecked(pwd.as_mut_ptr()),
                pwd.len(),
            )
        };

        unsafe { ed25519_extended_delete(seed_ptr) }
    }

    #[test]
    fn derive_from_key() {
        let mut key = "012345678901234567890123456789++".to_owned().into_bytes();
        let mut pwd = "password".to_string().into_bytes();
        let mut pk = [0; 32];

        let seed_ptr = unsafe {
            ed25519_extended_derive_from_key(
                NonNull::new_unchecked(key.as_mut_ptr()),
                key.len(),
                NonNull::new_unchecked(pwd.as_mut_ptr()),
                pwd.len(),
            )
        };

        let pub_key = unsafe { ed25519_extended_to_public_key(seed_ptr.as_ref()) };
        unsafe {
            ed25519_public_key_to_bytes(pub_key.as_ref(), NonNull::new_unchecked(pk.as_mut_ptr()))
        };

        unsafe { ed25519_extended_delete(seed_ptr) }
        unsafe { ed25519_delete_public(pub_key) }

        assert_eq!(
            pk,
            [
                173, 76, 24, 245, 224, 113, 78, 89, 210, 27, 97, 237, 37, 208, 87, 226, 122, 126,
                204, 179, 26, 213, 64, 150, 202, 159, 85, 66, 91, 129, 232, 55
            ]
        );
    }

    #[test]
    fn public_key() {
        let mut public = vec![0; 32];

        let mut rng = Rng::new([]);

        let key_ptr = unsafe { ed25519_extended_generate(&mut rng) };

        let pub_key = unsafe { ed25519_extended_to_public_key(key_ptr.as_ref()) };
        unsafe {
            ed25519_public_key_to_bytes(
                pub_key.as_ref(),
                NonNull::new_unchecked(public.as_mut_ptr()),
            )
        };
        unsafe { ed25519_delete_public(pub_key) }

        unsafe { ed25519_extended_delete(key_ptr) }

        assert_ne!(public, vec![0; 32]);
    }
}
