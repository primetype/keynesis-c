use crate::{
    keys::ed25519::{Ed25519PublicKey, Ed25519PublicKeyPtr},
    rng::Rng,
};
use keynesis::key::curve25519;
use std::ptr::NonNull;

/// A Curve25519 secret key
pub struct Curve25519SecretKey(curve25519::SecretKey);

/// convenient alias for non null pointer
///
/// Don't forget to release the allocated resource with [`curve25519_delete`].
pub type Curve25519SecretKeyPtr = NonNull<Curve25519SecretKey>;

/// Generate a new [`Curve25519SecretKey`] from the given [`Rng`]
///
/// Don't forget to release the resource with [`curve25519_delete`]
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn curve25519_generate(rng: &mut Rng) -> Curve25519SecretKeyPtr {
    let ptr = Box::into_raw(Box::new(Curve25519SecretKey(curve25519::SecretKey::new(
        rng.rng(),
    ))));

    NonNull::new_unchecked(ptr)
}

/// retrieve the [`Curve25519SecretKey`] from the given key and password
///
/// This function may be rather long to execute as it performs multiple
/// PBKDF2 iterations.
///
/// The key should not be less than 32 bytes. However it is possible to use
/// an empty password.
///
/// Don't forget to release the resource with [`curve25519_delete`]
///
/// # Safety
///
/// `key` and `password` must be valid for reads. Even if the effective `_size`
/// is `0`, the pointers must be non-NULL and properly aligned.
///
#[no_mangle]
pub unsafe extern "C" fn curve25519_derive_from_key(
    key: NonNull<u8>,
    key_size: usize,
    password: NonNull<u8>,
    password_size: usize,
) -> Curve25519SecretKeyPtr {
    let key = std::slice::from_raw_parts_mut(key.as_ptr(), key_size);
    let password = std::slice::from_raw_parts_mut(password.as_ptr(), password_size);

    let seed = keynesis::Seed::derive_from_key(key, password);
    let key = curve25519::SecretKey::new(seed.into_rand_chacha());

    let ptr = Box::into_raw(Box::new(Curve25519SecretKey(key)));

    NonNull::new_unchecked(ptr)
}

/// get the public key out of the secret key
#[no_mangle]
pub extern "C" fn curve25519_to_public_key(key: &Curve25519SecretKey) -> Ed25519PublicKeyPtr {
    Ed25519PublicKey::new(key.0.public_key())
}

/// Drop the [`Curve25519SecretKey`] and release the resource.
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn curve25519_delete(key: Curve25519SecretKeyPtr) {
    let _ = Box::from_raw(key.as_ptr());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ed25519::{ed25519_delete_public, ed25519_public_key_to_bytes};

    #[test]
    #[ignore = "We don't have a way to actually show attempting to delete a null pointer will raise a SIGILL"]
    fn delete_null() {
        let key_ptr = unsafe { NonNull::new_unchecked(std::ptr::null_mut()) };

        unsafe { curve25519_delete(key_ptr) }
    }

    #[test]
    fn derive_from_key_null_pwd() {
        let mut key = vec![0; 32];
        let mut pwd = vec![];

        let seed_ptr = unsafe {
            curve25519_derive_from_key(
                NonNull::new_unchecked(key.as_mut_ptr()),
                key.len(),
                NonNull::new_unchecked(pwd.as_mut_ptr()),
                pwd.len(),
            )
        };

        unsafe { curve25519_delete(seed_ptr) }
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "It is highly unsafe to use key with less than 32bytes")]
    fn derive_from_small_key() {
        let mut key = vec![0; 30];
        let mut pwd = vec![];

        let seed_ptr = unsafe {
            curve25519_derive_from_key(
                NonNull::new_unchecked(key.as_mut_ptr()),
                key.len(),
                NonNull::new_unchecked(pwd.as_mut_ptr()),
                pwd.len(),
            )
        };

        unsafe { curve25519_delete(seed_ptr) }
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn derive_from_small_key() {
        let mut key = vec![0; 30];
        let mut pwd = vec![];

        let seed_ptr = unsafe {
            curve25519_derive_from_key(
                NonNull::new_unchecked(key.as_mut_ptr()),
                key.len(),
                NonNull::new_unchecked(pwd.as_mut_ptr()),
                pwd.len(),
            )
        };

        unsafe { curve25519_delete(seed_ptr) }
    }

    #[test]
    fn derive_from_key() {
        let mut key = "012345678901234567890123456789++".to_owned().into_bytes();
        let mut pwd = "password".to_string().into_bytes();
        let mut pk = [0; 32];

        let seed_ptr = unsafe {
            curve25519_derive_from_key(
                NonNull::new_unchecked(key.as_mut_ptr()),
                key.len(),
                NonNull::new_unchecked(pwd.as_mut_ptr()),
                pwd.len(),
            )
        };

        let pub_key = unsafe { curve25519_to_public_key(seed_ptr.as_ref()) };
        unsafe {
            ed25519_public_key_to_bytes(pub_key.as_ref(), NonNull::new_unchecked(pk.as_mut_ptr()))
        };

        unsafe { curve25519_delete(seed_ptr) }
        unsafe { ed25519_delete_public(pub_key) }

        assert_eq!(
            pk,
            [
                146, 31, 81, 50, 192, 58, 254, 72, 124, 8, 213, 91, 64, 105, 28, 162, 249, 104,
                252, 230, 51, 45, 68, 8, 125, 187, 35, 18, 76, 138, 222, 22
            ]
        );
    }

    #[test]
    fn public_key() {
        let mut public = vec![0; 32];

        let mut rng = Rng::new([]);

        let key_ptr = unsafe { curve25519_generate(&mut rng) };

        let pub_key = unsafe { curve25519_to_public_key(key_ptr.as_ref()) };
        unsafe {
            ed25519_public_key_to_bytes(
                pub_key.as_ref(),
                NonNull::new_unchecked(public.as_mut_ptr()),
            )
        };

        unsafe { curve25519_delete(key_ptr) }
        unsafe { ed25519_delete_public(pub_key) }

        assert_ne!(public, vec![0; 32]);
    }
}
