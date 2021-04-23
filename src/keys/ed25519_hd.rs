use crate::{
    keys::ed25519::{
        ed25519_delete_public, Ed25519PublicKey, Ed25519PublicKeyPtr, Ed25519Signature,
        Ed25519SignaturePtr,
    },
    rng::Rng,
};
use keynesis::key::ed25519_hd;
use std::ptr::NonNull;

/// An Ed25519Hd secret key
///
/// Allow for hierarchical deterministic derivation
pub struct Ed25519HdSecretKey(ed25519_hd::SecretKey);

pub struct Ed25519HdChainCode(ed25519_hd::ChainCode);

/// convenient alias for non null pointer
///
/// Don't forget to release the allocated resource with [`ed25519_hd_delete_secret`].
pub type Ed25519HdSecretKeyPtr = NonNull<Ed25519HdSecretKey>;

/// convenient alias for non null pointer
///
/// Don't forget to release the allocated resource with [`ed25519_hd_delete_chain_code`].
pub type Ed25519HdChainCodePtr = NonNull<Ed25519HdChainCode>;

/// Ed25519HdPublicKey are composed of a [`Ed25519PublicKey`] and a [`Ed25519HdChainCode`]
///
/// Don't forget to release the allocated resource with [`ed25519_hd_delete_chain_code`]
/// or to release the individual components with the appropriate function.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Ed25519HdPublicKey {
    pub public_key: Ed25519PublicKeyPtr,
    pub chain_code: Ed25519HdChainCodePtr,
}

/// Generate a new [`Ed25519HdSecretKey`] from the given [`Rng`]
///
/// Don't forget to release the resource with [`ed25519_hd_delete_secret`]
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_hd_generate(rng: &mut Rng) -> Ed25519HdSecretKeyPtr {
    let ptr = Box::into_raw(Box::new(Ed25519HdSecretKey(ed25519_hd::SecretKey::new(
        rng.rng(),
    ))));

    NonNull::new_unchecked(ptr)
}

/// retrieve the [`Ed25519HdSecretKey`] from the given key and password
///
/// This function may be rather long to execute as it performs multiple
/// PBKDF2 iterations.
///
/// The key should not be less than 32 bytes. However it is possible to use
/// an empty password.
///
/// Don't forget to release the resource with [`ed25519_hd_delete_secret`]
///
/// # Safety
///
/// `key` and `password` must be valid for reads. Even if the effective `_size`
/// is `0`, the pointers must be non-NULL and properly aligned.
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_hd_derive_from_key(
    key: NonNull<u8>,
    key_size: usize,
    password: NonNull<u8>,
    password_size: usize,
) -> Ed25519HdSecretKeyPtr {
    let key = std::slice::from_raw_parts(key.as_ptr(), key_size);
    let password = std::slice::from_raw_parts(password.as_ptr(), password_size);

    let seed = keynesis::Seed::derive_from_key(key, password);
    let key = ed25519_hd::SecretKey::new(seed.into_rand_chacha());

    let ptr = Box::into_raw(Box::new(Ed25519HdSecretKey(key)));

    NonNull::new_unchecked(ptr)
}

/// Derive a new Secret key from a parent key and a derivation path.
///
/// # Safety
///
/// [`path`] and [`path_size`] needs to coincide
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_hd_derive(
    root: &Ed25519HdSecretKey,
    path: NonNull<u8>,
    path_size: usize,
) -> Ed25519HdSecretKeyPtr {
    let path = std::slice::from_raw_parts(path.as_ptr(), path_size);

    let secret_key = root.0.derive(path);
    let key = Ed25519HdSecretKey(secret_key);

    let ptr = Box::into_raw(Box::new(key));

    NonNull::new_unchecked(ptr)
}

/// Derive a new Public key from a parent key and a derivation path.
///
/// # Safety
///
/// [`path`] and [`path_size`] needs to coincide
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_hd_derive_public(
    root: Ed25519HdPublicKey,
    path: NonNull<u8>,
    path_size: usize,
) -> Ed25519HdPublicKey {
    let path = std::slice::from_raw_parts(path.as_ptr(), path_size);

    let public_key =
        ed25519_hd::PublicKey::from_parts(root.public_key.as_ref().0, root.chain_code.as_ref().0);

    if let Some(pk) = public_key.derive(path) {
        let chain_code = {
            let chain_code = *pk.chain_code();

            let ptr = Box::into_raw(Box::new(Ed25519HdChainCode(chain_code)));
            NonNull::new_unchecked(ptr)
        };
        let public_key = Ed25519PublicKey::new(*pk.key());

        Ed25519HdPublicKey {
            public_key,
            chain_code,
        }
    } else {
        Ed25519HdPublicKey {
            public_key: NonNull::new_unchecked(std::ptr::null_mut()),
            chain_code: NonNull::new_unchecked(std::ptr::null_mut()),
        }
    }
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
pub unsafe extern "C" fn ed25519_hd_to_public_key(key: &Ed25519HdSecretKey) -> Ed25519HdPublicKey {
    let pk = key.0.public_key();

    let chain_code = {
        let chain_code = *pk.chain_code();

        let ptr = Box::into_raw(Box::new(Ed25519HdChainCode(chain_code)));
        NonNull::new_unchecked(ptr)
    };
    let public_key = {
        let public_key = *pk.key();

        let ptr = Box::into_raw(Box::new(Ed25519PublicKey(public_key)));
        NonNull::new_unchecked(ptr)
    };

    Ed25519HdPublicKey {
        public_key,
        chain_code,
    }
}

/// generate the signature with the given [`Ed25519HdSecretKey`] and the given [`data`]
///
/// Don't forget to release the [`Ed25519Signature`] with [`ed25519_delete_signature`].
///
/// # Safety
///
/// Expect the data starting from pointer `data` to `data + data_size` to be
/// valid to read from.
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_hd_sign(
    key: &Ed25519HdSecretKey,
    data: NonNull<u8>,
    data_size: usize,
) -> Ed25519SignaturePtr {
    let data = std::slice::from_raw_parts(data.as_ptr(), data_size);

    let signature = Ed25519Signature(key.0.sign(data));

    let ptr = Box::into_raw(Box::new(signature));

    NonNull::new_unchecked(ptr)
}

/// Drop the [`Ed25519HdSecretKey`] and release the resource.
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_hd_delete_secret(key: Ed25519HdSecretKeyPtr) {
    let _ = Box::from_raw(key.as_ptr());
}

/// Drop the [`Ed25519HdChainCode`] and release the resource.
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_hd_delete_chain_code(chain_code: Ed25519HdChainCodePtr) {
    let _ = Box::from_raw(chain_code.as_ptr());
}

/// Drop the [`Ed25519HdPublicKey`] and release the resource.
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn ed25519_hd_delete_public(key: Ed25519HdPublicKey) {
    ed25519_delete_public(key.public_key);
    ed25519_hd_delete_chain_code(key.chain_code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ed25519::{
        ed25519_delete_signature, ed25519_public_key_to_bytes, ed25519_verify,
    };

    #[test]
    #[ignore = "We don't have a way to actually show attempting to delete a null pointer will raise a SIGILL"]
    fn delete_null() {
        let key_ptr = unsafe { NonNull::new_unchecked(std::ptr::null_mut()) };

        unsafe { ed25519_hd_delete_secret(key_ptr) }
    }

    #[test]
    fn derive() {
        let mut path = "derivation path".to_owned().into_bytes();
        let mut child_pk = [0; 32];
        let mut derived_pk = [0; 32];

        let mut rng = Rng::new([]);
        let root_sec = unsafe { ed25519_hd_generate(&mut rng) };
        let root_pub = unsafe { ed25519_hd_to_public_key(root_sec.as_ref()) };
        let child_sec = unsafe {
            ed25519_hd_derive(
                root_sec.as_ref(),
                NonNull::new_unchecked(path.as_mut_ptr()),
                path.len(),
            )
        };
        let child_pub = unsafe { ed25519_hd_to_public_key(child_sec.as_ref()) };
        let derived_pub = unsafe {
            ed25519_hd_derive_public(
                root_pub,
                NonNull::new_unchecked(path.as_mut_ptr()),
                path.len(),
            )
        };
        unsafe {
            ed25519_public_key_to_bytes(
                child_pub.public_key.as_ref(),
                NonNull::new_unchecked(child_pk.as_mut_ptr()),
            );
        }
        unsafe {
            ed25519_public_key_to_bytes(
                derived_pub.public_key.as_ref(),
                NonNull::new_unchecked(derived_pk.as_mut_ptr()),
            );
        }

        unsafe { ed25519_hd_delete_secret(root_sec) };
        unsafe { ed25519_hd_delete_public(root_pub) };
        unsafe { ed25519_hd_delete_secret(child_sec) };
        unsafe { ed25519_hd_delete_public(child_pub) };
        unsafe { ed25519_hd_delete_public(derived_pub) };

        assert_eq!(
            derived_pk, child_pk,
            "expect Pk(Hd(root_sec, path)) == Hd(root_pub)"
        );
    }

    #[test]
    fn sign() {
        let mut data = vec![0x8F; 12];

        let mut rng = Rng::new([]);
        let sec_key = unsafe { ed25519_hd_generate(&mut rng) };
        let pub_key = unsafe { ed25519_hd_to_public_key(sec_key.as_ref()) };

        let signature = unsafe {
            ed25519_hd_sign(
                sec_key.as_ref(),
                NonNull::new_unchecked(data.as_mut_ptr()),
                data.len(),
            )
        };

        let verified = unsafe {
            ed25519_verify(
                pub_key.public_key.as_ref(),
                signature.as_ref(),
                NonNull::new_unchecked(data.as_mut_ptr()),
                data.len(),
            )
        };

        unsafe { ed25519_hd_delete_secret(sec_key) };
        unsafe { ed25519_hd_delete_public(pub_key) };
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
            ed25519_hd_derive_from_key(
                NonNull::new_unchecked(key.as_mut_ptr()),
                key.len(),
                NonNull::new_unchecked(pwd.as_mut_ptr()),
                pwd.len(),
            )
        };

        unsafe { ed25519_hd_delete_secret(seed_ptr) }
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "It is highly unsafe to use key with less than 32bytes")]
    fn derive_from_small_key() {
        let mut key = vec![0; 30];
        let mut pwd = vec![];

        let seed_ptr = unsafe {
            ed25519_hd_derive_from_key(
                NonNull::new_unchecked(key.as_mut_ptr()),
                key.len(),
                NonNull::new_unchecked(pwd.as_mut_ptr()),
                pwd.len(),
            )
        };

        unsafe { ed25519_hd_delete_secret(seed_ptr) }
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn derive_from_small_key() {
        let mut key = vec![0; 30];
        let mut pwd = vec![];

        let seed_ptr = unsafe {
            ed25519_hd_derive_from_key(
                NonNull::new_unchecked(key.as_mut_ptr()),
                key.len(),
                NonNull::new_unchecked(pwd.as_mut_ptr()),
                pwd.len(),
            )
        };

        unsafe { ed25519_hd_delete_secret(seed_ptr) }
    }

    #[test]
    fn derive_from_key() {
        let mut key = "012345678901234567890123456789++".to_owned().into_bytes();
        let mut pwd = "password".to_string().into_bytes();
        let mut pk = [0; 32];

        let sec_key = unsafe {
            ed25519_hd_derive_from_key(
                NonNull::new_unchecked(key.as_mut_ptr()),
                key.len(),
                NonNull::new_unchecked(pwd.as_mut_ptr()),
                pwd.len(),
            )
        };

        let pub_key = unsafe { ed25519_hd_to_public_key(sec_key.as_ref()) };
        unsafe {
            ed25519_public_key_to_bytes(
                pub_key.public_key.as_ref(),
                NonNull::new_unchecked(pk.as_mut_ptr()),
            );
        }

        unsafe { ed25519_hd_delete_secret(sec_key) }
        unsafe { ed25519_hd_delete_public(pub_key) }

        assert_eq!(
            pk,
            [
                173, 76, 24, 245, 224, 113, 78, 89, 210, 27, 97, 237, 37, 208, 87, 226, 122, 126,
                204, 179, 26, 213, 64, 150, 202, 159, 85, 66, 91, 129, 232, 55
            ],
        );
    }

    #[test]
    fn public_key() {
        let mut public = vec![0; 32];

        let mut rng = Rng::new([]);

        let sec_key = unsafe { ed25519_hd_generate(&mut rng) };

        let pub_key = unsafe { ed25519_hd_to_public_key(sec_key.as_ref()) };
        unsafe {
            ed25519_public_key_to_bytes(
                pub_key.public_key.as_ref(),
                NonNull::new_unchecked(public.as_mut_ptr()),
            );
        }

        unsafe { ed25519_hd_delete_secret(sec_key) }
        unsafe { ed25519_hd_delete_public(pub_key) }

        assert_ne!(public, vec![0; 32]);
    }
}
