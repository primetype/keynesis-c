use keynesis::noise::{CipherStateError, HandshakeStateError};

pub mod ik;
pub mod n;
pub mod transport_state;
pub mod x;

/// the kind of error that may appear when performing a Noise handshake
#[derive(Debug)]
pub struct NoiseError {
    error: HandshakeStateError,
}

/// the kind of error that may appear when performing a Noise handshake
#[derive(Debug)]
pub struct NoiseCipherError {
    error: CipherStateError,
}

/// convenient type alias for pointer to NoiseErrorPtr
///
/// if nullptr, then it means there was no error.
/// use [`noise_error_delete`] once you need to release the resource
///
pub type NoiseErrorPtr = *mut NoiseError;

/// convenient type alias for pointer to [`NoiseCipherError`]
///
/// if nullptr, then it means there was no error.
/// use [`noise_cipher_error_delete`] once you need to release the resource
///
pub type NoiseCipherErrorPtr = *mut NoiseCipherError;

impl NoiseError {
    pub(crate) fn new(error: HandshakeStateError) -> Box<Self> {
        Box::new(Self { error })
    }
}

impl NoiseCipherError {
    pub(crate) fn new(error: CipherStateError) -> Box<Self> {
        Box::new(Self { error })
    }
}

/// **DROP** the [`NoiseErrorPtr`] and release the resources
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn noise_error_delete(n_ptr: NoiseErrorPtr) {
    if !n_ptr.is_null() {
        let _ = Box::from_raw(n_ptr);
    }
}

/// **DROP** the [`NoiseCipherErrorPtr`] and release the resources
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn noise_cipher_error_delete(n_ptr: NoiseCipherErrorPtr) {
    if !n_ptr.is_null() {
        let _ = Box::from_raw(n_ptr);
    }
}
