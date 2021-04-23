use crate::{
    keys::ed25519::{Ed25519PublicKey, Ed25519SecretKey},
    noise::{NoiseError, NoiseErrorPtr},
    rng::Rng,
};
use keynesis::{hash::Blake2b, key::ed25519::SecretKey, noise::N};
use std::{convert::TryInto, ptr::NonNull};

pub struct NoiseN {
    state: N<SecretKey, Blake2b, Rng>,
}

pub type NoiseNPtr = NonNull<NoiseN>;

/// the extra length needed in the output when encrypting a message
///
/// i.e. to add as missing bytes of the message: `message.length + NOISE_N_METADATA_SIZE`
pub const NOISE_N_METADATA_SIZE: usize = 48;

/// create a [`NoiseN`] object that can be used on send a message to a sender
///
/// * if `psk0` is not null, it needs to be 32 bytes long
/// * if `prologue` is not null, it needs to be `prologue_size` bytes long
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn noise_n(
    rng: &mut Rng,
    psk0: *mut u8,
    prologue: *mut u8,
    prologue_size: usize,
) -> NoiseNPtr {
    let prologue = if let Some(prologue) = NonNull::new(prologue) {
        std::slice::from_raw_parts(prologue.as_ref(), prologue_size)
    } else {
        &[]
    };
    let psk0 = if let Some(psk0) = NonNull::new(psk0) {
        let psk0 = std::slice::from_raw_parts(psk0.as_ptr(), keynesis::Seed::SIZE);
        let psk0: [u8; keynesis::Seed::SIZE] = psk0.try_into().unwrap();
        Some(keynesis::Seed::from(psk0))
    } else {
        None
    };

    let state = N::<SecretKey, Blake2b, _>::new(rng.derive_rng(), &psk0, prologue);

    let ptr = Box::into_raw(Box::new(NoiseN { state }));

    NonNull::new_unchecked(ptr)
}

/// **CONSUME** the [`NoiseN`] object that will be used to send a message
/// to the given `recipient`.
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
/// * memory `message` to `message + message_size` needs to be valid to read
/// * memory `output` to `output + message_size + 16` needs to be valid to write
///
#[no_mangle]
pub unsafe extern "C" fn noise_n_send(
    mut n_ptr: NoiseNPtr,
    recipient: &Ed25519PublicKey,
    message: NonNull<u8>,
    message_size: usize,
    output: NonNull<u8>,
) -> NoiseErrorPtr {
    let message = std::slice::from_raw_parts(message.as_ref(), message_size);
    let output =
        std::slice::from_raw_parts_mut(output.as_ptr(), message_size + NOISE_N_METADATA_SIZE);

    let n = std::ptr::read(n_ptr.as_ptr());
    let result = n.state.send(&recipient.0, message, output);

    let _ = Box::from_raw(n_ptr.as_mut());

    if let Err(error) = result {
        Box::into_raw(NoiseError::new(error))
    } else {
        std::ptr::null_mut()
    }
}

/// **CONSUME** the [`NoiseN`] object that will be used to receive a message
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
/// * memory `message` to `message + message_size` needs to be valid to read
/// * memory `output` to `output + message_size - 16` needs to be valid to write
///
#[no_mangle]
pub unsafe extern "C" fn noise_n_receive(
    mut n_ptr: NoiseNPtr,
    recipient: &Ed25519SecretKey,
    message: NonNull<u8>,
    message_size: usize,
    output: NonNull<u8>,
) -> NoiseErrorPtr {
    let message = std::slice::from_raw_parts(message.as_ref(), message_size);
    let output =
        std::slice::from_raw_parts_mut(output.as_ptr(), message_size - NOISE_N_METADATA_SIZE);

    let n = std::ptr::read(n_ptr.as_ptr());
    let result = n.state.receive(&recipient.0, message);

    let _ = Box::from_raw(n_ptr.as_mut());

    match result {
        Err(error) => Box::into_raw(NoiseError::new(error)),
        Ok(mut decoded) => {
            output.copy_from_slice(decoded.as_ref());
            keynesis::memsec::memset(decoded.as_mut_ptr(), 0x8F, decoded.len());
            std::ptr::null_mut()
        }
    }
}

/// **DROP** the [`NoiseN`] and release the resources
///
/// Use this function if you do not need to [`noise_n_send`] or [`noise_n_receive`]
/// anymore and you simply need to cancel
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn noise_n_cancel(mut n_ptr: NoiseNPtr) {
    let _ = Box::from_raw(n_ptr.as_mut());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::ed25519::{
        ed25519_delete_public, ed25519_delete_secret, ed25519_generate, ed25519_to_public_key,
    };
    use std::ptr::null_mut;

    #[test]
    fn cancel_n() {
        let mut rng = Rng::new(&[]);

        let n = unsafe { noise_n(&mut rng, null_mut(), null_mut(), 0) };

        unsafe { noise_n_cancel(n) }
    }

    #[test]
    fn send_receive() {
        let mut rng = Rng::new(&[]);
        let mut message = b"message".to_vec();
        let mut encrypted = vec![0; message.len() + NOISE_N_METADATA_SIZE];
        let mut decrypted = vec![0; message.len()];

        let n = unsafe { noise_n(&mut rng, null_mut(), null_mut(), 0) };
        let receiver = unsafe { ed25519_generate(&mut rng) };
        let receiver_pk = unsafe { ed25519_to_public_key(receiver.as_ref()) };

        let error = unsafe {
            noise_n_send(
                n,
                receiver_pk.as_ref(),
                NonNull::new_unchecked(message.as_mut_ptr()),
                message.len(),
                NonNull::new_unchecked(encrypted.as_mut_ptr()),
            )
        };
        if let Some(error) = unsafe { error.as_ref() } {
            dbg!(error);
        }

        let n = unsafe { noise_n(&mut rng, null_mut(), null_mut(), 0) };
        let error = unsafe {
            noise_n_receive(
                n,
                receiver.as_ref(),
                NonNull::new_unchecked(encrypted.as_mut_ptr()),
                encrypted.len(),
                NonNull::new_unchecked(decrypted.as_mut_ptr()),
            )
        };
        if let Some(error) = unsafe { error.as_ref() } {
            dbg!(error);
        }

        unsafe { ed25519_delete_secret(receiver) };
        unsafe { ed25519_delete_public(receiver_pk) };

        assert_eq!(message, decrypted);
    }
}
