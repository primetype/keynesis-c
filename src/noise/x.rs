use crate::{
    keys::ed25519::{Ed25519PublicKey, Ed25519PublicKeyPtr, Ed25519SecretKey},
    noise::{NoiseError, NoiseErrorPtr},
    rng::Rng,
};
use keynesis::{hash::Blake2b, key::ed25519::SecretKey, noise::X};
use std::ptr::NonNull;

pub struct NoiseX {
    state: X<SecretKey, Blake2b, Rng>,
}

pub type NoiseXPtr = NonNull<NoiseX>;

/// create a [`NoiseX`] object that can be used on send a message to a sender
///
/// * if `prologue` is not null, it needs to be `prologue_size` bytes long
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn noise_x(
    rng: &mut Rng,
    prologue: *mut u8,
    prologue_size: usize,
) -> NoiseXPtr {
    let prologue = if let Some(prologue) = NonNull::new(prologue) {
        std::slice::from_raw_parts(prologue.as_ref(), prologue_size)
    } else {
        &[]
    };

    let state = X::<SecretKey, Blake2b, _>::new(rng.derive_rng(), prologue);

    let ptr = Box::into_raw(Box::new(NoiseX { state }));

    NonNull::new_unchecked(ptr)
}

/// **CONSUME** the [`NoiseX`] object that will be used to send a message
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
pub unsafe extern "C" fn noise_x_send(
    mut x_ptr: NoiseXPtr,
    sender: &Ed25519SecretKey,
    recipient: &Ed25519PublicKey,
    message: NonNull<u8>,
    message_size: usize,
    output: NonNull<u8>,
) -> NoiseErrorPtr {
    let message = std::slice::from_raw_parts(message.as_ref(), message_size);
    let output = std::slice::from_raw_parts_mut(output.as_ptr(), message_size + 16);

    let x = std::ptr::read(x_ptr.as_ptr());
    let result = x.state.send(&sender.0, &recipient.0, message, output);

    let _ = Box::from_raw(x_ptr.as_mut());

    if let Err(error) = result {
        Box::into_raw(NoiseError::new(error))
    } else {
        std::ptr::null_mut()
    }
}

/// **CONSUME** the [`NoiseX`] object that will be used to receive a message
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
/// * memory `message` to `message + message_size` needs to be valid to read
/// * memory `output` to `output + message_size - 16` needs to be valid to write
/// * sender is a pointer that will be allocated and filled with the public key
///   of the sender.
///
#[no_mangle]
pub unsafe extern "C" fn noise_x_receive(
    mut x_ptr: NoiseXPtr,
    recipient: &Ed25519SecretKey,
    message: NonNull<u8>,
    message_size: usize,
    output: NonNull<u8>,
    sender: &mut Ed25519PublicKeyPtr,
) -> NoiseErrorPtr {
    let message = std::slice::from_raw_parts(message.as_ref(), message_size);
    let output = std::slice::from_raw_parts_mut(output.as_ptr(), message_size - 16);

    let x = std::ptr::read(x_ptr.as_ptr());
    let result = x.state.receive(&recipient.0, message);

    let _ = Box::from_raw(x_ptr.as_mut());

    match result {
        Err(error) => Box::into_raw(NoiseError::new(error)),
        Ok((pk, mut decoded)) => {
            output.copy_from_slice(decoded.as_ref());
            keynesis::memsec::memset(decoded.as_mut_ptr(), 0x8F, decoded.len());

            *sender = NonNull::new_unchecked(Box::into_raw(Box::new(Ed25519PublicKey(pk))));

            std::ptr::null_mut()
        }
    }
}

/// **DROP** the [`NoiseX`] and release the resources
///
/// Use this function if you do not need to [`noise_x_send`] or [`noise_x_receive`]
/// anymore and you simply need to cancel
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn noise_x_cancel(mut x_ptr: NoiseXPtr) {
    let _ = Box::from_raw(x_ptr.as_mut());
}
