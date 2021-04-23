use keynesis::{
    hash::Blake2b,
    noise::{TransportReceiveHalf, TransportSendHalf, TransportState},
};
use std::ptr::NonNull;

use crate::{
    keys::ed25519::{Ed25519PublicKey, Ed25519PublicKeyPtr},
    noise::{NoiseCipherError, NoiseCipherErrorPtr},
};

/// you can either chose to keep them together or split the state
/// and manipulate each independently.
#[repr(C)]
pub struct NoiseTransportState {
    pub sender: NoiseTransportSendHalfPtr,
    pub receiver: NoiseTransportReceiveHalfPtr,
}
pub struct NoiseTransportSendHalf {
    state: TransportSendHalf<Blake2b>,
}
pub struct NoiseTransportReceiveHalf {
    state: TransportReceiveHalf<Blake2b>,
}
pub type NoiseTransportSendHalfPtr = NonNull<NoiseTransportSendHalf>;
pub type NoiseTransportReceiveHalfPtr = NonNull<NoiseTransportReceiveHalf>;

impl NoiseTransportState {
    pub(crate) fn new(state: TransportState<Blake2b>) -> NoiseTransportState {
        let (sender, receiver) = state.split();
        let sender = unsafe {
            NonNull::new_unchecked(Box::into_raw(Box::new(NoiseTransportSendHalf {
                state: sender,
            })))
        };
        let receiver = unsafe {
            NonNull::new_unchecked(Box::into_raw(Box::new(NoiseTransportReceiveHalf {
                state: receiver,
            })))
        };
        Self { sender, receiver }
    }
}

/// Get the 64 bytes of the Noise session
///
/// This value is unique per established sessions
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn noise_transport_state_session(
    transport_state: &NoiseTransportState,
    session: NonNull<u8>,
) {
    let session = std::slice::from_raw_parts_mut(session.as_ptr(), 64);

    session.copy_from_slice(transport_state.sender.as_ref().state.noise_session());
}

/// Send an encrypted message to the remote peer
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
/// * the output needs to be 16 bytes longer than the input
///
#[no_mangle]
pub unsafe extern "C" fn noise_transport_send(
    transport_state: &mut NoiseTransportSendHalf,
    input: NonNull<u8>,
    input_size: usize,
    output: NonNull<u8>,
) -> NoiseCipherErrorPtr {
    let input = std::slice::from_raw_parts(input.as_ptr(), input_size);
    let output = std::slice::from_raw_parts_mut(output.as_ptr(), input_size + 16);

    if let Err(error) = transport_state.state.send(input, output) {
        Box::into_raw(NoiseCipherError::new(error))
    } else {
        std::ptr::null_mut()
    }
}

/// Receive an encrypted message from the remote peer
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
/// * the output needs to be 16 bytes longer than the input
///
#[no_mangle]
pub unsafe extern "C" fn noise_transport_receive(
    transport_state: &mut NoiseTransportReceiveHalf,
    input: NonNull<u8>,
    input_size: usize,
    output: NonNull<u8>,
) -> NoiseCipherErrorPtr {
    let input = std::slice::from_raw_parts(input.as_ptr(), input_size);
    let output = std::slice::from_raw_parts_mut(output.as_ptr(), input_size);

    if let Err(error) = transport_state.state.receive(input, output) {
        Box::into_raw(NoiseCipherError::new(error))
    } else {
        std::ptr::null_mut()
    }
}

/// Get the 64 bytes of the Noise session
///
/// This value is unique per established sessions
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn noise_transport_sender_state_session(
    transport_state: &NoiseTransportSendHalf,
    session: NonNull<u8>,
) {
    let session = std::slice::from_raw_parts_mut(session.as_ptr(), 64);

    session.copy_from_slice(transport_state.state.noise_session());
}

/// Get the 64 bytes of the Noise session
///
/// This value is unique per established sessions
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn noise_transport_receiver_state_session(
    transport_state: &NoiseTransportSendHalf,
    session: NonNull<u8>,
) {
    let session = std::slice::from_raw_parts_mut(session.as_ptr(), 64);

    session.copy_from_slice(transport_state.state.noise_session());
}

/// Get the [`Ed25519PublicKey`] of the remote peer on this session
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn noise_transport_remote_public_key(
    transport_state: &NoiseTransportState,
) -> Ed25519PublicKeyPtr {
    Ed25519PublicKey::new(
        *transport_state
            .sender
            .as_ref()
            .state
            .remote_public_identity(),
    )
}

/// Get the [`Ed25519PublicKey`] of the remote peer on this session
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub extern "C" fn noise_transport_sender_remote_public_key(
    transport_state: &NoiseTransportSendHalf,
) -> Ed25519PublicKeyPtr {
    Ed25519PublicKey::new(*transport_state.state.remote_public_identity())
}

/// Get the [`Ed25519PublicKey`] of the remote peer on this session
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub extern "C" fn noise_transport_receiver_remote_public_key(
    transport_state: &NoiseTransportReceiveHalf,
) -> Ed25519PublicKeyPtr {
    Ed25519PublicKey::new(*transport_state.state.remote_public_identity())
}

/// **DROP** the [`NoiseTransportState`] and release the resources
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn noise_transport_state_delete(ts: NoiseTransportState) {
    let _ = Box::from_raw(ts.sender.as_ptr());
    let _ = Box::from_raw(ts.receiver.as_ptr());
}

/// **DROP** the [`NoiseTransportSendHalf`] and release the resources
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn noise_transport_sender_state_delete(ts: NoiseTransportSendHalfPtr) {
    let _ = Box::from_raw(ts.as_ptr());
}

/// **DROP** the [`NoiseTransportReceiveHalf`] and release the resources
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn noise_transport_receiver_state_delete(ts: NoiseTransportReceiveHalfPtr) {
    let _ = Box::from_raw(ts.as_ptr());
}
