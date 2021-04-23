use crate::{
    keys::ed25519::{Ed25519PublicKey, Ed25519PublicKeyPtr, Ed25519SecretKey},
    noise::{transport_state::NoiseTransportState, NoiseError, NoiseErrorPtr},
    rng::Rng,
};
use keynesis::{
    hash::Blake2b,
    key::ed25519::SecretKey,
    noise::{ik, IK},
};
use std::ptr::NonNull;

pub struct NoiseIk {
    state: IK<SecretKey, Blake2b, Rng, ik::A>,
}

pub struct NoiseIkInitiatorWait {
    state: IK<SecretKey, Blake2b, Rng, ik::WaitB>,
}

pub struct NoiseIkResponderRespond {
    state: IK<SecretKey, Blake2b, Rng, ik::SendB>,
}

pub type NoiseIkPtr = NonNull<NoiseIk>;
pub type NoiseIkInitiatorWaitPtr = NonNull<NoiseIkInitiatorWait>;
pub type NoiseIkResponderRespondPtr = NonNull<NoiseIkResponderRespond>;

/// create a [`NoiseIk`] object that can be used on send a message to a sender
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
pub unsafe extern "C" fn noise_ik(
    rng: &mut Rng,
    prologue: *mut u8,
    prologue_size: usize,
) -> NoiseIkPtr {
    let prologue = if let Some(prologue) = NonNull::new(prologue) {
        std::slice::from_raw_parts(prologue.as_ref(), prologue_size)
    } else {
        &[]
    };

    let state = IK::<SecretKey, Blake2b, _, _>::new(rng.derive_rng(), prologue);

    let ptr = Box::into_raw(Box::new(NoiseIk { state }));

    NonNull::new_unchecked(ptr)
}

/// **CONSUME** the [`NoiseIk`] object and initiate the [`IK`] handshake
/// between the `initiator` and the `responder`
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
/// * memory `output` to `output + 96` needs to be valid to write
///
#[no_mangle]
pub unsafe extern "C" fn noise_ik_initiator_initiate(
    mut ik_ptr: NoiseIkPtr,
    initiator: &Ed25519SecretKey,
    responder: &Ed25519PublicKey,
    output: NonNull<u8>,
    ik_ptr_next: &mut NoiseIkInitiatorWaitPtr,
) -> NoiseErrorPtr {
    let output = std::slice::from_raw_parts_mut(output.as_ptr(), 96);

    let ik = std::ptr::read(ik_ptr.as_ptr());
    let result = ik.state.initiate(&initiator.0, responder.0, output);

    let _ = Box::from_raw(ik_ptr.as_mut());

    match result {
        Err(error) => Box::into_raw(NoiseError::new(error)),
        Ok(next) => {
            *ik_ptr_next = NonNull::new_unchecked(Box::into_raw(Box::new(NoiseIkInitiatorWait {
                state: next,
            })));
            std::ptr::null_mut()
        }
    }
}

/// **CONSUME** the [`NoiseIk`] object and receive the initial message
/// of the [`IK`] handshake.
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
/// * memory `input` to `input + 96` needs to be valid to read
///
#[no_mangle]
pub unsafe extern "C" fn noise_ik_responder_receive(
    mut ik_ptr: NoiseIkPtr,
    responder: &Ed25519SecretKey,
    input: NonNull<u8>,
    ik_ptr_next: &mut NoiseIkResponderRespondPtr,
) -> NoiseErrorPtr {
    let input = std::slice::from_raw_parts(input.as_ptr(), 96);

    let ik = std::ptr::read(ik_ptr.as_ptr());
    let result = ik.state.receive(&responder.0, input);

    let _ = Box::from_raw(ik_ptr.as_mut());

    match result {
        Err(error) => Box::into_raw(NoiseError::new(error)),
        Ok(next) => {
            *ik_ptr_next =
                NonNull::new_unchecked(Box::into_raw(Box::new(NoiseIkResponderRespond {
                    state: next,
                })));
            std::ptr::null_mut()
        }
    }
}

/// Get the [`Ed25519PublicKey`] of the initiator from the responder's state
///
#[no_mangle]
pub extern "C" fn noise_ik_responder_get_initiator_public_key(
    ik_ptr: &NoiseIkResponderRespond,
) -> Ed25519PublicKeyPtr {
    let pk = *ik_ptr.state.remote_public_identity();
    Ed25519PublicKey::new(pk)
}

/// **CONSUME** the [`NoiseIk_Responder_RespondPtr`] object and generate the
/// reply from the responder to the initiator.
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn noise_ik_responder_respond(
    ik_ptr: NoiseIkResponderRespondPtr,
    output: NonNull<u8>,
    transport_state: &mut NoiseTransportState,
) -> NoiseErrorPtr {
    let output = std::slice::from_raw_parts_mut(output.as_ptr(), 48);

    let ik = std::ptr::read(ik_ptr.as_ptr());
    let result = ik.state.reply(output);

    let _ = Box::from_raw(ik_ptr.as_ptr());

    match result {
        Err(error) => Box::into_raw(NoiseError::new(error)),
        Ok(next) => {
            *transport_state = NoiseTransportState::new(next);
            std::ptr::null_mut()
        }
    }
}

/// **CONSUME** the [`NoiseIkInitiatorWaitPtr`] object and the given
/// reply and generate the the Transport State
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn noise_ik_initiator_receive(
    ik_ptr: NoiseIkInitiatorWaitPtr,
    initiator: &Ed25519SecretKey,
    input: NonNull<u8>,
    transport_state: &mut NoiseTransportState,
) -> NoiseErrorPtr {
    let input = std::slice::from_raw_parts(input.as_ptr(), 48);

    let ik = std::ptr::read(ik_ptr.as_ptr());
    let result = ik.state.receive(&initiator.0, input);

    let _ = Box::from_raw(ik_ptr.as_ptr());

    match result {
        Err(error) => Box::into_raw(NoiseError::new(error)),
        Ok(next) => {
            *transport_state = NoiseTransportState::new(next);
            std::ptr::null_mut()
        }
    }
}

/// **DROP** the [`NoiseIk`] and release the resources
///
/// Use this function if you do not need to [`noise_ik_initiator_initiate`] or [`noise_ik_responder_receive`]
/// anymore and you simply need to cancel
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn noise_ik_cancel(ik_ptr: NoiseIkPtr) {
    let _ = Box::from_raw(ik_ptr.as_ptr());
}

/// **DROP** the [`NoiseIkResponderRespond`] and release the resources
///
/// Use this function if you do not need to [`noise_ik_responder_respond`]
/// anymore and you simply need to cancel
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn noise_ik_responder_cancel(ik_ptr: NoiseIkResponderRespondPtr) {
    let _ = Box::from_raw(ik_ptr.as_ptr());
}

/// **DROP** the [`NoiseIkInitiatorWait`] and release the resources
///
/// Use this function if you do not need to [`noise_ik_initiator_receive`]
/// anymore and you simply need to cancel
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn noise_ik_initiator_cancel(ik_ptr: NoiseIkInitiatorWaitPtr) {
    let _ = Box::from_raw(ik_ptr.as_ptr());
}
