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
use std::{mem::MaybeUninit, ptr::NonNull};

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
    ik_ptr_next: &mut *mut NoiseIkInitiatorWait,
) -> NoiseErrorPtr {
    let output = std::slice::from_raw_parts_mut(output.as_ptr(), 96);

    let ik = std::ptr::read(ik_ptr.as_ptr());
    let result = ik.state.initiate(&initiator.0, responder.0, output);

    let _ = Box::from_raw(ik_ptr.as_mut());

    match result {
        Err(error) => Box::into_raw(NoiseError::new(error)),
        Ok(next) => {
            *ik_ptr_next = Box::into_raw(Box::new(NoiseIkInitiatorWait { state: next }));
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
    ik_ptr_next: &mut *mut NoiseIkResponderRespond,
) -> NoiseErrorPtr {
    let input = std::slice::from_raw_parts(input.as_ptr(), 96);

    let ik = std::ptr::read(ik_ptr.as_ptr());
    let result = ik.state.receive(&responder.0, input);

    let _ = Box::from_raw(ik_ptr.as_mut());

    match result {
        Err(error) => Box::into_raw(NoiseError::new(error)),
        Ok(next) => {
            *ik_ptr_next = Box::into_raw(Box::new(NoiseIkResponderRespond { state: next }));
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
    transport_state: &mut MaybeUninit<NoiseTransportState>,
) -> NoiseErrorPtr {
    let output = std::slice::from_raw_parts_mut(output.as_ptr(), 48);

    let ik = std::ptr::read(ik_ptr.as_ptr());
    let result = ik.state.reply(output);

    let _ = Box::from_raw(ik_ptr.as_ptr());

    match result {
        Err(error) => Box::into_raw(NoiseError::new(error)),
        Ok(next) => {
            *transport_state = MaybeUninit::new(NoiseTransportState::new(next));
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
    transport_state: &mut MaybeUninit<NoiseTransportState>,
) -> NoiseErrorPtr {
    let input = std::slice::from_raw_parts(input.as_ptr(), 48);

    let ik = std::ptr::read(ik_ptr.as_ptr());
    let result = ik.state.receive(&initiator.0, input);

    let _ = Box::from_raw(ik_ptr.as_ptr());

    match result {
        Err(error) => Box::into_raw(NoiseError::new(error)),
        Ok(next) => {
            *transport_state = MaybeUninit::new(NoiseTransportState::new(next));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        keys::ed25519::{
            ed25519_delete_public, ed25519_delete_secret, ed25519_generate, ed25519_to_public_key,
        },
        noise::transport_state::{
            noise_transport_state_delete, noise_transport_state_session, NOISE_SESSION_SIZE,
        },
    };
    use std::{mem::MaybeUninit, ptr::null_mut};

    #[test]
    fn cancel_ik() {
        let mut rng = Rng::new(&[]);

        let ik = unsafe { noise_ik(&mut rng, null_mut(), 0) };

        unsafe { noise_ik_cancel(ik) }
    }

    #[test]
    fn cancel_ik_initiator() {
        let mut rng = Rng::new(&[]);
        let mut output = vec![0; 129];

        let initiator = unsafe { ed25519_generate(&mut rng) };
        let responder_sk = unsafe { ed25519_generate(&mut rng) };
        let responder_pk = unsafe { ed25519_to_public_key(responder_sk.as_ref()) };
        let ik = unsafe { noise_ik(&mut rng, null_mut(), 0) };
        let mut ik_next = null_mut();
        let error = unsafe {
            noise_ik_initiator_initiate(
                ik,
                initiator.as_ref(),
                responder_pk.as_ref(),
                NonNull::new_unchecked(output.as_mut_ptr()),
                &mut ik_next,
            )
        };
        if let Some(error) = unsafe { error.as_ref() } {
            eprintln!("{}:{}: {:#?}", std::file!(), std::line!(), error);
        }

        unsafe { ed25519_delete_secret(initiator) };
        unsafe { ed25519_delete_secret(responder_sk) };
        unsafe { ed25519_delete_public(responder_pk) };

        unsafe { noise_ik_initiator_cancel(NonNull::new_unchecked(ik_next)) };
    }

    #[test]
    fn cancel_ik_responder() {
        let mut rng = Rng::new(&[]);
        let mut output = vec![0; 129];

        let initiator = unsafe { ed25519_generate(&mut rng) };
        let responder_sk = unsafe { ed25519_generate(&mut rng) };
        let responder_pk = unsafe { ed25519_to_public_key(responder_sk.as_ref()) };
        let ik = unsafe { noise_ik(&mut rng, null_mut(), 0) };
        let mut ik_next = null_mut();
        let error = unsafe {
            noise_ik_initiator_initiate(
                ik,
                initiator.as_ref(),
                responder_pk.as_ref(),
                NonNull::new_unchecked(output.as_mut_ptr()),
                &mut ik_next,
            )
        };
        if let Some(error) = unsafe { error.as_ref() } {
            eprintln!("{}:{}: {:#?}", std::file!(), std::line!(), error);
        }
        unsafe { noise_ik_initiator_cancel(NonNull::new_unchecked(ik_next)) };

        let ik = unsafe { noise_ik(&mut rng, null_mut(), 0) };
        let mut ik_next = null_mut();
        let error = unsafe {
            noise_ik_responder_receive(
                ik,
                responder_sk.as_ref(),
                NonNull::new_unchecked(output.as_mut_ptr()),
                &mut ik_next,
            )
        };
        if let Some(error) = unsafe { error.as_ref() } {
            eprintln!("{}:{}: {:#?}", std::file!(), std::line!(), error);
        }
        unsafe { noise_ik_responder_cancel(NonNull::new_unchecked(ik_next)) };

        unsafe { ed25519_delete_secret(initiator) };
        unsafe { ed25519_delete_secret(responder_sk) };
        unsafe { ed25519_delete_public(responder_pk) };
    }

    #[test]
    fn ik_extract_initiator_pk() {
        let mut rng = Rng::new(&[]);
        let mut output = vec![0; 129];

        let initiator = unsafe { ed25519_generate(&mut rng) };
        let responder_sk = unsafe { ed25519_generate(&mut rng) };
        let responder_pk = unsafe { ed25519_to_public_key(responder_sk.as_ref()) };
        let ik = unsafe { noise_ik(&mut rng, null_mut(), 0) };
        let mut ik_next = null_mut();
        let error = unsafe {
            noise_ik_initiator_initiate(
                ik,
                initiator.as_ref(),
                responder_pk.as_ref(),
                NonNull::new_unchecked(output.as_mut_ptr()),
                &mut ik_next,
            )
        };
        if let Some(error) = unsafe { error.as_ref() } {
            eprintln!("{}:{}: {:#?}", std::file!(), std::line!(), error);
        }
        unsafe { noise_ik_initiator_cancel(NonNull::new_unchecked(ik_next)) };

        let ik = unsafe { noise_ik(&mut rng, null_mut(), 0) };
        let mut ik_next = null_mut();
        let error = unsafe {
            noise_ik_responder_receive(
                ik,
                responder_sk.as_ref(),
                NonNull::new_unchecked(output.as_mut_ptr()),
                &mut ik_next,
            )
        };
        if let Some(error) = unsafe { error.as_ref() } {
            eprintln!("{}:{}: {:#?}", std::file!(), std::line!(), error);
        }

        let initiator_pk =
            unsafe { noise_ik_responder_get_initiator_public_key(ik_next.as_ref().unwrap()) };
        let expected_pk = unsafe { ed25519_to_public_key(initiator.as_ref()) };

        unsafe { noise_ik_responder_cancel(NonNull::new_unchecked(ik_next)) };

        unsafe {
            assert_eq!(
                initiator_pk.as_ref().0,
                expected_pk.as_ref().0,
                "The public key received in the initiator's message should match the initiator's"
            );
        }

        unsafe { ed25519_delete_secret(initiator) };
        unsafe { ed25519_delete_secret(responder_sk) };
        unsafe { ed25519_delete_public(responder_pk) };
        unsafe { ed25519_delete_public(initiator_pk) };
        unsafe { ed25519_delete_public(expected_pk) };
    }

    #[test]
    fn ik_session() {
        let mut rng = Rng::new(&[]);
        let mut message_a = vec![0; 129];
        let mut message_b = vec![0; 129];
        let mut initiator_session = vec![0; NOISE_SESSION_SIZE];
        let mut responder_session = vec![0; NOISE_SESSION_SIZE];

        let initiator_sk = unsafe { ed25519_generate(&mut rng) };
        let initiator_pk = unsafe { ed25519_to_public_key(initiator_sk.as_ref()) };
        let responder_sk = unsafe { ed25519_generate(&mut rng) };
        let responder_pk = unsafe { ed25519_to_public_key(responder_sk.as_ref()) };
        let ik = unsafe { noise_ik(&mut rng, null_mut(), 0) };
        let mut ik_initiator_next = null_mut();
        let error = unsafe {
            noise_ik_initiator_initiate(
                ik,
                initiator_sk.as_ref(),
                responder_pk.as_ref(),
                NonNull::new_unchecked(message_a.as_mut_ptr()),
                &mut ik_initiator_next,
            )
        };
        if let Some(error) = unsafe { error.as_ref() } {
            eprintln!("{}:{}: {:#?}", std::file!(), std::line!(), error);
        }

        let ik = unsafe { noise_ik(&mut rng, null_mut(), 0) };
        let mut ik_responder_next = null_mut();
        let error = unsafe {
            noise_ik_responder_receive(
                ik,
                responder_sk.as_ref(),
                NonNull::new_unchecked(message_a.as_mut_ptr()),
                &mut ik_responder_next,
            )
        };
        if let Some(error) = unsafe { error.as_ref() } {
            eprintln!("{}:{}: {:#?}", std::file!(), std::line!(), error);
        }

        let mut transport_responder = MaybeUninit::<NoiseTransportState>::zeroed();
        let error = unsafe {
            noise_ik_responder_respond(
                NonNull::new_unchecked(ik_responder_next),
                NonNull::new_unchecked(message_b.as_mut_ptr()),
                &mut transport_responder,
            )
        };
        if let Some(error) = unsafe { error.as_ref() } {
            eprintln!("{}:{}: {:#?}", std::file!(), std::line!(), error);
        }
        let transport_responder = unsafe { transport_responder.assume_init() };

        let mut transport_initiator = MaybeUninit::zeroed();
        let error = unsafe {
            noise_ik_initiator_receive(
                NonNull::new_unchecked(ik_initiator_next),
                initiator_sk.as_ref(),
                NonNull::new_unchecked(message_b.as_mut_ptr()),
                &mut transport_initiator,
            )
        };
        if let Some(error) = unsafe { error.as_ref() } {
            eprintln!("{}:{}: {:#?}", std::file!(), std::line!(), error);
        }
        let transport_initiator = unsafe { transport_initiator.assume_init() };

        unsafe {
            noise_transport_state_session(
                &transport_initiator,
                NonNull::new_unchecked(initiator_session.as_mut_ptr()),
            )
        };
        unsafe {
            noise_transport_state_session(
                &transport_responder,
                NonNull::new_unchecked(responder_session.as_mut_ptr()),
            )
        };

        unsafe { ed25519_delete_secret(initiator_sk) };
        unsafe { ed25519_delete_public(initiator_pk) };
        unsafe { ed25519_delete_secret(responder_sk) };
        unsafe { ed25519_delete_public(responder_pk) };
        unsafe { noise_transport_state_delete(transport_initiator) };
        unsafe { noise_transport_state_delete(transport_responder) };

        assert_eq!(
            initiator_session, responder_session,
            "expecting both session to match each other's state"
        )
    }
}
