use anyhow::{Context as _, Result};
use rand_chacha::ChaChaRng;
use rand_core::{CryptoRng, OsRng, RngCore, SeedableRng};
use std::ptr::NonNull;

/// Random Number Generator
///
/// Underlying this is a ChaCha with 20 rounds. This will be used
/// in the library as a random number generator. You should only
/// need to generate it once and then destroy at the end of the
/// usage of this library.
///
/// Just make sure the raw seed you create this `Rng` with is securely
/// randomly generated (see: [`rng_from_raw_seed`]).
pub struct Rng(ChaChaRng);

/// a `NonNull` pointer for `Rng`. This is a handy alias that will be
/// used across the library's API to highlight what is expected and when.
///
/// This object is created by [`rng_from_raw_seed`] and deleted with
/// [`rng_delete`].
pub type RngPtr = NonNull<Rng>;

impl Rng {
    pub(crate) fn default() -> Result<Self> {
        let mut seed: <ChaChaRng as SeedableRng>::Seed = [0; 32];

        let mut os_rng = OsRng::default();
        os_rng
            .try_fill_bytes(&mut seed)
            .context("Cannot generate 32 bytes from the OS's RNG")?;

        let inner = ChaChaRng::from_seed(seed);
        Ok(Self(inner))
    }

    pub(crate) fn new(input_seed: impl AsRef<[u8]>) -> Self {
        let mut seed: <ChaChaRng as SeedableRng>::Seed = [0; 32];
        let len = std::cmp::min(input_seed.as_ref().len(), seed.len());
        seed[..len].copy_from_slice(&input_seed.as_ref()[..len]);

        let inner = ChaChaRng::from_seed(seed);
        Self(inner)
    }

    pub(crate) fn rng(&mut self) -> &mut ChaChaRng {
        &mut self.0
    }

    pub(crate) fn derive_rng(&mut self) -> Self {
        let mut seed: <ChaChaRng as SeedableRng>::Seed = [0; 32];
        self.0.fill_bytes(&mut seed);

        Self::new(seed)
    }
}

/// Generate a new [`Rng`] seeded from the System's RNG
///
/// Don't forget to free the resource once this is no longer needed. Though this should
/// only be needed when releasing the whole program: `rng_delete`.
///
/// This function returns a nullptr if the generation of the RNG failed
///
#[no_mangle]
pub extern "C" fn rng_from_os_rng() -> *mut Rng {
    match Rng::default() {
        Ok(rng) => Box::into_raw(Box::new(rng)),
        #[cfg(debug_assertions)]
        Err(error) => panic!("{:?}", error),
        #[cfg(not(debug_assertions))]
        Err(_error) => std::ptr::null_mut(),
    }
}

/// Seed a new RNG from the given raw part. Feed in any array of 0 to 32 bytes long
///
/// bytes beyond 32 will be ignored, bytes below 32 long will be assumed to be byte `0`
///
/// For example, if you feed an array say:
///
/// * [ 1, 2, 3 ] : [1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0 ..]
/// * [ 1, 2, .. 32, 33, 34, .. ] : [1, 2, .., 32 ]
///
/// Don't forget to free the resource once this is no longer needed. Though this should
/// only be needed when releasing the whole program: `rng_delete`.
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn rng_from_raw_seed(seed_ptr: NonNull<u8>, seed_size: usize) -> RngPtr {
    let input_seed = std::slice::from_raw_parts_mut(seed_ptr.as_ptr(), seed_size);
    let rng = Rng::new(input_seed);
    let ptr = Box::into_raw(Box::new(rng));

    // it is okay to use `new_unchecked` here because the pointer
    // has been created just above and there is no way it would
    // return a null pointer.
    NonNull::new_unchecked(ptr)
}

/// Drop the [Rng] and release the resource.
///
/// # Safety
///
/// This function dereference raw pointers. Even though
/// the function checks if the pointers are null. Mind not to put random values
/// in or you may see unexpected behaviors
///
#[no_mangle]
pub unsafe extern "C" fn rng_delete(seed: RngPtr) {
    let _ = Box::from_raw(seed.as_ptr());
}

impl RngCore for Rng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}
impl CryptoRng for Rng {}
