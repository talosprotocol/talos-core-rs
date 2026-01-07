use crate::adapters::crypto::RealCryptoProvider;
use crate::domain::wallet::Wallet;
use pyo3::prelude::*;

/// Python wrapper for Wallet.
#[pyclass(name = "Wallet")]
pub struct PyWallet {
    inner: Wallet,
}

#[pymethods]
impl PyWallet {
    #[staticmethod]
    #[pyo3(signature = (name=None))]
    fn generate(name: Option<String>) -> Self {
        let provider = RealCryptoProvider;
        Self {
            inner: Wallet::generate(name, &provider),
        }
    }

    #[staticmethod]
    #[pyo3(signature = (seed, name=None))]
    fn from_seed(seed: Vec<u8>, name: Option<String>) -> PyResult<Self> {
        if seed.len() != 32 {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "Seed must be 32 bytes, got {}",
                seed.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&seed);
        let provider = RealCryptoProvider;
        Ok(Self {
            inner: Wallet::from_seed(arr, name, &provider),
        })
    }

    fn to_did(&self) -> String {
        self.inner.to_did()
    }

    fn address(&self) -> String {
        let provider = RealCryptoProvider;
        self.inner.address(&provider)
    }

    fn sign(&self, message: Vec<u8>) -> Vec<u8> {
        let provider = RealCryptoProvider;
        self.inner.sign(&message, &provider).to_vec()
    }

    #[staticmethod]
    fn verify(message: Vec<u8>, signature: Vec<u8>, public_key: Vec<u8>) -> bool {
        if signature.len() != 64 || public_key.len() != 32 {
            return false;
        }
        let mut sig = [0u8; 64];
        let mut pk = [0u8; 32];
        sig.copy_from_slice(&signature);
        pk.copy_from_slice(&public_key);

        let provider = RealCryptoProvider;
        Wallet::verify(&message, &sig, &pk, &provider)
    }

    #[getter]
    fn public_key(&self) -> Vec<u8> {
        self.inner.public_key().to_vec()
    }

    #[getter]
    fn name(&self) -> Option<String> {
        self.inner.name().map(|s| s.to_string())
    }
}
