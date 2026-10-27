//! Native Python access to authenticated local API key vaults.

use std::path::PathBuf;

use pyo3::{
    exceptions::{PyKeyError, PyOSError, PyRuntimeError, PyValueError},
    prelude::*,
    types::{PyBytes, PyString},
};
use secure_store_core::{Store as Vault, StoreError};

include!(concat!(env!("OUT_DIR"), "/embedded.rs"));

/// A native vault that decrypts individual values on demand.
#[derive(Debug)]
#[pyclass(name = "Store", module = "secure_store", frozen)]
struct PythonStore {
    inner: Vault,
}

#[pymethods]
impl PythonStore {
    #[new]
    fn new(py: Python<'_>, data: &[u8], password: &str) -> PyResult<Self> {
        py.detach(|| Vault::open(data, password.as_bytes()))
            .map(|inner| Self { inner })
            .map_err(|error| python_error(&error))
    }

    /// Read and authenticate an encrypted vault file.
    #[staticmethod]
    fn open(py: Python<'_>, path: PathBuf, password: &str) -> PyResult<Self> {
        py.detach(|| Vault::open_file(path, password.as_bytes()))
            .map(|inner| Self { inner })
            .map_err(|error| python_error(&error))
    }

    /// Open an application-build bundle or the vault compiled into this extension.
    #[staticmethod]
    fn embedded(py: Python<'_>) -> PyResult<Self> {
        let data = py.import("secure_store._embedded")?.getattr("DATA")?;
        let result = if data.is_none() {
            py.detach(embedded_store)
        } else {
            let data = data.cast::<PyBytes>()?.as_bytes();
            py.detach(|| Vault::open_embedded(data))
        };
        result
            .map(|inner| Self { inner })
            .map_err(|error| python_error(&error))
    }

    /// Return one plaintext value. Python owns the returned string.
    fn get<'py>(&self, py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyString>> {
        let value = self.inner.get(name).map_err(|error| python_error(&error))?;
        Ok(PyString::new(py, &value))
    }

    fn __repr__(&self) -> String {
        format!("{:?}", self.inner)
    }
}

/// Encrypt dotenv text with a password. Return serialized vault bytes.
#[pyfunction]
fn seal<'py>(py: Python<'py>, dotenv: &str, password: &str) -> PyResult<Bound<'py, PyBytes>> {
    let data = py
        .detach(|| secure_store_core::seal_dotenv(dotenv, password.as_bytes()))
        .map_err(|error| python_error(&error))?;
    Ok(PyBytes::new(py, &data))
}

/// Encrypt a bounded dotenv file for the Python application build hook.
#[pyfunction(name = "_seal_embedded_file")]
fn seal_embedded_file<'py>(
    py: Python<'py>,
    path: PathBuf,
    password: &str,
) -> PyResult<Bound<'py, PyBytes>> {
    let data = py
        .detach(|| secure_store_core::seal_embedded_file(path, password.as_bytes()))
        .map_err(|error| python_error(&error))?;
    Ok(PyBytes::new(py, &data))
}

fn python_error(error: &StoreError) -> PyErr {
    match error {
        StoreError::NotFound => PyKeyError::new_err(error.to_string()),
        StoreError::Io(_) => PyOSError::new_err(error.to_string()),
        StoreError::NotEmbedded | StoreError::Random | StoreError::KeyDerivation => {
            PyRuntimeError::new_err(error.to_string())
        }
        StoreError::SizeLimit
        | StoreError::InvalidPassword
        | StoreError::InvalidEnv
        | StoreError::InvalidFormat
        | StoreError::Authentication => PyValueError::new_err(error.to_string()),
    }
}

/// Register the native Python interface.
#[pymodule(name = "_native", gil_used = false)]
fn native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PythonStore>()?;
    module.add_function(wrap_pyfunction!(seal, module)?)?;
    module.add_function(wrap_pyfunction!(seal_embedded_file, module)?)?;
    module.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
