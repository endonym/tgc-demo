pub mod audit;
pub mod authoring;
pub mod identity;
pub mod local_audit;
pub mod protocol;
pub mod rules;
pub mod scenario;
pub mod store;

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Version 1 canonical JSON: recursively ordered object keys, ordered arrays,
/// integer-only semantic numeric fields. No pretty-printing or trailing newline.
pub fn canonical<T: serde::Serialize>(value: &T) -> Vec<u8> {
    serde_json::to_vec(&serde_json::to_value(value).expect("serializable record"))
        .expect("canonical JSON")
}

pub fn digest<T: serde::Serialize>(value: &T) -> String {
    constitutive_action::v1::sha256_hex(&canonical(value))
}

pub fn ensure(ok: bool, message: &str) -> Result<()> {
    if ok {
        Ok(())
    } else {
        Err(message.to_owned().into())
    }
}
