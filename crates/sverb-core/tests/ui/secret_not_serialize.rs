use sverb_core::secret::SecretString;

fn main() {
    let secret = SecretString::from("hunter2");
    let _json = serde_json::to_string(&secret);
}
