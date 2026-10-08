use sverb_core::secret::SecretString;

fn main() {
    let a = SecretString::from("a");
    let b = SecretString::from("b");
    let _same = a == b;
}
