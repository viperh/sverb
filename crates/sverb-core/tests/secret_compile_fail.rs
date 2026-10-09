//! `Secret` can't be cloned or serialized by accident.

#[test]
fn secret_misuse_does_not_compile() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/ui/secret_*.rs");
}
