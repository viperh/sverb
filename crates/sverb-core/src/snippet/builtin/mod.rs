//! M7-01: snippets that ship with sverb (SPEC §9.10 "install shell integration").
//!
//! They are not vault items until the user adds one (the autocomplete overlay offers
//! it): from then on they are ordinary snippets, run through the normal flow (the
//! variable form shows the rendered script as a preview; *Exec on hosts* runs it).

pub mod shell_integration;

#[cfg(test)]
mod tests;
