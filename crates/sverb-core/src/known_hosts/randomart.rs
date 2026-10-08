//! The OpenSSH "drunken bishop" randomart (`sshkey_fingerprint_randomart` in
//! OpenSSH's `sshkey.c`), byte-identical to `ssh-keygen -lv -E sha256`.
//!
//! A bishop starts in the middle of a 17×9 field and makes four moves per digest byte
//! (two bits each, least significant first: bit 0 → x ±1, bit 1 → y ±1, clamped to the
//! field). Each visit raises the cell's count; counts map to ` .o+=*BOX@%&#/^`, the start
//! is `S` and the end `E`. The header is `[TYPE BITS]` (`[TYPE]` if that is too long),
//! the footer `[SHA256]`, both centered in the border.

/// Field width.
pub const FIELD_X: usize = 17;
/// Field height.
pub const FIELD_Y: usize = 9;

const SYMBOLS: &[u8] = b" .o+=*BOX@%&#/^SE";

/// Center `title` in a `+----+` border of the field's width.
fn border(title: &str) -> String {
    let len = title.chars().count();
    let left = FIELD_X.saturating_sub(len) / 2;
    let right = FIELD_X.saturating_sub(left + len);
    format!("+{}{title}{}+", "-".repeat(left), "-".repeat(right))
}

/// The randomart of a SHA-256 `digest` for a key shown as `key_type` (`ED25519`,
/// `RSA`, `ECDSA`, `ED25519-SK`, …) of `bits`. Lines are joined with `\n`, without a
/// trailing newline.
pub fn randomart(digest: &[u8], key_type: &str, bits: u32) -> String {
    let max = SYMBOLS.len() - 1; // 16: `E`
    let mut field = [[0_usize; FIELD_Y]; FIELD_X];
    let (mut x, mut y) = (FIELD_X / 2, FIELD_Y / 2);
    for byte in digest {
        let mut input = *byte;
        for _ in 0..4 {
            x = if input & 1 == 1 {
                (x + 1).min(FIELD_X - 1)
            } else {
                x.saturating_sub(1)
            };
            y = if input & 2 == 2 {
                (y + 1).min(FIELD_Y - 1)
            } else {
                y.saturating_sub(1)
            };
            if field[x][y] < max - 2 {
                field[x][y] += 1;
            }
            input >>= 2;
        }
    }
    field[FIELD_X / 2][FIELD_Y / 2] = max - 1;
    field[x][y] = max;

    // OpenSSH's title buffer holds FIELD_X bytes including the NUL: longer titles fall
    // back to `[TYPE]`, and whatever is left is cut to FIELD_X - 1 characters.
    let mut title = format!("[{key_type} {bits}]");
    if title.chars().count() > FIELD_X {
        title = format!("[{key_type}]");
    }
    let title: String = title.chars().take(FIELD_X - 1).collect();
    let mut lines = Vec::with_capacity(FIELD_Y + 2);
    lines.push(border(&title));
    for row in 0..FIELD_Y {
        let cells: String = (0..FIELD_X)
            .map(|col| char::from(SYMBOLS[field[col][row].min(max)]))
            .collect();
        lines.push(format!("|{cells}|"));
    }
    lines.push(border("[SHA256]"));
    lines.join("\n")
}
