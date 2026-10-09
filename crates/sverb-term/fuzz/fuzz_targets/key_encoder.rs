//! Arbitrary key chords, modifiers and terminal modes never panic the key,
//! mouse or paste encoders.
//!
//!   cd crates/sverb-term/fuzz && cargo +nightly fuzz run key_encoder

#![no_main]

use libfuzzer_sys::fuzz_target;
use sverb_term::{
    KittyKeyboardFlags, MouseEncoding, MouseMode, TermModes,
    modes::input::{
        BackspaceMode, EncodeOpts, Key, KeyInput, KeyMods, KeypadKey, MouseAction, MouseButton,
        MouseInput, encode_key, encode_paste, route_mouse,
    },
};

fn key(tag: u8, arg: u32) -> Key {
    match tag % 18 {
        0 => Key::Char(char::from_u32(arg).unwrap_or('a')),
        1 => Key::Enter,
        2 => Key::Tab,
        3 => Key::Backspace,
        4 => Key::Esc,
        5 => Key::Up,
        6 => Key::Down,
        7 => Key::Left,
        8 => Key::Right,
        9 => Key::Home,
        10 => Key::End,
        11 => Key::Insert,
        12 => Key::Delete,
        13 => Key::PageUp,
        14 => Key::PageDown,
        15 => Key::F(arg as u8),
        16 => Key::Keypad(KeypadKey::Digit(arg as u8)),
        _ => Key::Keypad(KeypadKey::Enter),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 12 {
        return;
    }
    let arg = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
    let f = data[6];
    let modes = TermModes {
        app_cursor: f & 1 != 0,
        app_keypad: f & 2 != 0,
        bracketed_paste: f & 4 != 0,
        alt_screen: f & 8 != 0,
        line_feed_new_line: f & 16 != 0,
        modify_other_keys: data[7] % 4,
        kitty_keyboard: KittyKeyboardFlags(data[8]),
        mouse_mode: [MouseMode::None, MouseMode::Click, MouseMode::Drag, MouseMode::Motion]
            [usize::from(data[9] % 4)],
        mouse_encoding: [
            MouseEncoding::Default,
            MouseEncoding::Utf8,
            MouseEncoding::Sgr,
            MouseEncoding::Urxvt,
        ][usize::from(data[9] / 4 % 4)],
        ..TermModes::default()
    };
    let opts = EncodeOpts {
        backspace: if f & 32 != 0 { BackspaceMode::CtrlH } else { BackspaceMode::Del },
    };
    let mods = KeyMods::from_bits(data[1]);
    let _ = encode_key(KeyInput::new(key(data[0], arg), mods), &modes, &opts);
    let action = match data[10] % 8 {
        0 => MouseAction::Press(MouseButton::Left),
        1 => MouseAction::Release(MouseButton::Middle),
        2 => MouseAction::Drag(MouseButton::Right),
        3 => MouseAction::Move,
        4 => MouseAction::WheelUp,
        5 => MouseAction::WheelDown,
        6 => MouseAction::WheelLeft,
        _ => MouseAction::WheelRight,
    };
    let ev = MouseInput {
        action,
        col: u16::from_le_bytes([data[2], data[3]]),
        row: u16::from_le_bytes([data[4], data[5]]),
        mods,
    };
    let _ = route_mouse(&ev, &modes);
    let _ = encode_paste(&String::from_utf8_lossy(&data[11..]), &modes);
});
