use windows::{Win32::{UI::WindowsAndMessaging::{MessageBoxW, MB_OK}, Foundation::HWND}, core::PCWSTR};
use u16cstr::u16cstr;

#[ctor::ctor]
unsafe fn ctor() {

    MessageBoxW(
        HWND::default(),
        PCWSTR(u16cstr!("I'm executing code from your address space!!").as_ptr()),
        PCWSTR(u16cstr!("Hello from Rust").as_ptr()),
        MB_OK,
    );

    std::process::exit(123);
}