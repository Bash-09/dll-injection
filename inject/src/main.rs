use std::{env::Args, ffi::c_void, path::PathBuf};

use color_eyre::{Report, eyre::eyre};
use widestring::{U16CString, U16CStr, u16cstr};
use windows::{Win32::{UI::WindowsAndMessaging::{MessageBoxW, MESSAGEBOX_STYLE}, Foundation::{HWND, HANDLE}, System::{Threading::{QueryFullProcessImageNameW, PROCESS_NAME_NATIVE, PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_INFORMATION, OpenProcess, PROCESS_CREATE_THREAD, PROCESS_VM_READ, PROCESS_VM_WRITE, PROCESS_VM_OPERATION, CreateRemoteThread}, Memory::{MEM_COMMIT, PAGE_EXECUTE_READWRITE, VirtualAllocEx}, Diagnostics::Debug::WriteProcessMemory, LibraryLoader::{GetModuleHandleW, GetProcAddress}}}, core::{PCWSTR, PWSTR, PCSTR}};

type ThreadEntry = unsafe extern "system" fn(lpthreadparameter: *mut c_void) -> u32;

fn main() -> Result<(), Report> {
    // Get process and stuff
    let pid: u32 = std::env::args().nth(1).expect("No pid provided").parse().expect("Invalid pid");
    println!("Targetting process with pid {}", pid);

    let handle = open_process(pid)?;
    println!("Process: {}", query_full_process_image_name(handle)?);

    // Get dll path
    let dll_path = PathBuf::from("../injected/target/debug/injected.dll").canonicalize()?;
    let dll_path = U16CString::from_os_str(dll_path)?;

    // Allocate memory and get addresses
    let target_mem = virtual_alloc_ex(handle, 2048);
    if target_mem.is_null() {
        return Err(eyre!("Couldn't alloc memory."));
    }

    // Write dll path to memory
    let written = unsafe{ write_process_memory_raw(handle, target_mem, dll_path.as_ptr() as *const _, (dll_path.len() + 1) * std::mem::size_of::<u16>()).ok_or(eyre!("Couldn't write mem"))? };
    assert!(written > 0);

    // Get pointer to load library function
    let addr_load_library_w = get_proc_address("kernel32.dll", "LoadLibraryW")? as *const ();
    println!("LoadLibraryW address: {addr_load_library_w:p}");

    // Start a new thread at the LoadLibraryW function and pass it the pointer to the dll location as a parameter
    let thread = create_remote_thread(handle, unsafe{std::mem::transmute(addr_load_library_w)}, Some(target_mem));
    println!("Started thread? {:?}", thread);

    Ok(())
}

fn get_proc_address(module_name: &str, proc_name: &str) -> Result<unsafe extern "system" fn() -> isize, Report> {
    let module_name = U16CString::from_str(module_name)?;
    let module = unsafe{ GetModuleHandleW(PCWSTR(module_name.as_ptr()))? };

    unsafe { GetProcAddress(module, PCSTR(format!("{proc_name}\0").as_ptr())).ok_or(eyre!("Could not find proc {proc_name}")) }
}

fn create_remote_thread(hprocess: HANDLE, lpstartaddress: *mut c_void, lpparameter: Option<*const c_void>) -> Result<HANDLE, windows::core::Error> {
    let lpthreadattributes = None;
    let dwstacksize = 0;
    let lpstartaddress: ThreadEntry = unsafe {std::mem::transmute(lpstartaddress)};
    let dwcreationflags = 0;
    let lpthreadid = None;
    unsafe {CreateRemoteThread(hprocess, lpthreadattributes, dwstacksize, Some(lpstartaddress), lpparameter, dwcreationflags, lpthreadid)}
}

unsafe fn write_process_memory_raw(hprocess: HANDLE, lp_base_address: *const c_void, data: *const u8, len: usize) -> Option<usize> {
    let lpbuffer = data;
    let nsize = len;
    let mut num_bytes_written = 0;
    return if WriteProcessMemory(hprocess, lp_base_address, lpbuffer as _, nsize, Some(&mut num_bytes_written)).as_bool() {
        Some(num_bytes_written)
    } else {
        None
    }
}

fn write_process_memory(hprocess: HANDLE, lp_base_address: *const c_void, data: &[u8]) -> Option<usize> {
    let lpbuffer = data.as_ptr();
    let nsize = data.len();
    let mut num_bytes_written = 0;
    return if unsafe {WriteProcessMemory(hprocess, lp_base_address, lpbuffer as _, nsize, Some(&mut num_bytes_written)).as_bool()} {
        Some(num_bytes_written)
    } else {
        None
    }
}

fn virtual_alloc_ex(hprocess: HANDLE, dwsize: usize) -> *mut c_void {
    let flallocation_type = MEM_COMMIT; // MEM_COMMIT
    let flprotect = PAGE_EXECUTE_READWRITE;

    unsafe {VirtualAllocEx(hprocess, None, dwsize, flallocation_type, flprotect)}
}

fn open_process(pid: u32) -> Result<HANDLE, Report> {
    let dw_desired_access = PROCESS_QUERY_INFORMATION 
        | PROCESS_CREATE_THREAD
        | PROCESS_VM_OPERATION
        | PROCESS_VM_READ
        | PROCESS_VM_WRITE;
    Ok(unsafe {OpenProcess(dw_desired_access, false, pid)?})
}

fn query_full_process_image_name(hprocess: HANDLE) -> Result<String, Report> {
    let mut buffer = [0u16; 16384];
    let mut buf_len = buffer.len() as u32;
    unsafe {QueryFullProcessImageNameW(hprocess, PROCESS_NAME_NATIVE, PWSTR(buffer.as_mut_ptr()), &mut buf_len).ok()?};
    let name = U16CStr::from_slice(&buffer[..buf_len as usize + 1])?.to_string()?;

    Ok(name)
}