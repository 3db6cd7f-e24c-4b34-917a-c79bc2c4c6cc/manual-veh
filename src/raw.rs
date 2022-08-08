// Imports
use crate::{raw_offset::RawOffset, PVectoredExceptionHandler};
use once_cell::race::OnceBox;
use std::ffi::{c_void, OsString};
use std::os::windows::ffi::OsStringExt;
use winapi::um::winnt::LONG;

// Architecture-specific imports
#[cfg(target_pointer_width = "32")]
use pelite::pe32::{exports::GetProcAddress, PeView};
#[cfg(target_pointer_width = "64")]
use pelite::pe64::{exports::GetProcAddress, PeView};

// Type aliases
type FnRtlpAddVectoredHandler = unsafe extern "fastcall" fn(
    FirstHandler: LONG,
    VectoredHandler: PVectoredExceptionHandler,
    handler_type: LONG,
) -> *const c_void;
type FnRtlpRemoveVectoredHandler = unsafe extern "fastcall" fn(
    VectoredHandlerHandle: *const c_void,
    handler_type: LONG,
) -> *const c_void;

// Structs
#[repr(C)]
struct UNICODE_STRING {
    bytes_length: u16,
    bytes_max_length: u16,
    buffer: *const u16,
}

struct VectoredHandlers {
    add: FnRtlpAddVectoredHandler,
    remove: FnRtlpRemoveVectoredHandler,
}

unsafe fn get_module_handle<T: AsRef<str>>(name: T) -> Option<*const u8> {
    #[cfg(target_pointer_width = "32")]
    static ARCH_PTR_SIZE: usize = 4;
    #[cfg(target_pointer_width = "64")]
    static ARCH_PTR_SIZE: usize = 8;

    // Make the name uppercase to make this function case insensitive
    let target_name = name.as_ref().to_uppercase();

    // Get PEB
    let peb: *const u8;

    #[cfg(target_pointer_width = "32")]
    let list_base = {
        std::arch::asm!("mov {}, fs:[30h]", out(reg) peb);

        // PEB
        let x = peb;
        // Ldr
        let x = *(x.add(0x0C) as *const *const u8);
        // InInitializationOrderModuleList
        x.add(0x1C) as *const u8
    };

    #[cfg(target_pointer_width = "64")]
    let list_base = {
        std::arch::asm!("mov {}, gs:[60h]", out(reg) peb);

        // PEB
        let x = peb;
        // Ldr
        let x = *(x.add(0x18) as *const *const u8);
        // InInitializationOrderModuleList
        x.add(0x30) as *const u8
    };

    let mut current = list_base;
    loop {
        // Follow the link
        current = *(current as *const *const u8);

        // If we're back at the start, break out
        if std::ptr::eq(current, list_base) {
            break None;
        }

        // Get pointers to base addr + name
        // TODO: Create a struct of this - _LDR_MODULE
        let base_ptr = current.add(ARCH_PTR_SIZE * 2);
        let name_ptr = current.add((ARCH_PTR_SIZE * 5) + std::mem::size_of::<UNICODE_STRING>());

        // Try match the name against our target name
        if let Some(name) = (name_ptr as *const UNICODE_STRING).as_ref() {
            let name = std::slice::from_raw_parts(name.buffer, (name.bytes_length / 2) as _);
            let name = OsString::from_wide(name);
            let name = name.to_string_lossy().to_uppercase();

            if name == target_name {
                break Some(*(base_ptr as *const *const u8));
            }
        }
    }
}

static VECTORED_HANDLER: OnceBox<VectoredHandlers> = OnceBox::new();

#[inline(never)]
fn find_handlers() -> Box<VectoredHandlers> {
    unsafe {
        // We're using continue handlers as they're less likely to be hooked/modified
        // They're calling the same function as the exception handler funcs do
        const RAVCH: &str = "RtlAddVectoredContinueHandler";
        const RRVCH: &str = "RtlRemoveVectoredContinueHandler";

        get_module_handle("ntdll.dll")
            .map(|base| PeView::module(base))
            .and_then(|module| {
                unsafe fn get_wrapped_function<T>(wrapper: *const u8, size: usize) -> Option<T> {
                    // Create a window with the size of the pattern
                    // Enumerate so we can get where the pattern is found
                    // Filter on if current location matches the pattern
                    //   If it does
                    //     Read the `call` instruction's argument
                    //     Offset the current location by the argument (as calls are relative)
                    //     Skip until the end of the call instruction
                    // Map offset-into-function to a real pointer
                    // Transmute the pointer to a function
                    // Take the first match out of the iterator

                    #[cfg(target_pointer_width = "32")]
                    return std::slice::from_raw_parts(wrapper, size)
                        .windows(9)
                        .enumerate()
                        .filter_map(|(index, bytes)| match bytes {
                            &[0xE8, b1, b2, b3, b4, 0x5D, 0xC2, _, 0x00] => {
                                Some((i32::from_le_bytes([b1, b2, b3, b4])) + index as i32 + 5)
                            }
                            _ => None,
                        })
                        .map(|ravh| wrapper.raw_add(ravh as _))
                        .map(|ravh| std::mem::transmute_copy(&ravh))
                        .next();

                    #[cfg(target_pointer_width = "64")]
                    return std::slice::from_raw_parts(wrapper, size)
                        .windows(5)
                        .enumerate()
                        .filter_map(|(index, bytes)| match bytes {
                            &[0xE9, b1, b2, b3, b4] => {
                                Some((i32::from_le_bytes([b1, b2, b3, b4])) + index as i32 + 5)
                            }
                            _ => None,
                        })
                        .map(|ravh| wrapper.raw_add(ravh as _))
                        .map(|ravh| std::mem::transmute_copy(&ravh))
                        .next();
                }

                // Get the addresses of the exported functions we'll be reading from
                let ravch = module.get_proc_address(RAVCH).unwrap() as *const u8;
                let rrvch = module.get_proc_address(RRVCH).unwrap() as *const u8;

                // Get the wrapped function
                let ravch = get_wrapped_function(ravch, 0x50);
                let rrvch = get_wrapped_function(rrvch, 0x50);

                match (ravch, rrvch) {
                    (Some(ra), Some(rr)) => Some(VectoredHandlers {
                        add: ra,
                        remove: rr,
                    }),
                    _ => None,
                }
            })
            .unwrap()
            .into()
    }
}

pub unsafe fn add_vectored_exception_handler(
    first_handler: bool,
    vectored_handler: PVectoredExceptionHandler,
) -> *const c_void {
    (VECTORED_HANDLER.get_or_init(find_handlers).add)(first_handler as _, vectored_handler, 0)
}

pub unsafe fn remove_vectored_exception_handler(vectored_handler: *const c_void) -> *const c_void {
    (VECTORED_HANDLER.get_or_init(find_handlers).remove)(vectored_handler, 0)
}
