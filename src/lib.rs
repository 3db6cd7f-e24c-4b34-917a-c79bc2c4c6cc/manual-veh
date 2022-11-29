// Requirements
#![cfg(windows)]

// Modules
mod raw_offset;

// Public modules
pub mod raw;

// Imports
use crate::raw::{add_vectored_exception_handler, remove_vectored_exception_handler};
use std::{ffi::c_void, marker::PhantomData};

type RawExceptionHandler = unsafe extern "system" fn(*mut c_void) -> i32;

// This is essentially just a boolean with different names
#[repr(u8)]
pub enum Order {
    First = 1,
    Last = 0,
}

// Wrap the pointer/handle returned by `add_vectored_exception_handler`
pub struct Veh<T>(*const c_void, PhantomData<T>);

impl<T> Drop for Veh<T> {
    fn drop(&mut self) {
        unsafe { remove_vectored_exception_handler(self.0) };
    }
}

pub type VehVoid = Veh<c_void>;

#[cfg(feature = "impl-winapi")]
pub type VehWinapi = Veh<winapi::um::winnt::EXCEPTION_POINTERS>;

#[cfg(feature = "impl-windows")]
pub type VehWindows = Veh<windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS>;

impl<T> Veh<T> {
    /// # Safety
    /// The function passed as `handler` *must* be `unsafe extern "system" fn(*mut T) -> i32`,
    /// where T is a type that matches the Windows API's `EXCEPTION_POINTERS` type.
    ///
    /// This function will never directly cause undefined behaviour, but the handlers it registers
    /// might very well cause UB if they're not written correctly. Calling this function is
    /// therefore unsafe, as it might affect the program in unexpected ways if the caller doesn't
    /// properly handle exceptions it catches.
    ///
    /// This registers a function to be called when an exception occurs.
    /// Be sure that you know what you're doing, and know that a crash in an exception handler
    /// will trigger a new exception, calling the exception handler chain all over again.
    pub unsafe fn add_raw(order: Order, handler: usize) -> Self {
        Veh(raw_add(order, handler), PhantomData)
    }
}

impl Veh<c_void> {
    /// # Safety
    /// This function will never directly cause undefined behaviour, but the handlers it registers
    /// might very well cause UB if they're not written correctly. Calling this function is
    /// therefore unsafe, as it might affect the program in unexpected ways if the caller doesn't
    /// properly handle exceptions it catches.
    ///
    /// This registers a function to be called when an exception occurs.
    /// Be sure that you know what you're doing, and know that a crash in an exception handler
    /// will trigger a new exception, calling the exception handler chain all over again.
    pub unsafe fn add(
        order: Order,
        handler: unsafe extern "system" fn(*mut c_void) -> i32,
    ) -> Self {
        Veh(raw_add(order, handler as _), PhantomData)
    }
}

#[cfg(feature = "impl-winapi")]
impl VehWinapi {
    /// # Safety
    /// This function will never directly cause undefined behaviour, but the handlers it registers
    /// might very well cause UB if they're not written correctly. Calling this function is
    /// therefore unsafe, as it might affect the program in unexpected ways if the caller doesn't
    /// properly handle exceptions it catches.
    ///
    /// This registers a function to be called when an exception occurs.
    /// Be sure that you know what you're doing, and know that a crash in an exception handler
    /// will trigger a new exception, calling the exception handler chain all over again.
    pub unsafe fn add(
        order: Order,
        handler: unsafe extern "system" fn(*mut winapi::um::winnt::EXCEPTION_POINTERS) -> i32,
    ) -> Self {
        Veh(raw_add(order, handler as _), PhantomData)
    }
}

#[cfg(feature = "impl-windows")]
impl VehWindows {
    /// # Safety
    /// This function will never directly cause undefined behaviour, but the handlers it registers
    /// might very well cause UB if they're not written correctly. Calling this function is
    /// therefore unsafe, as it might affect the program in unexpected ways if the caller doesn't
    /// properly handle exceptions it catches.
    ///
    /// This registers a function to be called when an exception occurs.
    /// Be sure that you know what you're doing, and know that a crash in an exception handler
    /// will trigger a new exception, calling the exception handler chain all over again.
    pub unsafe fn add(
        order: Order,
        handler: unsafe extern "system" fn(
            *mut windows_sys::Win32::System::Diagnostics::Debug::EXCEPTION_POINTERS,
        ) -> i32,
    ) -> Self {
        Veh(raw_add(order, handler as _), PhantomData)
    }
}

unsafe fn raw_add(order: Order, handler: usize) -> *const c_void {
    let handler = std::mem::transmute(handler);
    match order {
        Order::First => add_vectored_exception_handler(true, handler),
        Order::Last => add_vectored_exception_handler(false, handler),
    }
}

#[cfg(test)]
mod tests {
    use crate::{Order, Veh};
    use winapi::{
        um::{
            minwinbase::EXCEPTION_ACCESS_VIOLATION,
            winnt::{EXCEPTION_POINTERS, LONG, PEXCEPTION_POINTERS},
        },
        vc::excpt::{EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH},
    };

    #[test]
    fn handler_executed() {
        static mut FLAG: bool = false;

        unsafe extern "system" fn handler(ptrs: PEXCEPTION_POINTERS) -> LONG {
            let cr = &mut *(*ptrs).ContextRecord;
            let er = &mut *(*ptrs).ExceptionRecord;

            // Avoid catching exceptions that aren't caused by us
            if er.ExceptionCode == EXCEPTION_ACCESS_VIOLATION && er.ExceptionAddress == 1 as _ {
                // Emulate a `ret` instruction to let the program continue
                #[cfg(target_pointer_width = "32")]
                {
                    cr.Eip = *(cr.Esp as *const u32) as _;
                    cr.Esp += 4;
                }
                #[cfg(target_pointer_width = "64")]
                {
                    cr.Rip = *(cr.Rsp as *const u64) as _;
                    cr.Rsp += 8;
                }

                // Set the flag
                FLAG = true;

                // Continue execution
                EXCEPTION_CONTINUE_EXECUTION
            } else {
                // Continue executing handlers
                EXCEPTION_CONTINUE_SEARCH
            }
        }

        unsafe {
            let _veh = Veh::<EXCEPTION_POINTERS>::add(Order::First, handler);

            assert!(!FLAG);
            (std::mem::transmute::<_, fn()>(1 as *const usize))();
            assert!(FLAG);
        }
    }
}
