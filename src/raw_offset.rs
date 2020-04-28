pub trait RawOffset {
    unsafe fn raw_offset(self, count: isize) -> Self;
    unsafe fn raw_add(self, count: usize) -> Self;
}

impl<T> RawOffset for *mut T {
    #[inline]
    unsafe fn raw_offset(self, count: isize) -> Self {
        (self as *mut u8).offset(count) as Self
    }

    #[inline]
    unsafe fn raw_add(self, count: usize) -> Self {
        (self as *mut u8).add(count) as Self
    }
}

impl<T> RawOffset for *const T {
    #[inline]
    unsafe fn raw_offset(self, count: isize) -> Self {
        (self as *const u8).offset(count) as Self
    }

    #[inline]
    unsafe fn raw_add(self, count: usize) -> Self {
        (self as *const u8).add(count) as Self
    }
}
