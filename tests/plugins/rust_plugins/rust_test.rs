#![no_std] // don't link the Rust standard library
#![no_main] // disable all Rust-level entry points

 use core::panic::PanicInfo;

#[no_mangle] // don't mangle the name of this function
#[inline(always)]
pub extern "C" fn _start() -> u64 {
    // this function is the entry point, since the linker looks for a function
    // named `_start` by default
    let b = my_main();
    return b as u64;
}

// Mocking xBGP API 
extern "C" {
    fn my_c_function2(b: bool) -> bool;
    fn get_arg(b: i32) -> i32;
}


#[inline(always)]
fn my_c_function(x: i32) -> bool {
    let y = x.checked_add(65);

    match y {
        Some(v) => v == 1,
        None => false,
    }
}

#[inline(always)]
fn mc_fun(x: i32) -> i32 {
    return x + 42;
}


#[inline(always)]
fn my_main() -> bool {
    let o;
    let oo;

    unsafe {
        o = get_arg(56);
    }

    oo = mc_fun(o);
    let a = my_c_function(oo);
    let b;
    unsafe {
        b = my_c_function2(a);
    }
    return b;
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        asm!("nop");
    }
}
