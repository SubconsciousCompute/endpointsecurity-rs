use std::env;

#[cfg(not(target_os = "macos"))]
fn main() {
    panic!("Cannot build for non OSX platforms")
}

#[cfg(target_os = "macos")]
fn main() {
    println!("cargo:rustc-link-lib=EndpointSecurity");
    println!("cargo:rustc-link-lib=bsm");

    use std::path::PathBuf;

    let bindings = bindgen::Builder::default()
        .header("EndpointSecurity.h")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        .generate()
        .expect("Unable to generate bindings for endpoint security");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("ep_sys.rs"))
        .expect("Couldn't write bindings!");
}
