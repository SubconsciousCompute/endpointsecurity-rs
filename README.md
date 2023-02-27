
# Endpoint security 

This crate provides safe bindings to the Endpoint Security OSX Library.

# Usage

add `endpointsecurity-rs` as a dependency to your project
```
[dependencies]
endpointsecurity-rs = "0.1.1"
```

You will have to [disable SIP](https://developer.apple.com/documentation/security/disabling_and_enabling_system_integrity_protection?language=objc) if you want to use endpoint security while development without signing the executables with Apple.

With SIP disabled, you can use the following command to sign your executables with entitlements.

```
codesign --entitlements [entitlements_file] --force -s - [filename]
```

# Examples

You can play around with examples in the crate to test out the crate. To build follow the commands below

```
# example

cargo build --example disallow_rename

codesign --entitlements Extension.entitlements --force -s - ./target/debug/examples/disallow_rename
./disallow_rename
```

