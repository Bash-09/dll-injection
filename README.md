# dll-injection
Example code for a small presentation on how DLL injection works.

**Injected** is the payload dll that will be injected into a target process. It just consists of a constructor which is run when the DLL is successfully loaded into the target process, which opens an alert box and then terminates the process with exit code 123.

**Inject** is the injector program which loads the payload DLL into a target process.

## Building / Running
Rust and Cargo are required to be installed (Cargo should be installed by default if Rust was installed through `rustup`).

`cd` into `injected` and run `cargo build` to build the payload DLL

`cd` into `inject` and run `cargo run process_id` where `process_id` is the process id of the target program you want to inject into (can be found via Task Manager)
