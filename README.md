# domainblock
A simple Rust CLI example to block a list of domains using [WinpkFilter](https://www.ntkernel.com/windows-packet-filter/) on Windows

## Usage Examples
```bash
# List all interfaces
cargo r -- interfaces
# Block `google.com` and `github.com` on network interface at 0 (index)
cargo r -- block -i 0 --domains "google.com" "github.com"
```

## Notes
- This example simply combines the 4th case of `filter` and the `listadapters` examples in [`ndisapi`](https://github.com/wiresock/ndisapi-rs) crate with the addition of DNS lookup. This means a large part of the code is directly taken from those examples.

- In order for the program to work, the [Windows Packet Filter driver](https://github.com/wiresock/ndisapi/releases/latest) must be installed on the system.
