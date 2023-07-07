# libhopper

LibHopper is an exploitation primitives finding framework for arbitrary user libraries.

## Overview

Ascii graph represent the logic of LibHopper

```
lib.so \
         -> libhopper -> dataset of (Influence, Requirements) -> Human effort for full exploit
test.c /
```

Explaination:

- Identify requirement of corruption (Requirement)
  - Full write, Arbitrary write, Overflow, etc.
- Capability of the exploit from making such corruption (Influence)
  - Directly memory control
    - Induced overflow, Arbitrary write, Relative Write
  - Function control (Twist intended control flow)
    - Heap corruption
    - File read/write
    - Additional syscalls
    - Additional libc attacks
- Real world challenges

## Explaination

The idea is from the exploitation of the `FILE` struct, which is an internal state maintained by the library. By carefully craft the data in the internal state, attacker can achieve arbitrary write, arbitrary read and remote code execution previlieges. Even with the lastest glibc version with bunch of checks in the `FILE` struct, attackers still possiable to make FSROP attacks by corrupting the struct.

This illustrates the vulnerable part of any user libraries' internal states. Because the library apis are designed to trust the use of user program. However, the bug always appears in the user program that may cause the corruption in the library maintained internal states. LibHopper is trying to dig into this scenario to find possiable exploitation primitives that may be used by attackers to build exploits from the bug / vulnerability in the code.

The LibHopper based on the user library test cases or normal program that properly invoke library apis, which is critical. LibHopper will try to "insert" corruptions to library internal states between library api calls to simulate the bug in user program. It will then process on the corruption and analyze the program behavior after the crash.

LibHopper (idealy) will going to output the information dataset of "Influence" and "Requirements" pair. These information will then be used by human to generate exploits manually (This process might be automated in the future).

The influence are mainly focus on the [data oriented attacks](https://www.google.com/search?q=data+oriented+attacks&oq=data+oriented+attacks&aqs=chrome..69i57.295j0j1&sourceid=chrome&ie=UTF-8). By corrupting the data inside the internal state, attacker can twist the original control flow path to cause additional damage.

## Test Results

Currently the tests covers 5 well-known used libraries. Results are in the [results](./results/) folder.

- libssl / openssl
- libpng
- libjpeg
- libxml2
- zlib

The corruption results are devided into two types: full corruption and 1-byte corruption. This will give us some first handed information about the internal struct is being used in some way that may cause some "influence."

## Current Progress

Currently the tool is still using python-driven gdb script to dynamically execute the test cases and breakpoint on the library api functions to "insert" different corruption type to match possiable "requirement" that cause the vulnerability.

## Challenges

The challenges below might be solvable by using `angr`

- Know what value needed to do the corruption to achieve the "influence"
- Monitor exactly the "influence" of the corruption