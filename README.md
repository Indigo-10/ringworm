# Ringworm

Modular payload generation framework for creating custom malware. Work-in-progress project focused on building a flexible system for payload compilation and deployment.

## What it does

**CLI Interface (Program.cs):**
- Interactive menu for payload generation
- Template-based code generation with variable substitution
- Cross-platform compilation support (Windows/Linux)
- Configurable encryption and compression options

**Process Injection Template (process_injection.c):**
- Downloads shellcode from HTTP/HTTPS URLs
- Performs process injection into specified target processes
- Supports AES-256-CBC decryption (placeholder implementation)
- Supports deflate9 decompression (placeholder implementation)
- Uses Windows API for memory allocation and remote thread creation

## Current Features

- Template-based C code generation
- HTTP/HTTPS shellcode download with SSL support
- Process enumeration and injection
- Configurable target processes and payload URLs
- Cross-compiler support (cl.exe and mingw32-gcc)

## Future Goals

Planning to implement direct and indirect syscalls for API evasion instead of relying on traditional C libraries or shellcode, though this requires more advanced knowledge to execute properly.

## Usage

```bash
# Build and run the CLI
dotnet run

# Follow prompts to configure:
# - Target process (e.g., notepad.exe)
# - Shellcode URL
# - Output filename
# - Encryption/compression options
```

---
*For authorized security research and red team operations only*

