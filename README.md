# JwtAnalyzer
JWT Analyzer is a C# CLI tool that reads, scans, and edits JSON Web Tokens for security analysis. It helps identify common JWT misconfigurations, decode claims, and modify tokens for testing purposes. Designed as an early-stage project for educational and authorized security testing.

### JWT Tool

A **CLI security utility written in C#** that provides **JWT reader, scanner, and editor modes** for analysis and testing purposes.

This project is intended for **educational use and authorized security testing only**.

---

### Features

**Reader Mode**

* Decode and display JWT Header
* Decode and display JWT Payload

**Scanner Mode**

* Detect `alg=none`
* Detect missing signature
* Check token expiration (`exp`)
* Check `nbf` (not before)
* Check `iat` (issued at)
* Detect missing `iss` and `aud`
* Warn about uncommon algorithms
* Detect unusually large tokens

**Editor Mode**

* Modify any claim
* Remove any claim
* Change algorithm
* Generate a modified JWT (unsigned)

---

### Usage

```bash
JwtTool.exe --mode read -t <JWT>
JwtTool.exe --mode scan -t <JWT>
JwtTool.exe --mode edit -t <JWT> --set exp=2000000000
JwtTool.exe --mode edit -t <JWT> --remove iss
JwtTool.exe -h
```

---

### Options

* `--mode read`
  Decode and display JWT content

* `--mode scan`
  Analyze JWT for common security issues

* `--mode edit`
  Modify or remove claims and output a new JWT

* `-t , --token <JWT>`
  JWT token input

* `--set key=value`
  Set or update a claim

* `--remove key`
  Remove a claim

* `-h , --help`
  Show help message

---

### Example

Input:

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

Output:

```
alg: HS256
exp: valid
INFO: iss missing
INFO: aud missing
```

---

### Project Status

This is an **early-stage project**.
The tool will continue to evolve with additional detection logic, features, and improvements.

---

### Notes

* Edited tokens are **not re-signed**
* The tool does **not perform exploitation**
* Scanner is **analysis-only**

---

### Requirements

* .NET 6.0 or newer
* Windows (CLI)
* Visual Studio or dotnet CLI

---

### Disclaimer

This tool is provided for **educational and authorized testing purposes only**.
The author is not responsible for misuse.

---

### License

MIT
