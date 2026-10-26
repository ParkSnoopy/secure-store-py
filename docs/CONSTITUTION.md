# Project Constitution

> This file defines the immutable laws of this codebase. AI agents and human
> developers alike must follow these rules. No exceptions.

## Non-Negotiable Rules

### 1. Error Handling

- **No `unwrap()` or `expect()`** - Handle errors explicitly with `?` or match
- **No `panic!()`** - Return `Result` or `Option` instead
- **Use `thiserror`** for custom error types in libraries
- **Use `anyhow`** for error handling in applications

### 2. Logging & Output

- **No `println!()` or `eprintln!()`** - Use `tracing` for structured logging
- **No `dbg!()`** - Remove all debug macros before committing
- Log levels: `error` for failures, `warn` for recoverable issues, `info` for
  important events, `debug` for development, `trace` for detailed debugging

### 3. Code Completeness

- **No `todo!()`** - Implement the feature or create an issue
- **No `unimplemented!()`** - Provide a proper error or stub
- **No `#[allow(...)]`** - Fix the lint warning properly

### 4. Documentation

- All public functions must have doc comments
- Doc comments must include:
  - Brief description of what the function does
  - `# Errors` section if it returns `Result`
  - `# Examples` for complex functions

### 5. Testing

- Tests must exist for all public API
- Use `#[test]` for unit tests, `tests/` directory for integration tests
- Test error cases, not just happy paths
- Aim for meaningful coverage, not 100% line coverage

## Architecture Principles

### Modularity

- Each module should have a single, clear responsibility
- Prefer composition over inheritance
- Keep public APIs minimal

### Performance

- Profile before optimizing
- Prefer stack allocation over heap when practical
- Use `Arc` and `Rc` sparingly - prefer borrowing

### Async Code

- Never hold a `MutexGuard` across `.await`
- Prefer `tokio::sync` primitives over `std::sync` in async code
- Use structured concurrency with `JoinSet` or similar

### Dependencies

- Minimize dependencies - each one is a liability
- Prefer well-maintained crates with good security track records
- Pin major versions in `Cargo.toml`

## Code Style

- Run `cargo fmt` before committing
- Follow Rust API Guidelines: https://rust-lang.github.io/api-guidelines/
- Use meaningful names - avoid single-letter variables except in iterators
- Keep functions under 50 lines when possible

---

*This constitution is enforced by the lint configuration in `Cargo.toml`.
Violations will cause compilation to fail.*
