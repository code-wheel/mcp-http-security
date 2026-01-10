# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.4] - 2026-01-09

### Added
- Tests for edge cases in PdoStorage for 100% code coverage
  - Non-array rows from PDOStatement::fetch
  - Non-string key_id/data values
  - Non-string data column in get()

## [Unreleased]

### Added
- PHPStan level 9 strict type checking
- Infection PHP mutation testing
- PHPBench performance benchmarks
- Example integrations (Slim 4, standalone, CLI key manager)

### Changed
- Changed `readonly class` to `readonly` properties for PHP 8.1 compatibility
- Cast keyId to string in `listKeys()` to handle PHP's numeric key conversion

### Fixed
- PHP 8.1 compatibility with readonly properties
- TypeError when iterating storage keys with numeric-looking IDs
- FileStorageTest cleanup and warning suppression

## [1.0.3] - 2026-01-07

### Added
- Comprehensive test suite with 167 tests
- CorruptibleStorage helper class for testing edge cases
- Tests for MySQL/PostgreSQL table creation in PdoStorage
- Tests for transaction rollback scenarios
- Tests for invalid JSON handling
- Edge case tests for IP and Origin validators

### Fixed
- PHP 8.1 compatibility (readonly class syntax)
- TypeError when storage keys look like integers

## [1.0.2] - 2026-01-07

### Added
- Codecov integration for test coverage reporting
- PHP 8.4 support in CI matrix
- Coverage configuration in phpunit.xml

## [1.0.1] - 2026-01-07

### Added
- Initial test suite
- CI workflow with GitHub Actions

## [1.0.0] - 2026-01-07

### Added
- Initial release
- API Key authentication with secure hashing (SHA-256 + pepper)
- IP allowlisting with CIDR notation support (IPv4/IPv6)
- Origin allowlisting with wildcard subdomain support
- PSR-15 SecurityMiddleware
- Multiple storage backends (Array, File, PDO)
- TTL/expiry support for API keys
- Scope-based authorization
- Exception hierarchy for security errors
