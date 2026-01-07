# Contributing to MCP HTTP Security

Thank you for your interest in contributing to MCP HTTP Security!

## Development Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/code-wheel/mcp-http-security.git
   cd mcp-http-security
   ```

2. Install dependencies:
   ```bash
   composer install
   ```

3. Run tests:
   ```bash
   composer test
   ```

## Code Quality Standards

This project maintains strict code quality standards:

### PHPStan Level 9

All code must pass PHPStan at the strictest level:

```bash
composer analyse
```

### Test Coverage

Maintain comprehensive test coverage:

```bash
composer test:coverage
```

### Mutation Testing

We use Infection PHP for mutation testing to ensure test quality:

```bash
composer infection
```

Minimum thresholds:
- MSI (Mutation Score Indicator): 80%
- Covered MSI: 90%

## Pull Request Process

1. **Fork the repository** and create a feature branch
2. **Write tests** for any new functionality
3. **Ensure all checks pass**:
   ```bash
   composer ci
   ```
4. **Update documentation** if needed
5. **Submit a pull request** with a clear description

## Commit Messages

Follow conventional commit format:

- `feat:` New features
- `fix:` Bug fixes
- `docs:` Documentation changes
- `test:` Test additions or changes
- `refactor:` Code refactoring
- `chore:` Build/tooling changes

Example: `feat: Add Redis storage backend`

## Running Benchmarks

Performance benchmarks help track performance regressions:

```bash
composer benchmark
```

## Testing Against Multiple PHP Versions

The CI pipeline tests against PHP 8.1, 8.2, 8.3, and 8.4. If you have multiple PHP versions installed locally, you can test with:

```bash
php8.1 vendor/bin/phpunit
php8.2 vendor/bin/phpunit
# etc.
```

## Security Issues

For security vulnerabilities, please email security@codewheel.dev instead of opening a public issue.

## Code Style

- Use strict types: `declare(strict_types=1);`
- Follow PSR-12 coding standards
- Use typed properties and return types
- Prefer readonly properties where appropriate
- Document complex logic with comments

## Questions?

Open an issue or reach out to the maintainers.
