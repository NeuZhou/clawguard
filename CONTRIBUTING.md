# Contributing to ClawGuard

Thanks for your interest in ClawGuard! Here's how to get involved.

## Getting Started

```bash
git clone https://github.com/NeuZhou/clawguard.git
cd clawguard
npm install
npm run build
npm test
```

## Development

```bash
# Type check
npm run check

# Run tests
npm test

# Run scanner on a directory
npm run scan -- ./path/to/scan
```

## Adding Security Rules

Rules live in `rules.d/`. Each rule category has its own file with pattern definitions.

To add a new pattern:

1. Find the appropriate rule file in `rules.d/`
2. Add your pattern with: regex, severity, confidence, description, and remediation
3. Add tests in `tests/`
4. Run `npm test` to verify

## Pull Request Process

1. Fork the repo and create a feature branch: `git checkout -b feat/my-feature`
2. Write tests for new functionality
3. Ensure all tests pass: `npm test`
4. Ensure types check: `npm run check`
5. Submit a PR with a clear description

## Code Style

- TypeScript strict mode
- No runtime dependencies (zero-dep policy)
- Every pattern needs a test
- Use descriptive commit messages: `feat:`, `fix:`, `test:`, `docs:`

## Reporting Security Issues

If you find a security vulnerability, **please do not open a public issue**. Email neuzhou@outlook.com directly.

## CLA

Contributors must agree to our [CLA](CLA.md) to enable dual licensing (AGPL-3.0 + Commercial).

## License

By contributing, you agree that your contributions will be licensed under AGPL-3.0.
