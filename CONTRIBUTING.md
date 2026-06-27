# Contributing to WiGuard

We welcome contributions to **WiGuard**! Here are the guidelines to help you get started.

## How to Contribute
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/amazing-feature`).
3. Make your changes, ensuring code matches PEP 8 guidelines and contains type hints/docstrings.
4. Add unit tests for your changes under the `tests/` folder.
5. Verify all tests pass:
   ```bash
   python -m unittest discover -s tests
   ```
6. Commit your changes (`git commit -m 'Add amazing new feature'`).
7. Push to the branch (`git push origin feature/amazing-feature`).
8. Open a Pull Request.

## Code Style
- Use standard Python 3.12+ features.
- Write docstrings for all modules, classes, and methods.
- Include type hints for all parameters and return values.
- Handle exceptions gracefully and log appropriately.
