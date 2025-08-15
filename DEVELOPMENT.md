# Development Guide

## Setting Up Development Environment

### Prerequisites

- Python 3.8 or higher
- pip
- git
- Redis (optional, for caching)
- PostgreSQL or SQLite

### Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/aida-permissions.git
   cd aida-permissions
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install in development mode:**
   ```bash
   make install-dev
   # Or manually:
   pip install -e ".[dev]"
   ```

4. **Install pre-commit hooks:**
   ```bash
   pre-commit install
   ```

## Code Quality with Ruff

This project uses [Ruff](https://github.com/astral-sh/ruff) for linting and formatting. Ruff is an extremely fast Python linter and formatter, written in Rust, that replaces Black, isort, and Flake8.

### Why Ruff?

- **Speed**: 10-100x faster than existing tools
- **Comprehensive**: Replaces multiple tools (Black, isort, Flake8, and dozens of plugins)
- **Consistent**: Single configuration for all code quality checks
- **Modern**: Built-in support for latest Python features
- **Django-aware**: Includes Django-specific rules

### Basic Ruff Commands

```bash
# Check for linting issues
ruff check aida_permissions tests

# Auto-fix linting issues
ruff check --fix aida_permissions tests

# Format code
ruff format aida_permissions tests

# Check formatting without changing files
ruff format --check aida_permissions tests

# Show statistics about issues
ruff check --statistics aida_permissions tests

# Explain a specific rule
ruff rule DJ001  # Explains Django-specific rule about null=True on CharField
```

### Using Make Commands

We provide convenient Make commands for common tasks:

```bash
# Run all checks and auto-fix
make check

# Just lint (no auto-fix)
make lint

# Auto-fix linting issues
make lint-fix

# Format code
make format

# Check formatting without changes
make format-check

# Run strict checks (no auto-fix, fails on issues)
make check-strict
```

### Ruff Configuration

Ruff is configured in `pyproject.toml` with the following key settings:

- **Line length**: 120 characters
- **Python version**: 3.8+
- **Enabled rules**: Django-specific, security, performance, and style rules
- **Auto-fix**: Enabled for safe fixes

#### Key Rule Categories

- `E`, `W`: pycodestyle errors and warnings
- `F`: pyflakes
- `I`: isort (import sorting)
- `DJ`: Django-specific rules
- `S`: Security checks (Bandit)
- `B`: Bugbear (common bugs)
- `SIM`: Simplification suggestions
- `UP`: Python version upgrade suggestions
- `RUF`: Ruff-specific rules

### VS Code Integration

Add to `.vscode/settings.json`:

```json
{
  "[python]": {
    "editor.formatOnSave": true,
    "editor.codeActionsOnSave": {
      "source.fixAll": true,
      "source.organizeImports": true
    },
    "editor.defaultFormatter": "charliermarsh.ruff"
  },
  "ruff.lint.enable": true,
  "ruff.lint.run": "onType",
  "ruff.format.enable": true
}
```

Install the Ruff VS Code extension:
```bash
code --install-extension charliermarsh.ruff
```

### PyCharm Integration

1. Install the Ruff plugin from the marketplace
2. Go to Settings → Tools → Ruff
3. Enable "Run ruff on save"
4. Set the path to ruff executable

### Pre-commit Hooks

Pre-commit automatically runs Ruff before each commit:

```bash
# Install pre-commit hooks
pre-commit install

# Run manually on all files
pre-commit run --all-files

# Update hooks to latest versions
pre-commit autoupdate
```

### Common Ruff Workflows

#### 1. Before committing code:
```bash
make check  # Auto-fixes issues and formats code
```

#### 2. CI/CD pipeline:
```bash
make check-strict  # Fails if any issues found
```

#### 3. Understanding an error:
```bash
# If you see error DJ008
ruff rule DJ008
# Explains: Model field defines `__str__` without `__repr__`
```

#### 4. Ignoring a rule for a specific line:
```python
# For a single line
x = 1  # noqa: F841

# For a block
# ruff: noqa: F841
x = 1
y = 2
# ruff: noqa
```

#### 5. Project-wide rule configuration:
Edit `pyproject.toml`:
```toml
[tool.ruff]
ignore = ["DJ001"]  # Ignore null=True on CharField
```

## Testing

### Running Tests

```bash
# Run all tests
make test

# Run with verbose output
make test-verbose

# Run with coverage
make test-coverage

# Run specific test file
pytest tests/test_models.py

# Run specific test
pytest tests/test_models.py::TestPermission::test_create_permission
```

### Writing Tests

Tests should follow these conventions:

1. Use pytest fixtures for setup
2. Name test files as `test_*.py`
3. Name test classes as `Test*`
4. Name test methods as `test_*`

Example:
```python
import pytest
from aida_permissions.models import Permission

@pytest.mark.django_db
class TestPermission:
    def test_create_permission(self):
        permission = Permission.objects.create(
            codename="test.view",
            name="View Test"
        )
        assert permission.codename == "test.view"
```

## Database Migrations

```bash
# Create migrations
python manage.py makemigrations aida_permissions

# Apply migrations
python manage.py migrate

# Check migration status
python manage.py showmigrations aida_permissions
```

## Documentation

### Code Documentation

- Use Google-style docstrings
- Include type hints where appropriate
- Document all public APIs

Example:
```python
def has_permission(user: User, permission: str) -> bool:
    """Check if user has a specific permission.
    
    Args:
        user: The user to check permissions for.
        permission: The permission codename to check.
        
    Returns:
        True if user has the permission, False otherwise.
        
    Example:
        >>> has_permission(user, "equipment.view")
        True
    """
```

## Release Process

1. **Update version:**
   ```python
   # In setup.py and pyproject.toml
   version = "1.1.0"
   ```

2. **Run checks:**
   ```bash
   make check-strict
   make test-coverage
   ```

3. **Build packages:**
   ```bash
   make build
   ```

4. **Tag release:**
   ```bash
   git tag -a v1.1.0 -m "Release version 1.1.0"
   git push origin v1.1.0
   ```

5. **Upload to PyPI:**
   ```bash
   pip install twine
   twine upload dist/*
   ```

## Troubleshooting

### Ruff Issues

**Issue**: Ruff not found
```bash
# Solution: Install ruff
pip install ruff
```

**Issue**: Import sorting conflicts
```bash
# Solution: Let ruff handle it
ruff check --fix --select I aida_permissions
```

**Issue**: Line too long errors
```bash
# Solution: Auto-format
ruff format aida_permissions
```

### Test Issues

**Issue**: Django settings not found
```bash
# Solution: Set environment variable
export DJANGO_SETTINGS_MODULE=tests.settings
```

**Issue**: Database not available
```bash
# Solution: Use in-memory database
# In tests/settings.py
DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': ':memory:',
    }
}
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run `make check-strict`
5. Commit with descriptive message
6. Push and create a pull request

### Commit Message Format

```
type: subject

body (optional)

footer (optional)
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation
- `style`: Code style (formatting, etc)
- `refactor`: Code refactoring
- `test`: Tests
- `chore`: Maintenance

Example:
```
feat: add multi-tenant support for permissions

- Add tenant_id field to all models
- Update queries to filter by tenant
- Add tests for multi-tenant scenarios

Closes #123
```