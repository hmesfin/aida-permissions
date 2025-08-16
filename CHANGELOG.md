# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2024-08-16

### Fixed
- Fixed compatibility with custom User models that don't have a username field
- Fixed UserAdmin requiring search_fields configuration
- Dynamic search fields now adapt to available User model fields
- Management commands now handle User models with email as USERNAME_FIELD
- Admin and ViewSet search fields are now dynamically configured

### Added
- Created user_utils module for handling different User model configurations
- Added utility functions for getting user identifiers and display names
- Enhanced compatibility with custom Django User models
- Added documentation for custom User model support in README and COMPATIBILITY.md

## [1.0.1] - 2024-08-15

### Fixed
- Updated GitHub repository URLs in package metadata
- Fixed project URLs to point to correct GitHub repository

### Changed
- Minor documentation improvements

## [1.0.0] - 2024-08-15

### Added
- Initial release of aida-permissions
- Role-Based Access Control (RBAC) with inheritance support
- Multi-tenancy ready with tenant isolation
- Django REST Framework integration
- Vue.js components for frontend integration
- Dynamic permissions that can be created and assigned at runtime
- Time-based permissions with expiration support
- Django admin interface for easy management
- Intelligent caching for high performance
- Comprehensive audit logging
- Management commands for permission initialization
- Support for Django 3.2 through 5.1
- Full test suite with pytest
- CI/CD with GitHub Actions