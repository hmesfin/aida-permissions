from setuptools import find_packages, setup

with open("README.md", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="aida-permissions",
    version="1.0.2",
    author="gojjotech",
    author_email="admin@gojjotech.com",
    description="A flexible Django roles and permissions extension optimized for DRF and Vue.js",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/hmesfin/aida-permissions",
    project_urls={
        "Bug Tracker": "https://github.com/hmesfin/aida-permissions/issues",
        "Documentation": "https://github.com/hmesfin/aida-permissions",
        "Source Code": "https://github.com/hmesfin/aida-permissions",
    },
    keywords="django permissions roles rbac rest drf vue multi-tenant",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Framework :: Django",
        "Framework :: Django :: 3.2",
        "Framework :: Django :: 4.0",
        "Framework :: Django :: 4.1",
        "Framework :: Django :: 4.2",
        "Framework :: Django :: 5.0",
        "Framework :: Django :: 5.1",
    ],
    python_requires=">=3.8",
    install_requires=[
        "Django>=3.2,<=5.1",
        "djangorestframework>=3.12.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-django>=4.5.0",
            "pytest-cov>=3.0.0",
            "ruff>=0.1.0",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
