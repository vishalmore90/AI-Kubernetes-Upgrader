from setuptools import setup, find_packages

setup(
    name="ai-k8s-upgrader",
    version="1.0.0",
    description="Enterprise-grade Kubernetes Upgrade Feasibility, Compatibility, and Risk Assessment Engine",
    author="AI-Kubernetes-Upgrader",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "flask>=2.3.0",
        "jinja2>=3.1.0",
        "packaging>=23.0",
        "pyyaml>=6.0",
        "requests>=2.31.0",
        "rich>=13.0.0",
        "click>=8.1.0",
        "tabulate>=0.9.0",
    ],
    entry_points={
        "console_scripts": [
            "k8s-upgrade-assess=ai_k8s_upgrader.cli:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Systems Administration",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)
