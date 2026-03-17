from setuptools import setup, find_packages

setup(
    name="clawguard",
    version="1.0.3",
    description="AI Agent Immune System — Python bindings for ClawGuard",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Kang Zhou",
    author_email="neuzhou@outlook.com",
    url="https://github.com/NeuZhou/clawguard",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[],
    entry_points={
        "console_scripts": [
            "clawguard=clawguard:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU Affero General Public License v3",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
    # Note: Requires Node.js >= 18 and @neuzhou/clawguard npm package
    # Install with: npm install -g @neuzhou/clawguard
    # The Python package wraps the Node.js CLI via subprocess
)
