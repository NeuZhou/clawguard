// ClawGuard - Tests: Python Bindings / pip install support (Issue #3)
// Tests for Python package structure and CLI wrapper

import { describe, it } from 'node:test';
import * as assert from 'node:assert';
import * as fs from 'fs';
import * as path from 'path';

const ROOT = path.resolve(__dirname, '..');
const PYTHON_DIR = path.join(ROOT, 'python');

describe('Python Bindings (Issue #3)', () => {
  it('python/ directory exists', () => {
    assert.ok(fs.existsSync(PYTHON_DIR), 'python/ directory should exist');
  });

  it('setup.py exists with package metadata', () => {
    const setupPath = path.join(PYTHON_DIR, 'setup.py');
    assert.ok(fs.existsSync(setupPath), 'setup.py should exist');
    const content = fs.readFileSync(setupPath, 'utf-8');
    assert.ok(content.includes('clawguard'), 'Should reference clawguard package');
    assert.ok(content.includes('setup('), 'Should call setup()');
    assert.ok(content.includes('install_requires'), 'Should have install_requires');
  });

  it('pyproject.toml exists', () => {
    const tomlPath = path.join(PYTHON_DIR, 'pyproject.toml');
    assert.ok(fs.existsSync(tomlPath), 'pyproject.toml should exist');
    const content = fs.readFileSync(tomlPath, 'utf-8');
    assert.ok(content.includes('[build-system]'), 'Should have build-system');
    assert.ok(content.includes('[project]'), 'Should have project section');
  });

  it('clawguard Python module exists', () => {
    const modulePath = path.join(PYTHON_DIR, 'clawguard', '__init__.py');
    assert.ok(fs.existsSync(modulePath), '__init__.py should exist');
  });

  it('clawguard module exposes scan function', () => {
    const initPath = path.join(PYTHON_DIR, 'clawguard', '__init__.py');
    const content = fs.readFileSync(initPath, 'utf-8');
    assert.ok(content.includes('def scan'), 'Should expose scan function');
  });

  it('clawguard module exposes check function', () => {
    const initPath = path.join(PYTHON_DIR, 'clawguard', '__init__.py');
    const content = fs.readFileSync(initPath, 'utf-8');
    assert.ok(content.includes('def check'), 'Should expose check function');
  });

  it('clawguard module exposes sanitize function', () => {
    const initPath = path.join(PYTHON_DIR, 'clawguard', '__init__.py');
    const content = fs.readFileSync(initPath, 'utf-8');
    assert.ok(content.includes('def sanitize'), 'Should expose sanitize function');
  });

  it('clawguard CLI entry point is defined', () => {
    const setupContent = fs.readFileSync(path.join(PYTHON_DIR, 'setup.py'), 'utf-8');
    assert.ok(
      setupContent.includes('console_scripts') || setupContent.includes('entry_points'),
      'Should define console_scripts entry point'
    );
  });

  it('README.md exists in python directory', () => {
    const readmePath = path.join(PYTHON_DIR, 'README.md');
    assert.ok(fs.existsSync(readmePath), 'Python README should exist');
    const content = fs.readFileSync(readmePath, 'utf-8');
    assert.ok(content.includes('pip install'), 'README should mention pip install');
    assert.ok(content.includes('clawguard'), 'README should reference clawguard');
  });

  it('pyproject.toml has correct package name', () => {
    const content = fs.readFileSync(path.join(PYTHON_DIR, 'pyproject.toml'), 'utf-8');
    assert.ok(content.includes('name = "clawguard"'), 'Package name should be clawguard');
  });

  it('setup.py specifies Node.js dependency', () => {
    const content = fs.readFileSync(path.join(PYTHON_DIR, 'setup.py'), 'utf-8');
    assert.ok(content.includes('nodejs') || content.includes('node') || content.includes('subprocess'), 
      'Should reference Node.js for backend execution');
  });

  it('clawguard module has version string', () => {
    const initContent = fs.readFileSync(path.join(PYTHON_DIR, 'clawguard', '__init__.py'), 'utf-8');
    assert.ok(initContent.includes('__version__'), 'Should have __version__ string');
  });

  it('Python tests file exists', () => {
    const testPath = path.join(PYTHON_DIR, 'tests', 'test_clawguard.py');
    assert.ok(fs.existsSync(testPath), 'Python test file should exist');
  });
});
