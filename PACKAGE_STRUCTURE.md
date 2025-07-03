# DS620 Firmware Updater Package Structure

```
ds620-firmware-updater/
│
├── ds620_updater/              # Main Python package
│   ├── __init__.py            # Package initialization
│   ├── __main__.py            # CLI entry point
│   └── updater.py             # Core updater implementation
│
├── firmware/                   # Firmware files (v4.52)
│   ├── DS620_0452.s           # Main firmware (Motorola S-Record)
│   ├── DS620_PD_300_0111.cwd  # Photo Direct 300 DPI
│   ├── DS620_PD_600_0111.cwd  # Photo Direct 600 DPI
│   ├── DS620_PD_610_0111.cwd  # Photo Direct 610 DPI
│   ├── DS620_SD_300_0111.cwd  # Standard Direct 300 DPI
│   ├── DS620_SD_600_0111.cwd  # Standard Direct 600 DPI
│   └── DS620_SD_610_0111.cwd  # Standard Direct 610 DPI
│
├── docs/                       # Documentation
│   └── PROTOCOL.md            # Protocol specification
│
├── tests/                      # Test suite
│   ├── __init__.py
│   └── test_protocol.py       # Protocol tests
│
├── setup.py                    # Traditional setup script
├── pyproject.toml             # Modern Python packaging
├── requirements.txt           # Core dependencies
├── requirements-dev.txt       # Development dependencies
├── MANIFEST.in                # Package data inclusion
├── README.md                  # Main documentation
├── LICENSE                    # MIT License
└── .gitignore                 # Git ignore patterns
```

## Installation Methods

### 1. Development Installation
```bash
cd ds620-firmware-updater
pip install -e .
```

### 2. Package Installation
```bash
cd ds620-firmware-updater
pip install .
```

### 3. Direct Script Usage
```bash
python -m ds620_updater --help
```

## Command Line Usage

After installation, the updater is available as:
- `ds620-updater`
- `ds620-firmware-updater`
- `python -m ds620_updater`

All three commands are equivalent.