# ZTE B760H LOGO Tool

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![Pillow](https://img.shields.io/badge/Pillow-10%2B-3776AB?style=flat-square&logo=python&logoColor=white)](https://python-pillow.org/)
[![Linux](https://img.shields.io/badge/Linux-Compatible-111111?style=flat-square&logo=linux&logoColor=white)](https://www.linux.org/)
[![License](https://img.shields.io/badge/License-MIT-111111?style=flat-square&logo=opensourceinitiative&logoColor=white)](LICENSE)

A small, conservative CLI toolkit for inspecting, unpacking, rebuilding, and independently verifying the ZTE/MediaTek B760H `LOGO` resource container.

## Features

- Inspect `LOGO` structure and embedded resources
- Unpack the four RGB565/zlib boot-logo resources
- Rebuild all four resources from a single artwork
- Preserve aspect ratio without cropping or stretching
- Preserve non-logo regions and the fixed 3 MiB layout
- Verify candidates with the main verifier
- Independently verify candidates with a separate parser

## Requirements

- Python 3.10+
- Pillow 10+

## Installation

Use a virtual environment:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/pip install -r requirements.txt
```

Using a virtual environment is recommended on Ubuntu and Debian, where the system Python environment may reject direct `pip install` commands.

## Usage

### Inspect

```bash
.venv/bin/python src/logo_tool.py info ./LOGO
```

### Unpack

```bash
.venv/bin/python src/logo_tool.py unpack ./LOGO --output ./unpacked
```

### Build

Use one artwork image to rebuild all four boot-logo resources:

```bash
.venv/bin/python src/logo_tool.py pack   --source ./LOGO   --image ./artwork.png   --output ./output/LOGO
```

The artwork is fitted to each target resolution with its original aspect ratio. Unused canvas area is filled with black.

### Verify

```bash
.venv/bin/python src/logo_tool.py verify   --source ./LOGO   --candidate ./output/LOGO
```

### Independent verification

```bash
.venv/bin/python src/logo_verify.py   --source ./LOGO   --candidate ./output/LOGO
```

A successful verification ends with:

```text
VERIFICATION SUCCESSFUL
```

and:

```text
INDEPENDENT VERIFICATION: SUCCESS
```

## Workflow

```text
LOGO
  │
  ├── inspect
  ├── unpack
  ├── artwork.png
  │
  └── pack ──→ output/LOGO
                  │
                  ├── main verify
                  └── independent verify
```

## Safety

The supplied source file is never modified.

The repository does not contain firmware images, proprietary partition data, boot artwork, reverse-engineering dumps, or a private golden-master hash. Input and output paths are explicit.

The independent verifier reparses the container independently of the packer. It validates the four zlib resources, locates the 35-frame animation, checks preserved regions, validates protected header ranges, and checks the fixed-size/padding relationships.

## Project Structure

```text
zte-b760h-logo-tool/
├── src/
│   ├── logo_tool.py
│   └── logo_verify.py
├── README.md
├── LICENSE
├── requirements.txt
└── .gitignore
```

## Scope

This project provides the reusable tooling only. It intentionally does not publish proprietary B760H firmware, extracted partition images, reverse-engineering data, or private test artifacts.

## License

MIT. See [LICENSE](LICENSE).
