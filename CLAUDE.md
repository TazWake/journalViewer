# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a digital forensics tool development project focused on creating an EXT3/4 filesystem journal analyzer. The tool extracts and parses journal data from disk images (raw DD format and EWF format) and converts it to CSV format for forensic analysis.

## Project Status

This appears to be a specification-driven project currently in the planning phase. The codebase contains comprehensive technical specifications but no implemented code yet.

## Common Commands

### Build System (Planned - CMake)
Based on the specifications, the intended build process will be:

```powershell
# Create build directory
mkdir build
cd build

# Configure with CMake
cmake ..

# Compile (Windows)
cmake --build . --config Release

# Install (optional, requires admin PowerShell)
cmake --install .
```

### Dependencies (Windows)
```powershell
# Install Visual Studio Build Tools or Visual Studio Community
# Install CMake from https://cmake.org/download/
# Install vcpkg for C++ package management
git clone https://github.com/Microsoft/vcpkg.git
cd vcpkg
.\bootstrap-vcpkg.bat
.\vcpkg integrate install

# Install libewf via vcpkg
.\vcpkg install libewf:x64-windows
```

### Dependencies (Ubuntu/Debian)
```bash
sudo apt-get install build-essential cmake libewf-dev
```

### Dependencies (RHEL/CentOS)
```bash
# RHEL/CentOS 7
sudo yum install gcc-c++ cmake libewf-devel

# RHEL/CentOS 8+
sudo dnf install gcc-c++ cmake libewf-devel
```

### Python Alternative Dependencies
```powershell
# Windows PowerShell
pip install pytsk3 pyewf
```

## Architecture and Technical Design

### Core Components (Planned)
The architecture is designed around these main classes:

1. **JournalAnalyzer**: Main orchestrator class
2. **ImageHandler**: Handles raw DD and EWF image format reading
3. **JournalParser**: Parses EXT3/4 journal structures (JBD/JBD2)
4. **CSVExporter**: Converts journal data to CSV format

### Key Technologies
- **C++17**: Primary implementation language for performance
- **libewf**: Expert Witness Format support for .E01/.Ex01 files
- **CMake**: Build system
- **JBD/JBD2**: Journal Block Device structures for EXT3/4

### Input Formats Supported
- Raw disk images (DD format)
- Expert Witness Format (EWF) - .E01/.Ex01 files
- Multi-segment EWF images (.E01, .E02, etc.)

### Target Filesystems
- EXT3 filesystems with JBD (Journal Block Device)
- EXT4 filesystems with JBD2 (Journal Block Device 2)
- Both internal journals (inode 8) and external journal devices

## Command Line Interface (Planned)

### Primary Binary: `ext-journal-analyzer`

```bash
ext-journal-analyzer -i <image_file> -o <output.csv> [options]
```

### Key Arguments
- `-i, --image`: Input image file path (required)
- `-o, --output`: Output CSV file path (required)
- `-t, --type`: Image type (auto|raw|ewf) [default: auto]
- `-v, --verbose`: Verbose output
- `--journal-offset`: Manual journal offset (bytes)
- `--start-seq`: Start from specific sequence number
- `--end-seq`: End at specific sequence number

### Usage Examples
```powershell
# Process EWF image
.\ext-journal-analyzer.exe -i evidence.E01 -o journal_analysis.csv -v

# Process raw image with manual journal location
.\ext-journal-analyzer.exe -i disk.dd -o output.csv --journal-offset 1048576

# Process specific transaction range
.\ext-journal-analyzer.exe -i evidence.E01 -o filtered.csv --start-seq 100 --end-seq 200
```

## Development Phases

### Implementation Priority
1. **Phase 1**: Core infrastructure (image handlers, journal detection, CSV output)
2. **Phase 2**: Journal parsing (descriptor/commit blocks, transaction tracking)
3. **Phase 3**: Data interpretation (inode resolution, file path reconstruction)
4. **Phase 4**: Enhanced features (filtering, integrity checking, optimization)

### Development Strategy
- **Priority 1**: Compiled C++ binary for performance
- **Priority 2**: Python implementation for rapid prototyping
- **Focus**: Ubuntu LTS (18.04+) and RHEL/CentOS (7+) on x86_64

## Output Format

### CSV Schema
```
timestamp,transaction_seq,block_type,fs_block_num,operation_type,affected_inode,file_path,data_size,checksum
```

The tool generates forensically relevant data including transaction timestamps, sequence numbers, filesystem block numbers, and when possible, affected inodes and file paths.

## Security and Forensics Focus

This tool is designed for **defensive security and forensic analysis only**. Key considerations:
- Maintains data integrity through checksum verification
- Preserves chain of custody documentation
- Focuses on read-only analysis of evidence images
- Implements secure handling of potentially sensitive forensic data

## Key Journal Structures

### JBD2 Magic Numbers and Types
- **Magic**: 0xC03B3998 (JBD2)
- **Block Types**: 1=descriptor, 2=commit, 3=superblock v1, 4=superblock v2, 5=revocation

### Transaction Structure
Each journal transaction consists of:
1. Descriptor Block (lists filesystem blocks being updated)
2. Data Blocks (actual filesystem data)
3. Commit Block (marks transaction completion)

## Project Notes

- You do not need to build any applications as part of this project, they will be done separately in a linux vm

## Development Memories

- You do not need to push anything to GitHub that will be done separately.