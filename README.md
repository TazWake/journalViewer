# EXT Journal Analyzer

A forensic tool for analyzing EXT3/4 filesystem journals from disk images. This tool extracts journal transaction data from raw disk images and Expert Witness Format (EWF) files, converting the binary journal structures into human-readable CSV format for forensic analysis.

## Features

- **Multi-format Support**: Processes both raw disk images (DD format) and Expert Witness Format (.E01/.Ex01) files
- **EXT3/4 Compatibility**: Supports both EXT3 (JBD) and EXT4 (JBD2) journal formats
- **Automatic Journal Detection**: Locates journals stored as regular files (inode 8) or external devices
- **Transaction Parsing**: Extracts descriptor blocks, data blocks, commit records, and revocation entries
- **CSV Export**: Generates structured forensic data with timestamps, sequence numbers, and checksums
- **Flexible Filtering**: Support for transaction sequence range filtering
- **Cross-platform**: Designed for Ubuntu/RHEL platforms with Windows development support

## Compilation

### Prerequisites

#### Ubuntu/Debian
```bash
sudo apt-get update
sudo apt-get install build-essential cmake libewf-dev pkg-config
```

#### RHEL/CentOS 7
```bash
sudo yum install gcc-c++ cmake libewf-devel pkgconfig
```

#### RHEL/CentOS 8+
```bash
sudo dnf install gcc-c++ cmake libewf-devel pkgconf-pkg-config
```

### Building the Tool

```bash
# Clone or extract the source code
git clone <repository-url>
cd journalViewer

# Create build directory
mkdir build
cd build

# Configure with CMake
cmake ..

# Compile
make -j$(nproc)

# Optional: Install system-wide
sudo make install
```

## Usage

### Basic Syntax
```bash
./ext-journal-analyzer -i <image_file> -o <output.csv> [options]
```

### Required Arguments
- `-i, --image <file>` - Input image file path (DD or EWF format)
- `-o, --output <file>` - Output CSV file path

### Optional Arguments
- `-t, --type <type>` - Image type (auto|raw|ewf) [default: auto]
- `-v, --verbose` - Enable verbose output
- `-h, --help` - Display help information
- `--version` - Display version information
- `--journal-offset <bytes>` - Manual journal offset (for direct access)
- `--journal-size <bytes>` - Manual journal size specification
- `--start-seq <number>` - Start from specific transaction sequence number
- `--end-seq <number>` - End at specific transaction sequence number
- `--no-header` - Omit CSV header row

### Examples

#### Process an EWF Evidence File
```bash
./ext-journal-analyzer -i evidence.E01 -o journal_analysis.csv -v
```

#### Process a Raw Disk Image
```bash
./ext-journal-analyzer -i disk.dd -o output.csv --verbose
```

#### Manual Journal Location
```bash
./ext-journal-analyzer -i disk.dd -o output.csv --journal-offset 1048576
```

#### Filter Transaction Range
```bash
./ext-journal-analyzer -i evidence.E01 -o filtered.csv --start-seq 100 --end-seq 200
```

#### Batch Processing Script
```bash
#!/bin/bash
for image in *.E01; do
    ./ext-journal-analyzer -i "$image" -o "${image%.E01}_journal.csv" -v
done
```

## Output Format

The tool generates CSV files with the following columns:

| Column | Description |
|--------|-------------|
| `timestamp` | Transaction commit time (ISO 8601 format) |
| `transaction_seq` | Journal sequence number |
| `block_type` | Type of journal block (descriptor/data/commit/revocation) |
| `fs_block_num` | Filesystem block number being modified |
| `operation_type` | Inferred operation type (file_creation, deletion, etc.) |
| `affected_inode` | Inode number when determinable |
| `file_path` | File path when recoverable from directory entries |
| `data_size` | Size of data block |
| `checksum` | Block checksum for integrity verification |

### Sample Output
```csv
timestamp,transaction_seq,block_type,fs_block_num,operation_type,affected_inode,file_path,data_size,checksum
2024-01-15T10:30:45Z,295,descriptor,0,transaction_start,0,,24,a1b2c3d4
2024-01-15T10:30:45Z,295,data,163,filesystem_update,0,,4096,e5f6a7b8
2024-01-15T10:30:45Z,295,commit,0,transaction_end,0,,0,12345678
```

## Forensic Applications

This tool is designed for defensive security and digital forensics:

- **Timeline Analysis**: Reconstruct filesystem activity chronology
- **Data Recovery**: Identify recently deleted or modified files
- **Incident Response**: Track unauthorized file system changes
- **Evidence Analysis**: Support legal and compliance investigations
- **System Auditing**: Monitor filesystem integrity and changes

## Limitations

- **Read-only Analysis**: Tool performs non-invasive analysis of evidence images
- **Simplified Parsing**: Current implementation provides foundational journal parsing
- **Timestamp Accuracy**: Relies on journal commit records for timing information
- **Path Resolution**: File path reconstruction depends on available directory metadata

## Error Handling

The tool includes comprehensive error handling for:
- Invalid or corrupted image files
- Missing or damaged journal structures
- Insufficient permissions or disk space
- Network connectivity issues with remote images

## Support

For technical support or bug reports, please refer to the project documentation or contact the development team.

## Security Notice

This tool is designed exclusively for defensive security and forensic analysis. It should only be used on systems and data where you have explicit authorization to perform analysis.
