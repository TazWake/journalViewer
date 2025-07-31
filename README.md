# EXT Journal Analyzer v2.0

A comprehensive forensic tool for analyzing EXT3/4 filesystem journals from disk images. This advanced tool extracts and analyzes journal transaction data from raw disk images and Expert Witness Format (EWF) files, converting binary journal structures into human-readable CSV format with intelligent content analysis for forensic investigations.

## Features

### Core Capabilities
- **Multi-format Support**: Processes both raw disk images (DD format) and Expert Witness Format (.E01/.Ex01) files
- **EXT3/4 Compatibility**: Supports both EXT3 (JBD) and EXT4 (JBD2) journal formats with automatic detection
- **Automatic Journal Detection**: Locates journals stored as regular files (inode 8) or external devices
- **Advanced Transaction Parsing**: Extracts descriptor blocks, data blocks, commit records, and revocation entries
- **Flexible Filtering**: Support for transaction sequence range filtering and partition offset handling

### Enhanced Forensic Analysis (v2.0)
- **Intelligent Content Analysis**: Automatically extracts human-readable strings from data blocks
- **File Content Classification**: Identifies text files, configuration files, log entries, and other content types
- **Comprehensive Forensic Summary**: Detailed analysis reports with string extraction statistics
- **Journal Mode Detection**: Identifies JOURNAL, ORDERED, or WRITEBACK journaling modes
- **Path Reconstruction**: Advanced inode-to-path resolution with directory tree building
- **String Pattern Matching**: Detects URLs, file paths, configuration entries, and forensically relevant content

### Output and Analysis
- **Enhanced CSV Export**: Structured forensic data with extracted strings, file types, and path information
- **Forensic Metadata**: Includes timestamps, sequence numbers, checksums, and content analysis
- **Real-time Progress**: Verbose mode with detailed analysis progress and statistics
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
- `--partition-offset <sectors>` - Partition offset in 512-byte sectors
- `--partition-offset-bytes <bytes>` - Partition offset in bytes
- `--sector-size <size>` - Sector size in bytes [default: 512]
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
# Using calculated journal offset (from debugfs inode 8 extent data)
./ext-journal-analyzer -i example.raw -o example.csv --journal-offset 1073741824
```

#### Multi-Partition Images
```bash
# Process specific partition (using mmls output - partition 6 at sector 227328)
./ext-journal-analyzer -i starkskunk5.E01 -o partition6.csv --partition-offset 227328

# Or using byte offset
./ext-journal-analyzer -i starkskunk5.E01 -o partition6.csv --partition-offset-bytes 116391936
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

The tool generates comprehensive CSV files with forensic analysis data:

| Column | Description |
|--------|-------------|
| `relative_time` | Relative timing (T+0, T+1, etc.) - no misleading timestamps |
| `transaction_seq` | Journal sequence number |
| `block_type` | Type of journal block (descriptor/data/commit/revocation/superblock) |
| `fs_block_num` | Filesystem block number being modified |
| `operation_type` | Inferred operation type (file_data_update, text_file_update, etc.) |
| `affected_inode` | Inode number when determinable |
| `file_path` | **Enhanced**: File path OR extracted strings (STRINGS: content) |
| `data_size` | Size of data block |
| `checksum` | Block checksum for integrity verification |
| `file_type` | **New**: File type classification (text_file, config_file, log_file, etc.) |
| `file_size` | **New**: File size from inode analysis |
| `inode_number` | **New**: Specific inode number |
| `link_count` | **New**: Hard link count |
| `filename` | **New**: Filename from directory entries |
| `parent_dir_inode` | **New**: Parent directory inode |
| `change_type` | **New**: Type of change (new_entry, data_change, etc.) |
| `full_path` | **New**: Complete reconstructed file path |

### Sample Output with String Analysis
```csv
relative_time,transaction_seq,block_type,fs_block_num,operation_type,affected_inode,file_path,data_size,checksum,file_type,file_size,inode_number,link_count,filename,parent_dir_inode,change_type,full_path
T+0,0,superblock,0,journal_superblock,0,,4084,72b65708,superblock,0,0,0,,0,journal_init,/
T+1007855,1007855,data,307,file_data_update,0,STRINGS: cloudimg-rootfs,4096,d773a7ea,file_data,0,0,0,,0,data_change,/data_block_307
T+1007856,1007856,commit,0,transaction_end,0,,0,ef4d1f0a,transaction,0,0,0,,0,transaction_end,
```

### Forensic Summary Output
The tool also generates a comprehensive forensic analysis summary:
```
=== FORENSIC ANALYSIS SUMMARY ===
Journal Format: JBD2 (EXT3+/EXT4)
Inferred Mode: JOURNAL (Full data+metadata) (inferred from transaction patterns)
Total Transactions: 5688
Sequence Range: 1006559 - 1008457

--- STRING ANALYSIS RESULTS ---
Data Blocks with Readable Content: 542 / 1868 (29%)
Text File Blocks: 127
Configuration File Blocks: 89
Sample Extracted Content:
  [1] cloudimg-rootfs | ubuntu-server | /var/log/syslog
  [2] password=secret | database_host=localhost
Forensic Value: EXCELLENT - Recoverable file content detected
Next Steps: Full string extraction and content analysis recommended
```

## Forensic Applications

This tool is designed for defensive security and digital forensics:

### Primary Use Cases
- **Timeline Analysis**: Reconstruct filesystem activity chronology with relative timing
- **Data Recovery**: Extract human-readable content from journal data blocks
- **Content Analysis**: Recover deleted file fragments, configuration data, and log entries
- **Incident Response**: Track unauthorized file system changes and data modifications
- **Evidence Analysis**: Support legal and compliance investigations with comprehensive reports
- **System Auditing**: Monitor filesystem integrity and analyze change patterns

### Advanced Forensic Capabilities (v2.0)
- **String Extraction**: Recover readable content from journaled data blocks
- **Content Classification**: Automatically identify text files, configs, logs, and sensitive data
- **Pattern Analysis**: Detect URLs, credentials, file paths, and other forensically relevant content
- **Journal Mode Analysis**: Understand journaling behavior for evidence interpretation
- **Path Reconstruction**: Rebuild file system hierarchy from journal metadata

## Limitations

- **Read-only Analysis**: Tool performs non-invasive analysis of evidence images
- **Relative Timing**: No absolute timestamps - uses relative sequence ordering (T+0, T+1, etc.)
- **Content Dependency**: String extraction depends on journal mode (JOURNAL vs ORDERED)
- **Path Resolution**: File path reconstruction depends on available directory metadata in journal
- **Encrypted Data**: Cannot extract readable strings from encrypted or heavily compressed content

## Troubleshooting

### Journal Not Found Error
If you encounter "Warning: Journal not found in filesystem", try these steps:

1. **Verify filesystem has journal:**
   ```bash
   sudo fsck.ext4 -n /dev/loop0  # Should show journal recovery message
   ```

2. **Check journal location:**
   ```bash
   # Get journal inode details
   debugfs -R "stat <8>" example.raw
   
   # Calculate offset: start_block × block_size (usually 4096)
   # Example: block 262144 × 4096 = 1073741824 bytes
   ```

3. **For multi-partition images, use partition offset:**
   ```bash
   # Get partition layout
   mmls example.raw
   
   # Use partition offset for target partition
   ./ext-journal-analyzer -i example.raw --partition-offset 227328
   ```

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
