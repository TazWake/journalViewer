# EXT3/4 Journal Forensics Tool - Developer Specification

## Project Overview

This specification defines the requirements for developing a command-line forensics tool that extracts and parses EXT3/4 filesystem journals from disk images, converting journal data into human-readable CSV format for forensic analysis.

### Core Objectives
- Read journal data from raw disk images (DD format) and EWF format images
- Parse EXT3/4 journal structures (JBD/JBD2) to extract transaction information
- Convert binary journal data to structured CSV format for forensic analysis
- Provide command-line interface for automated processing
- Support both Ubuntu and RHEL platforms

## Technical Requirements

### 1. Supported Input Formats
- **Raw Images**: DD format (standard bit-for-bit copies)
- **Expert Witness Format (EWF)**: EnCase .E01/.Ex01 files and variants
- **Multi-segment images**: Support for split EWF files (.E01, .E02, etc.)

### 2. Target Filesystems
- **EXT3**: Traditional journaled filesystem with JBD (Journal Block Device)
- **EXT4**: Modern filesystem with JBD2 (Journal Block Device 2)
- **Both internal and external journals**: Support journals stored as regular files (inode 8) or external devices

### 3. Platform Support
- **Primary**: Ubuntu LTS (18.04+) and RHEL/CentOS (7+)
- **Architecture**: x86_64
- **Deployment**: Standalone binary (compiled version priority)

## Implementation Strategy

### Priority 1: Compiled Binary (C++)

#### Required Dependencies
```bash
# Ubuntu/Debian
sudo apt-get install build-essential cmake libewf-dev

# RHEL/CentOS  
sudo yum install gcc-c++ cmake libewf-devel
# or for newer versions
sudo dnf install gcc-c++ cmake libewf-devel
```

#### Key Libraries
1. **libewf** (>=20171104): Expert Witness Format support
   - Header: `#include <libewf.h>`
   - Link: `-lewf`
   
2. **Standard C++ libraries**: `<fstream>`, `<iostream>`, `<vector>`, `<string>`

#### Core Architecture
```cpp
class JournalAnalyzer {
private:
    std::unique_ptr<ImageHandler> image_handler;
    std::unique_ptr<JournalParser> journal_parser;
    std::unique_ptr<CSVExporter> csv_exporter;
    
public:
    bool openImage(const std::string& image_path, ImageType type);
    bool locateJournal();
    std::vector<JournalTransaction> parseJournal();
    bool exportToCSV(const std::string& output_path);
};
```

### Priority 2: Python Implementation

#### Required Dependencies
```bash
pip install pytsk3 pyewf struct
```

#### Key Libraries
1. **pytsk3**: Python bindings for The Sleuth Kit
2. **pyewf**: Python bindings for libewf
3. **struct**: Binary data parsing (built-in)

## Journal Structure Analysis

### Journal Location
The EXT3/4 journal is typically located at:
- **Internal journal**: Inode 8 (most common)
- **External journal**: Separate device specified in superblock
- **Journal size**: Up to 2^32 blocks for embedded journals

### JBD2 Data Structures (Big-Endian Format)

#### Journal Header (12 bytes)
```cpp
struct journal_header_t {
    uint32_be h_magic;      // 0xC03B3998 (JBD2 magic)
    uint32_be h_blocktype;  // Block type (1=descriptor, 2=commit, etc.)
    uint32_be h_sequence;   // Transaction sequence number
};
```

#### Transaction Structure
Each transaction consists of:
1. **Descriptor Block**: Lists filesystem blocks being updated
2. **Data Blocks**: Actual filesystem data being journaled  
3. **Commit Block**: Marks transaction completion

#### Block Types
- `1`: Descriptor block
- `2`: Commit block  
- `3`: Journal superblock v1
- `4`: Journal superblock v2
- `5`: Revocation block

## CSV Output Format

### Recommended CSV Schema
```csv
timestamp,transaction_seq,block_type,fs_block_num,operation_type,affected_inode,file_path,data_size,checksum
2024-01-15T10:30:45Z,295,descriptor,163,directory_update,5,/root,4096,a1b2c3d4
2024-01-15T10:30:45Z,295,data,163,directory_entry,11,/root/new_file.txt,32,e5f6a7b8
2024-01-15T10:30:45Z,295,commit,0,transaction_end,0,,0,12345678
```

### Field Descriptions
- **timestamp**: Transaction commit time (ISO 8601 format)
- **transaction_seq**: Journal sequence number
- **block_type**: Type of journal block (descriptor/data/commit/revocation)
- **fs_block_num**: Filesystem block number being modified
- **operation_type**: Inferred operation (file_creation, deletion, directory_update, etc.)
- **affected_inode**: Inode number when determinable
- **file_path**: File path when recoverable from directory entries
- **data_size**: Size of data block
- **checksum**: Block checksum for integrity verification

## Command Line Interface

### Primary Binary: `ext-journal-analyzer`

#### Basic Usage
```bash
ext-journal-analyzer -i <image_file> -o <output.csv> [options]
```

#### Arguments
- `-i, --image`: Input image file path (required)
- `-o, --output`: Output CSV file path (required)  
- `-t, --type`: Image type (auto|raw|ewf) [default: auto]
- `-v, --verbose`: Verbose output
- `-h, --help`: Display help information
- `--version`: Display version information

#### Advanced Options
- `--journal-offset`: Manual journal offset (bytes)
- `--journal-size`: Manual journal size (bytes)
- `--start-seq`: Start from specific sequence number
- `--end-seq`: End at specific sequence number
- `--no-header`: Omit CSV header row

#### Example Usage
```bash
# Process EWF image
./ext-journal-analyzer -i evidence.E01 -o journal_analysis.csv -v

# Process raw image with manual journal location
./ext-journal-analyzer -i disk.dd -o output.csv --journal-offset 1048576

# Process only specific transaction range
./ext-journal-analyzer -i evidence.E01 -o filtered.csv --start-seq 100 --end-seq 200
```

## Build System

### CMake Configuration (CMakeLists.txt)
```cmake
cmake_minimum_required(VERSION 3.10)
project(ext-journal-analyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBEWF REQUIRED libewf)

include_directories(${LIBEWF_INCLUDE_DIRS})
link_directories(${LIBEWF_LIBRARY_DIRS})

add_executable(ext-journal-analyzer
    src/main.cpp
    src/image_handler.cpp
    src/journal_parser.cpp
    src/csv_exporter.cpp
)

target_link_libraries(ext-journal-analyzer ${LIBEWF_LIBRARIES})
```

### Build Instructions
```bash
# Clone or extract source code
cd ext-journal-analyzer

# Create build directory
mkdir build && cd build

# Configure with CMake
cmake ..

# Compile
make -j$(nproc)

# Install (optional)
sudo make install
```

## Implementation Phases

### Phase 1: Core Infrastructure (Week 1-2)
1. Implement image handler classes for raw and EWF formats
2. Create basic journal superblock detection
3. Implement journal header parsing
4. Design CSV output structure

### Phase 2: Journal Parsing (Week 3-4)
1. Parse descriptor blocks and extract filesystem block lists
2. Parse commit blocks and transaction boundaries
3. Implement revocation block handling
4. Add transaction sequence tracking

### Phase 3: Data Interpretation (Week 5-6)
1. Correlate journal data with filesystem metadata
2. Implement inode resolution where possible
3. Add directory entry reconstruction
4. Implement file path resolution

### Phase 4: Enhanced Features (Week 7-8)
1. Add filtering and search capabilities
2. Implement integrity checking
3. Add progress reporting
4. Performance optimization

## Error Handling and Validation

### Critical Validations
1. **Magic number verification**: Ensure 0xC03B3998 for JBD2
2. **Checksum validation**: Verify block checksums when available
3. **Sequence consistency**: Check transaction sequence ordering
4. **Block boundary validation**: Ensure reads don't exceed image size

### Error Recovery
- Continue processing on non-critical errors
- Log all errors with specific details
- Provide partial results when possible
- Clear error messages for common issues

## Testing Strategy

### Unit Tests
- Journal structure parsing
- CSV output formatting  
- Image format detection
- Error condition handling

### Integration Tests
- Test with known good EXT3/4 images
- Validate against reference implementations
- Cross-platform compatibility testing
- Performance benchmarking

### Test Data Requirements
- Clean EXT3/4 filesystem images
- Images with active journal transactions
- Corrupted/partially damaged images
- Large filesystem images (>1TB)

## Future Enhancement Opportunities

### Short-term Enhancements
1. **Live filesystem analysis**: Support for mounted filesystems
2. **Timeline generation**: Automatic timeline creation from journal data
3. **Advanced filtering**: Complex query capabilities
4. **Batch processing**: Multiple image processing
5. **Progress indication**: Real-time progress reporting

### Medium-term Features
1. **GUI interface**: Graphical frontend for the tool
2. **Database export**: SQLite/PostgreSQL output options
3. **Integration hooks**: API for integration with other forensic tools
4. **Automated reporting**: HTML/PDF report generation
5. **Metadata correlation**: Cross-reference with file system metadata

### Long-term Possibilities
1. **Machine learning integration**: Pattern detection in journal activity
2. **Distributed processing**: Cluster-based analysis for large datasets
3. **Real-time monitoring**: Live system journal monitoring
4. **Cloud integration**: Cloud storage and processing capabilities
5. **Advanced visualization**: Interactive timeline and relationship mapping

## Security Considerations

### Data Integrity
- Verify image file integrity before processing
- Maintain chain of custody through checksums
- Document all processing steps in audit log

### Privacy Protection
- Ensure no sensitive data leakage in debug output
- Implement secure temporary file handling
- Clear memory of sensitive data after processing

## Performance Targets

### Minimum Requirements
- **Processing speed**: >50MB/s on modern hardware
- **Memory usage**: <1GB RAM for typical images
- **Disk I/O**: Efficient sequential reads, minimal seeks

### Optimization Strategies
- Memory-mapped file access for large images
- Multi-threaded processing where applicable
- Efficient data structures for journal parsing
- Streaming CSV output to handle large datasets

## Documentation Requirements

### User Documentation
- Installation guide for Ubuntu and RHEL
- Command-line reference with examples
- Troubleshooting guide
- Output format specification

### Developer Documentation
- Code architecture overview
- API documentation
- Build system documentation
- Contributing guidelines

## Conclusion

This specification provides a comprehensive framework for implementing a professional-grade EXT3/4 journal forensics tool. The modular design allows for incremental development while ensuring extensibility for future enhancements. The focus on both compiled and Python implementations provides flexibility for different deployment scenarios and user preferences.

**Priority**: Focus initially on the compiled C++ version for performance, with Python implementation following once core functionality is proven and stable.

**Validation**: All implementation decisions should be validated against actual EXT3/4 journal structures and existing forensic tool outputs where possible.

**Certainty Level**: High confidence in core journal structure specifications (based on Linux kernel documentation), moderate confidence in optimal CSV schema (subject to user feedback and practical testing).