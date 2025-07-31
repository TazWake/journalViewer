# EXT4 Journal Analysis Enhancement Plan

## Current Status
✅ Journal location detection working (block 262144)  
✅ Journal header parsing working (fixed byte order issues)  
✅ Basic transaction enumeration working (descriptor/commit/superblock blocks)  
✅ CSV export framework in place  

## Goal
Enhance journal analysis to extract meaningful filesystem operations (file creation, deletion, renames, directory operations) from journal transaction data.

## Implementation Phases

### Phase 1: Basic Inode Analysis ⭐ **START HERE**
**Goal**: Extract file metadata from journal blocks to identify what files were affected

#### Tasks:
1. **Inode Structure Parsing**
   - Implement `parseInodeBlock()` function in `journal_parser.cpp`
   - Parse EXT4 inode structure (128 bytes):
     - Mode (file type + permissions) - offset 0-1
     - UID/GID - offset 2-3, 24-25  
     - Size - offset 4-7 (lower), 108-111 (upper)
     - Timestamps - offset 8-11, 12-15, 16-19, 20-23
     - Link count - offset 26-27
     - Block pointers/extents - offset 40-99

2. **Block Type Detection**
   - Add `identifyBlockType()` function to determine if a journal data block contains:
     - Inode data (look for valid inode signatures)
     - Directory data (check for directory entry patterns)
     - File data (everything else)

3. **Enhanced Transaction Processing**
   - Modify descriptor block processing to analyze the actual data blocks
   - For each filesystem block referenced in descriptor:
     - Read the block data from journal
     - Identify block type (inode/directory/data)
     - Parse inode metadata if applicable

4. **CSV Enhancement Phase 1**
   - Add columns: `file_type`, `file_size`, `inode_number`, `link_count`
   - Update `JournalTransaction` struct in `journal_parser.h`

**Expected Output**:
```csv
timestamp,transaction_seq,block_type,fs_block_num,operation_type,inode_number,file_type,file_size,link_count,data_size,checksum
2022-12-12T21:42:23Z,1008008,descriptor,524382,inode_update,12345,regular_file,2048,1,4096,a1b2c3d4
```

### Phase 2: Directory Operations Detection
**Goal**: Identify file creation, deletion, and directory changes

#### Tasks:
1. **Directory Entry Parsing**
   - Implement `parseDirectoryBlock()` function
   - Parse EXT4 directory entry structure:
     - Inode number - offset 0-3
     - Record length - offset 4-5  
     - Name length - offset 6
     - File type - offset 7
     - Filename - offset 8+

2. **Operation Inference Logic**
   - Implement `inferFileOperation()` function
   - Compare before/after states to detect:
     - New directory entries = file creation
     - Removed directory entries = file deletion
     - Changed inode link counts = hard link operations
     - Modified directory sizes = directory structure changes

3. **Transaction Correlation**
   - Track related blocks within same transaction
   - Correlate inode changes with directory entry changes

**Expected Output**:
```csv
timestamp,transaction_seq,operation_type,inode_number,filename,parent_dir_inode,change_type,data_size,checksum
2022-12-12T21:42:23Z,1008008,file_created,12345,document.txt,5678,new_entry,4096,a1b2c3d4
```

### Phase 3: Path Resolution
**Goal**: Build complete file paths for forensic analysis

#### Tasks:
1. **Directory Tree Mapping**
   - Implement `DirectoryTreeBuilder` class
   - Maintain inode-to-parent mapping
   - Cache directory structures for performance

2. **Path Reconstruction**
   - Implement `buildFullPath()` function
   - Traverse from inode up to root directory
   - Handle special cases (root, lost+found, etc.)

3. **Enhanced CSV Output**
   - Add `full_path` column
   - Handle path changes for rename operations

**Expected Output**:
```csv
timestamp,transaction_seq,operation_type,inode_number,full_path,change_type,file_size,data_size,checksum
2022-12-12T21:42:23Z,1008008,file_created,12345,/home/user/documents/report.txt,new_file,2048,4096,a1b2c3d4
```

### Phase 4: Advanced Operations
**Goal**: Detect complex filesystem operations

#### Tasks:
1. **Rename Detection**
   - Compare directory entries across transactions
   - Detect when same inode appears with different names
   - Track file moves between directories

2. **Permission/Ownership Changes**
   - Compare inode mode, UID, GID across transactions
   - Detect chmod, chown operations

3. **Extended Attributes**
   - Parse extended attribute blocks if present
   - Track SELinux context changes, etc.

**Expected Output**:
```csv
timestamp,transaction_seq,operation_type,inode_number,full_path,old_path,change_type,old_value,new_value,data_size,checksum
2022-12-12T21:42:23Z,1008007,file_renamed,12345,/home/user/report.pdf,/home/user/draft.pdf,name_change,draft.pdf,report.pdf,4096,b2c3d4e5
```

## Implementation Notes

### Key Files to Modify:
- `src/journal_parser.h` - Add new structs and function declarations
- `src/journal_parser.cpp` - Implement parsing functions
- `src/csv_exporter.h` - Update CSV schema
- `src/csv_exporter.cpp` - Update export logic

### New Dependencies:
- EXT4 filesystem structure definitions
- Endianness handling utilities (already using `__builtin_bswap32`)

### Testing Strategy:
1. **Unit Tests**: Create test journal blocks with known content
2. **Integration Tests**: Use known filesystem operations and verify output
3. **Forensic Validation**: Compare output with tools like `jls`, `fls`, `istat`

### Performance Considerations:
- Cache frequently accessed inodes
- Limit directory tree depth for path resolution
- Process transactions in sequence order
- Use memory-mapped file access for large journals

## Technical References

### EXT4 Structures:
- **Inode Structure**: 128 bytes, well-documented layout
- **Directory Entry**: Variable length, type field indicates file type
- **Journal Block Header**: 12 bytes (already implemented)

### Journal Transaction Flow:
1. **Descriptor Block**: Lists filesystem blocks to be modified
2. **Data Blocks**: Contains the actual filesystem data being written
3. **Commit Block**: Marks transaction as complete

### Forensic Value:
- **File Timeline**: When files were created/modified/deleted
- **User Activity**: What operations were performed
- **Data Recovery**: Locate deleted file inodes and data blocks
- **Incident Response**: Track filesystem changes during compromise

## Next Steps

1. **Start with Phase 1**: Implement basic inode parsing
2. **Test with Current Dataset**: Use the starkskunk5.E01 image for testing
3. **Validate Output**: Compare with TSK tools (`istat`, `fls`) for accuracy
4. **Iterate**: Add functionality incrementally, testing each phase

## Development Environment Notes

- **Build**: Manual builds required on test platform (not Windows PowerShell)
- **Testing**: Use TSK commands for validation (`jls`, `istat`, `fls`)
- **Debugging**: Extensive debug output already in place for journal parsing