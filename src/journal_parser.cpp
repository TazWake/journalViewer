#include "journal_parser.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <unordered_set>

// EXT4 constants
static const uint16_t EXT4_FT_REG_FILE = 0x8000;   // Regular file
static const uint16_t EXT4_FT_DIR = 0x4000;        // Directory
static const uint16_t EXT4_FT_CHRDEV = 0x2000;     // Character device
static const uint16_t EXT4_FT_BLKDEV = 0x6000;     // Block device
static const uint16_t EXT4_FT_FIFO = 0x1000;       // FIFO
static const uint16_t EXT4_FT_SOCK = 0xC000;       // Socket
static const uint16_t EXT4_FT_SYMLINK = 0xA000;    // Symbolic link

static const size_t EXT4_INODE_SIZE = 128;         // Standard EXT4 inode size
static const uint32_t EXT4_VALID_INUM = 11;        // First valid inode number

// EXT4 directory entry file types
static const uint8_t EXT4_FT_UNKNOWN = 0;          // Unknown file type
static const uint8_t EXT4_FT_REG_FILE_DIR = 1;     // Regular file (in dir entry)
static const uint8_t EXT4_FT_DIR_DIR = 2;          // Directory (in dir entry)
static const uint8_t EXT4_FT_CHRDEV_DIR = 3;       // Character device (in dir entry)
static const uint8_t EXT4_FT_BLKDEV_DIR = 4;       // Block device (in dir entry)
static const uint8_t EXT4_FT_FIFO_DIR = 5;         // FIFO (in dir entry)
static const uint8_t EXT4_FT_SOCK_DIR = 6;         // Socket (in dir entry)
static const uint8_t EXT4_FT_SYMLINK_DIR = 7;      // Symbolic link (in dir entry)

JournalParser::JournalParser() {
}

JournalParser::~JournalParser() {
}

std::vector<JournalTransaction> JournalParser::parseJournal(ImageHandler& image_handler, 
                                                           int start_seq, 
                                                           int end_seq) {
    std::vector<JournalTransaction> transactions;
    
    if (!image_handler.isJournalFound()) {
        std::cerr << "Error: Journal not located in image" << std::endl;
        return transactions;
    }
    
    long journal_offset = image_handler.getJournalOffset();
    long journal_size = image_handler.getJournalSize();
    
    // If journal size is not known, try to determine from superblock
    if (journal_size <= 0) {
        JournalSuperblock sb;
        if (parseJournalSuperblock(image_handler, journal_offset, sb)) {
            journal_size = sb.max_len * sb.block_size;
        } else {
            // Use a reasonable default size for scanning
            journal_size = 128 * 1024 * 1024; // 128MB default
        }
    }
    
    std::cout << "Parsing journal at offset " << journal_offset 
              << " with size " << journal_size << " bytes" << std::endl;
    
    // Parse journal blocks
    char block_buffer[BLOCK_SIZE];
    uint32_t current_transaction_seq = 0;
    std::vector<DescriptorEntry> current_descriptors;
    int blocks_scanned = 0;
    int valid_headers = 0;
    
    for (long offset = journal_offset; offset < journal_offset + journal_size; offset += BLOCK_SIZE) {
        blocks_scanned++;
        
        if (!image_handler.readBytes(offset, block_buffer, BLOCK_SIZE)) {
            if (blocks_scanned <= 10) {
                std::cout << "Debug: Block " << blocks_scanned << " at offset " << offset << " - read failed" << std::endl;
            }
            continue; // Skip unreadable blocks
        }
        
        JournalHeader header;
        if (!parseJournalHeader(block_buffer, header)) {
            if (blocks_scanned <= 10) {
                uint32_t* magic = reinterpret_cast<uint32_t*>(block_buffer);
                std::cout << "Debug: Block " << blocks_scanned << " at offset " << offset 
                          << " - invalid header, magic=0x" << std::hex << *magic << std::dec << std::endl;
            }
            continue; // Skip blocks without valid journal header
        }
        
        valid_headers++;
        if (blocks_scanned <= 10) {
            std::cout << "Debug: Block " << blocks_scanned << " at offset " << offset 
                      << " - valid header, magic=0x" << std::hex << header.magic 
                      << " type=" << std::dec << header.block_type 
                      << " seq=" << header.sequence << std::endl;
            
            // Show raw header bytes for first few blocks
            if (blocks_scanned <= 3) {
                std::cout << "  Raw header bytes: ";
                for (int i = 0; i < 12; i++) {
                    printf("%02x ", (unsigned char)block_buffer[i]);
                }
                std::cout << std::endl;
            }
        }
        
        // Filter by sequence number if specified
        if (start_seq >= 0 && (int)header.sequence < start_seq) {
            continue;
        }
        if (end_seq >= 0 && (int)header.sequence > end_seq) {
            break;
        }
        
        JournalBlockType block_type = static_cast<JournalBlockType>(header.block_type);
        
        if (blocks_scanned <= 5) {
            std::cout << "  Processing block type " << header.block_type << " (mapped to " << (int)block_type << ")" << std::endl;
        }
        
        switch (block_type) {
            case JournalBlockType::DESCRIPTOR: {
                current_transaction_seq = header.sequence;
                current_descriptors = parseDescriptorBlock(block_buffer + JOURNAL_HEADER_SIZE, 
                                                         BLOCK_SIZE - JOURNAL_HEADER_SIZE);
                
                // Create transaction record for descriptor block
                JournalTransaction trans;
                trans.timestamp = formatTimestamp(0); // Will be set at commit
                trans.transaction_seq = header.sequence;
                trans.block_type = "descriptor";
                trans.fs_block_num = 0;
                trans.operation_type = "transaction_start";
                trans.affected_inode = 0;
                trans.file_path = "";
                trans.data_size = current_descriptors.size() * sizeof(DescriptorEntry);
                trans.checksum = calculateChecksum(block_buffer, BLOCK_SIZE);
                
                // Initialize Phase 1 fields
                trans.file_type = "transaction";
                trans.file_size = 0;
                trans.inode_number = 0;
                trans.link_count = 0;
                
                // Initialize Phase 2 fields
                trans.filename = "";
                trans.parent_dir_inode = 0;
                trans.change_type = "transaction_start";
                
                // Initialize Phase 3 fields
                trans.full_path = "";
                
                transactions.push_back(trans);
                break;
            }
            
            case JournalBlockType::COMMIT: {
                uint32_t commit_seq;
                if (parseCommitBlock(block_buffer + JOURNAL_HEADER_SIZE, 
                                   BLOCK_SIZE - JOURNAL_HEADER_SIZE, commit_seq)) {
                    
                    // Create transaction record for commit block
                    JournalTransaction trans;
                    trans.timestamp = formatTimestamp(std::time(nullptr)); // Use current time as placeholder
                    trans.transaction_seq = header.sequence;
                    trans.block_type = "commit";
                    trans.fs_block_num = 0;
                    trans.operation_type = "transaction_end";
                    trans.affected_inode = 0;
                    trans.file_path = "";
                    trans.data_size = 0;
                    trans.checksum = calculateChecksum(block_buffer, BLOCK_SIZE);
                    
                    // Initialize Phase 1 fields
                    trans.file_type = "transaction";
                    trans.file_size = 0;
                    trans.inode_number = 0;
                    trans.link_count = 0;
                    
                    // Initialize Phase 2 fields
                    trans.filename = "";
                    trans.parent_dir_inode = 0;
                    trans.change_type = "transaction_end";
                    
                    // Initialize Phase 3 fields
                    trans.full_path = "";
                    
                    transactions.push_back(trans);
                    
                    // Process data blocks for this transaction with Phase 1 analysis
                    size_t data_block_index = 0;
                    for (const auto& desc : current_descriptors) {
                        // Calculate the offset of this data block in the journal
                        long data_block_offset = offset + BLOCK_SIZE * (1 + data_block_index);
                        
                        // Read the actual data block from journal
                        char data_block_buffer[BLOCK_SIZE];
                        bool data_read_success = false;
                        if (data_block_offset < journal_offset + journal_size) {
                            data_read_success = image_handler.readBytes(data_block_offset, data_block_buffer, BLOCK_SIZE);
                        }
                        
                        JournalTransaction data_trans;
                        data_trans.timestamp = trans.timestamp;
                        data_trans.transaction_seq = header.sequence;
                        data_trans.block_type = "data";
                        data_trans.fs_block_num = desc.fs_block_num;
                        data_trans.data_size = BLOCK_SIZE;
                        
                        // Initialize Phase 1 fields with defaults
                        data_trans.file_type = "unknown";
                        data_trans.file_size = 0;
                        data_trans.inode_number = 0;
                        data_trans.link_count = 0;
                        data_trans.affected_inode = 0;
                        data_trans.file_path = "";
                        
                        // Initialize Phase 2 fields with defaults
                        data_trans.filename = "";
                        data_trans.parent_dir_inode = 0;
                        data_trans.change_type = "unknown";
                        
                        // Initialize Phase 3 fields with defaults
                        data_trans.full_path = "";
                        
                        if (data_read_success) {
                            data_trans.checksum = calculateChecksum(data_block_buffer, BLOCK_SIZE);
                            
                            // Analyze block content with Phase 1 functionality
                            BlockContentType content_type = identifyBlockType(data_block_buffer, BLOCK_SIZE);
                            
                            switch (content_type) {
                                case BlockContentType::INODE_TABLE: {
                                    data_trans.operation_type = "inode_update";
                                    
                                    // Parse inode information
                                    std::vector<EXT4Inode> inodes;
                                    std::vector<uint32_t> inode_numbers;
                                    if (parseInodeBlock(data_block_buffer, BLOCK_SIZE, inodes, inode_numbers)) {
                                        if (!inodes.empty()) {
                                            // Phase 3: Update directory tree with inode information
                                            updateDirectoryTreeFromInodes(inodes, inode_numbers);
                                            
                                            // Use data from first valid inode found
                                            const EXT4Inode& first_inode = inodes[0];
                                            data_trans.file_type = getFileTypeString(first_inode.mode);
                                            data_trans.file_size = getFullFileSize(first_inode);
                                            data_trans.inode_number = inode_numbers[0];
                                            data_trans.link_count = first_inode.links_count;
                                            data_trans.affected_inode = inode_numbers[0];
                                            
                                            // Phase 3: Build full path for inode
                                            data_trans.full_path = buildFullPath(inode_numbers[0]);
                                            
                                            // If multiple inodes, indicate this in operation type
                                            if (inodes.size() > 1) {
                                                data_trans.operation_type = "inode_batch_update";
                                            }
                                        }
                                    }
                                    break;
                                }
                                
                                case BlockContentType::DIRECTORY: {
                                    data_trans.operation_type = "directory_update";
                                    data_trans.file_type = "directory";
                                    
                                    // Phase 2: Parse directory entries
                                    std::vector<EXT4DirectoryEntry> dir_entries;
                                    if (parseDirectoryBlock(data_block_buffer, BLOCK_SIZE, dir_entries)) {
                                        if (!dir_entries.empty()) {
                                            // Phase 3: Update directory tree with entries
                                            uint32_t parent_inode = desc.fs_block_num; // Approximate parent inode
                                            updateDirectoryTree(dir_entries, parent_inode);
                                            
                                            // Use information from first valid directory entry
                                            const EXT4DirectoryEntry& first_entry = dir_entries[0];
                                            
                                            // Set Phase 2 fields
                                            data_trans.filename = first_entry.name;
                                            data_trans.parent_dir_inode = parent_inode;
                                            
                                            // Determine operation type based on directory analysis
                                            std::vector<EXT4Inode> empty_inodes; // Will be enhanced later
                                            FileOperationType op_type = inferFileOperation(dir_entries, empty_inodes, header.sequence);
                                            data_trans.operation_type = getOperationTypeString(op_type);
                                            
                                            // Analyze change type
                                            ChangeType change_type = analyzeDirectoryChanges(dir_entries);
                                            data_trans.change_type = getChangeTypeString(change_type);
                                            
                                            // Phase 3: Build full path for first entry
                                            data_trans.full_path = buildFullPath(first_entry.inode);
                                            
                                            // If multiple entries, create additional transactions
                                            for (size_t i = 1; i < dir_entries.size(); ++i) {
                                                JournalTransaction additional_trans = data_trans;
                                                additional_trans.filename = dir_entries[i].name;
                                                additional_trans.affected_inode = dir_entries[i].inode;
                                                additional_trans.inode_number = dir_entries[i].inode;
                                                additional_trans.full_path = buildFullPath(dir_entries[i].inode);
                                                transactions.push_back(additional_trans);
                                            }
                                            
                                            // Update main transaction with first entry info
                                            data_trans.affected_inode = first_entry.inode;
                                            data_trans.inode_number = first_entry.inode;
                                        }
                                    }
                                    break;
                                }
                                
                                case BlockContentType::METADATA: {
                                    data_trans.operation_type = "metadata_update";
                                    data_trans.file_type = "metadata";
                                    data_trans.change_type = "metadata_change";
                                    data_trans.full_path = "/metadata_block_" + std::to_string(desc.fs_block_num);
                                    break;
                                }
                                
                                case BlockContentType::FILE_DATA: {
                                    data_trans.operation_type = "file_data_update";
                                    data_trans.file_type = "file_data";
                                    data_trans.change_type = "data_change";
                                    data_trans.full_path = "/data_block_" + std::to_string(desc.fs_block_num);
                                    break;
                                }
                                
                                default: {
                                    data_trans.operation_type = "filesystem_update";
                                    data_trans.change_type = "unknown";
                                    data_trans.full_path = "/unknown_block_" + std::to_string(desc.fs_block_num);
                                    break;
                                }
                            }
                        } else {
                            data_trans.operation_type = "filesystem_update";
                            data_trans.checksum = "";
                        }
                        
                        transactions.push_back(data_trans);
                        data_block_index++;
                    }
                    
                    current_descriptors.clear();
                }
                break;
            }
            
            case JournalBlockType::REVOCATION: {
                JournalTransaction trans;
                trans.timestamp = formatTimestamp(std::time(nullptr));
                trans.transaction_seq = header.sequence;
                trans.block_type = "revocation";
                trans.fs_block_num = 0;
                trans.operation_type = "block_revocation";
                trans.affected_inode = 0;
                trans.file_path = "";
                trans.data_size = BLOCK_SIZE - JOURNAL_HEADER_SIZE;
                trans.checksum = calculateChecksum(block_buffer, BLOCK_SIZE);
                
                // Initialize Phase 1 fields
                trans.file_type = "revocation";
                trans.file_size = 0;
                trans.inode_number = 0;
                trans.link_count = 0;
                
                // Initialize Phase 2 fields
                trans.filename = "";
                trans.parent_dir_inode = 0;
                trans.change_type = "block_revocation";
                
                // Initialize Phase 3 fields
                trans.full_path = "";
                
                transactions.push_back(trans);
                break;
            }
            
            case JournalBlockType::SUPERBLOCK_V1:
            case JournalBlockType::SUPERBLOCK_V2: {
                JournalTransaction trans;
                trans.timestamp = formatTimestamp(std::time(nullptr));
                trans.transaction_seq = header.sequence;
                trans.block_type = "superblock";
                trans.fs_block_num = 0;
                trans.operation_type = "journal_superblock";
                trans.affected_inode = 0;
                trans.file_path = "";
                trans.data_size = BLOCK_SIZE - JOURNAL_HEADER_SIZE;
                trans.checksum = calculateChecksum(block_buffer, BLOCK_SIZE);
                
                // Initialize Phase 1 fields
                trans.file_type = "superblock";
                trans.file_size = 0;
                trans.inode_number = 0;
                trans.link_count = 0;
                
                // Initialize Phase 2 fields
                trans.filename = "";
                trans.parent_dir_inode = 0;
                trans.change_type = "journal_init";
                
                // Initialize Phase 3 fields
                trans.full_path = "/";
                
                transactions.push_back(trans);
                break;
            }
        }
    }
    
    std::cout << "Debug: Scanned " << blocks_scanned << " blocks, found " << valid_headers 
              << " valid headers, created " << transactions.size() << " transactions" << std::endl;
    
    return transactions;
}

bool JournalParser::parseJournalHeader(const char* data, JournalHeader& header) {
    if (!data) return false;
    
    // Copy header data - the data is stored in big-endian format in the journal
    memcpy(&header.magic, data, 4);
    
    // Block type and sequence are stored as big-endian, need to convert
    uint32_t block_type_be, sequence_be;
    memcpy(&block_type_be, data + 4, 4);
    memcpy(&sequence_be, data + 8, 4);
    
    // Convert from big-endian to host byte order
    header.block_type = __builtin_bswap32(block_type_be);
    header.sequence = __builtin_bswap32(sequence_be);
    
    // Validate magic number (accept both JBD and JBD2)
    return (header.magic == JBD2_MAGIC || header.magic == JBD_MAGIC);
}

std::vector<DescriptorEntry> JournalParser::parseDescriptorBlock(const char* data, size_t size) {
    std::vector<DescriptorEntry> entries;
    
    if (!data || size < 8) return entries;
    
    // Parse descriptor entries (simplified)
    // Each entry is typically 8 bytes: 4 bytes block number + 4 bytes flags
    size_t entry_count = size / 8;
    
    for (size_t i = 0; i < entry_count && i * 8 + 8 <= size; ++i) {
        DescriptorEntry entry;
        memcpy(&entry.fs_block_num, data + i * 8, 4);
        memcpy(&entry.flags, data + i * 8 + 4, 4);
        
        // Basic validation - block number should be reasonable
        if (entry.fs_block_num > 0 && entry.fs_block_num < 0xFFFFFFFF) {
            entries.push_back(entry);
        }
    }
    
    return entries;
}

bool JournalParser::parseCommitBlock(const char* data, size_t size, uint32_t& sequence) {
    if (!data || size < 4) return false;
    
    // Commit block typically contains timestamp and other metadata
    // For now, we'll just extract basic information
    memcpy(&sequence, data, 4);
    
    return true;
}

std::string JournalParser::inferOperationType(const char* data, size_t size) {
    // This is a simplified heuristic - real implementation would analyze
    // the actual filesystem structures being modified
    
    if (!data || size == 0) return "unknown";
    
    // Look for common patterns in the data
    // This is highly simplified and would need extensive filesystem knowledge
    return "filesystem_update";
}

std::string JournalParser::calculateChecksum(const char* data, size_t size) {
    if (!data || size == 0) return "";
    
    // Simple CRC32-like checksum (simplified implementation)
    uint32_t checksum = 0;
    for (size_t i = 0; i < size; ++i) {
        checksum = checksum * 31 + static_cast<unsigned char>(data[i]);
    }
    
    std::stringstream ss;
    ss << std::hex << std::setw(8) << std::setfill('0') << checksum;
    return ss.str();
}

std::string JournalParser::formatTimestamp(uint64_t unix_timestamp) {
    if (unix_timestamp == 0) {
        unix_timestamp = std::time(nullptr);
    }
    
    std::time_t time = static_cast<std::time_t>(unix_timestamp);
    std::tm* tm_info = std::gmtime(&time);
    
    std::stringstream ss;
    ss << std::put_time(tm_info, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

std::string JournalParser::blockTypeToString(JournalBlockType type) {
    switch (type) {
        case JournalBlockType::DESCRIPTOR: return "descriptor";
        case JournalBlockType::COMMIT: return "commit";
        case JournalBlockType::SUPERBLOCK_V1: return "superblock_v1";
        case JournalBlockType::SUPERBLOCK_V2: return "superblock_v2";
        case JournalBlockType::REVOCATION: return "revocation";
        default: return "unknown";
    }
}

bool JournalParser::parseJournalSuperblock(ImageHandler& image_handler, long offset, JournalSuperblock& sb) {
    char buffer[BLOCK_SIZE];
    
    if (!image_handler.readBytes(offset, buffer, BLOCK_SIZE)) {
        return false;
    }
    
    JournalHeader header;
    if (!parseJournalHeader(buffer, header)) {
        return false;
    }
    
    if (header.block_type != static_cast<uint32_t>(JournalBlockType::SUPERBLOCK_V2)) {
        return false;
    }
    
    // Parse journal superblock fields (simplified)
    const char* sb_data = buffer + JOURNAL_HEADER_SIZE;
    memcpy(&sb.block_size, sb_data, 4);
    memcpy(&sb.max_len, sb_data + 4, 4);
    memcpy(&sb.first_transaction, sb_data + 8, 4);
    memcpy(&sb.sequence, sb_data + 12, 4);
    
    // Basic validation
    if (sb.block_size != BLOCK_SIZE || sb.max_len == 0) {
        return false;
    }
    
    return true;
}

bool JournalParser::validateJournalStructure(ImageHandler& image_handler) {
    if (!image_handler.isJournalFound()) {
        return false;
    }
    
    // Try to parse journal superblock
    JournalSuperblock sb;
    return parseJournalSuperblock(image_handler, image_handler.getJournalOffset(), sb);
}

size_t JournalParser::getEstimatedTransactionCount(ImageHandler& image_handler) {
    if (!image_handler.isJournalFound()) {
        return 0;
    }
    
    long journal_size = image_handler.getJournalSize();
    if (journal_size <= 0) {
        journal_size = 128 * 1024 * 1024; // Default 128MB
    }
    
    // Rough estimate: assume average transaction is 10 blocks
    return static_cast<size_t>(journal_size / (BLOCK_SIZE * 10));
}

// Phase 1 implementation: Parse inode blocks
bool JournalParser::parseInodeBlock(const char* data, size_t size, 
                                  std::vector<EXT4Inode>& inodes, 
                                  std::vector<uint32_t>& inode_numbers) {
    if (!data || size < EXT4_INODE_SIZE) {
        return false;
    }
    
    // Calculate how many inodes can fit in this block
    size_t max_inodes = size / EXT4_INODE_SIZE;
    
    for (size_t i = 0; i < max_inodes; ++i) {
        const char* inode_data = data + (i * EXT4_INODE_SIZE);
        EXT4Inode inode = {};
        
        // Parse inode structure (assuming little-endian host)
        memcpy(&inode.mode, inode_data + 0, 2);
        memcpy(&inode.uid, inode_data + 2, 2);
        memcpy(&inode.size_lo, inode_data + 4, 4);
        memcpy(&inode.atime, inode_data + 8, 4);
        memcpy(&inode.ctime, inode_data + 12, 4);
        memcpy(&inode.mtime, inode_data + 16, 4);
        memcpy(&inode.dtime, inode_data + 20, 4);
        memcpy(&inode.gid, inode_data + 24, 2);
        memcpy(&inode.links_count, inode_data + 26, 2);
        memcpy(&inode.blocks_lo, inode_data + 28, 4);
        memcpy(&inode.flags, inode_data + 32, 4);
        
        // Copy block pointers
        memcpy(inode.block, inode_data + 40, 60);
        
        // Parse remaining fields
        memcpy(&inode.generation, inode_data + 100, 4);
        memcpy(&inode.file_acl_lo, inode_data + 104, 4);
        memcpy(&inode.size_hi, inode_data + 108, 4);
        
        // Validate inode - check if it looks valid
        if (inode.mode != 0 && inode.links_count > 0 && inode.links_count < 65536) {
            // This looks like a valid inode
            inodes.push_back(inode);
            // Calculate inode number (this is simplified - real calculation needs block group info)
            inode_numbers.push_back(static_cast<uint32_t>(i + 1));
        }
    }
    
    return !inodes.empty();
}

// Identify what type of content a block contains
BlockContentType JournalParser::identifyBlockType(const char* data, size_t size) {
    if (!data || size < 16) {
        return BlockContentType::UNKNOWN;
    }
    
    // Check for inode table pattern
    // Look for multiple valid inode structures
    std::vector<EXT4Inode> temp_inodes;
    std::vector<uint32_t> temp_numbers;
    if (parseInodeBlock(data, size, temp_inodes, temp_numbers) && temp_inodes.size() >= 2) {
        return BlockContentType::INODE_TABLE;
    }
    
    // Check for directory entry pattern
    // Directory entries start with inode number (4 bytes) followed by record length
    const uint32_t* inode_num = reinterpret_cast<const uint32_t*>(data);
    const uint16_t* rec_len = reinterpret_cast<const uint16_t*>(data + 4);
    
    if (*inode_num > 0 && *inode_num < 0xFFFFFF && *rec_len >= 8 && *rec_len <= size) {
        // Additional check: name length should be reasonable
        const uint8_t* name_len = reinterpret_cast<const uint8_t*>(data + 6);
        if (*name_len > 0 && *name_len < 256) {
            return BlockContentType::DIRECTORY;
        }
    }
    
    // Check for metadata patterns (simplified)
    // Look for repeated patterns that might indicate metadata structures
    uint32_t pattern_count = 0;
    for (size_t i = 0; i < size - 4; i += 4) {
        const uint32_t* value = reinterpret_cast<const uint32_t*>(data + i);
        if (*value != 0 && *value < 0xFFFFFF) {
            pattern_count++;
        }
    }
    
    if (pattern_count > size / 16) {  // If more than 1/4 of 4-byte values look like block numbers
        return BlockContentType::METADATA;
    }
    
    return BlockContentType::FILE_DATA;
}

// Convert inode mode to readable file type string
std::string JournalParser::getFileTypeString(uint16_t mode) {
    uint16_t file_type = mode & 0xF000;  // Extract file type bits
    
    switch (file_type) {
        case EXT4_FT_REG_FILE: return "regular_file";
        case EXT4_FT_DIR: return "directory";
        case EXT4_FT_SYMLINK: return "symlink";
        case EXT4_FT_CHRDEV: return "char_device";
        case EXT4_FT_BLKDEV: return "block_device";
        case EXT4_FT_FIFO: return "fifo";
        case EXT4_FT_SOCK: return "socket";
        default: return "unknown";
    }
}

// Get full 64-bit file size from inode
uint64_t JournalParser::getFullFileSize(const EXT4Inode& inode) {
    return static_cast<uint64_t>(inode.size_lo) | 
           (static_cast<uint64_t>(inode.size_hi) << 32);
}

// Get full 32-bit UID from inode
uint32_t JournalParser::getFullUID(const EXT4Inode& inode) {
    return static_cast<uint32_t>(inode.uid) | 
           (static_cast<uint32_t>(inode.uid_hi) << 16);
}

// Get full 32-bit GID from inode
uint32_t JournalParser::getFullGID(const EXT4Inode& inode) {
    return static_cast<uint32_t>(inode.gid) | 
           (static_cast<uint32_t>(inode.gid_hi) << 16);
}

// Phase 2 implementation: Parse directory blocks
bool JournalParser::parseDirectoryBlock(const char* data, size_t size, 
                                       std::vector<EXT4DirectoryEntry>& entries) {
    if (!data || size < 8) {
        return false;
    }
    
    size_t offset = 0;
    entries.clear();
    
    while (offset < size) {
        // Need at least 8 bytes for directory entry header
        if (offset + 8 > size) {
            break;
        }
        
        EXT4DirectoryEntry entry = {};
        
        // Parse directory entry fields
        memcpy(&entry.inode, data + offset, 4);
        memcpy(&entry.rec_len, data + offset + 4, 2);
        memcpy(&entry.name_len, data + offset + 6, 1);
        memcpy(&entry.file_type, data + offset + 7, 1);
        
        // Validate entry
        if (entry.rec_len == 0 || entry.rec_len > size - offset) {
            break; // Invalid record length
        }
        
        if (entry.name_len > entry.rec_len - 8) {
            break; // Name length exceeds available space
        }
        
        // Extract filename if present
        if (entry.name_len > 0 && offset + 8 + entry.name_len <= size) {
            entry.name = std::string(data + offset + 8, entry.name_len);
            
            // Validate filename contains printable characters
            bool valid_name = true;
            for (char c : entry.name) {
                if (c < 0x20 || c > 0x7E) {
                    if (c != 0) { // Allow null termination
                        valid_name = false;
                        break;
                    }
                }
            }
            
            if (!valid_name) {
                entry.name = "<binary_name>";
            }
        }
        
        // Only add entries that look valid
        if (entry.inode > 0 && entry.inode < 0xFFFFFFFF && 
            entry.name_len < 256 && entry.rec_len >= 8) {
            entries.push_back(entry);
        }
        
        offset += entry.rec_len;
        
        // Safety check to prevent infinite loops
        if (entry.rec_len < 8) {
            break;
        }
    }
    
    return !entries.empty();
}

// Infer file operations from directory and inode analysis
FileOperationType JournalParser::inferFileOperation(const std::vector<EXT4DirectoryEntry>& entries,
                                                   const std::vector<EXT4Inode>& inodes,
                                                   uint32_t transaction_seq) {
    // This is a simplified heuristic-based approach
    // Real implementation would compare with previous transaction states
    
    if (entries.empty() && inodes.empty()) {
        return FileOperationType::UNKNOWN;
    }
    
    // Analyze directory entries for creation/deletion patterns
    if (!entries.empty()) {
        // Look for special patterns that indicate operations
        for (const auto& entry : entries) {
            // New entries with recent inodes likely indicate file creation
            if (entry.inode > 0 && entry.name != "." && entry.name != "..") {
                // Check if this looks like a new file/directory based on entry type
                switch (entry.file_type) {
                    case EXT4_FT_REG_FILE_DIR:
                        return FileOperationType::FILE_CREATED;
                    case EXT4_FT_DIR_DIR:
                        return FileOperationType::DIRECTORY_CREATED;
                    case EXT4_FT_SYMLINK_DIR:
                        return FileOperationType::FILE_CREATED; // Symlink creation
                    default:
                        return FileOperationType::FILE_CREATED;
                }
            }
        }
    }
    
    // Analyze inode changes
    if (!inodes.empty()) {
        for (const auto& inode : inodes) {
            // Check link count changes
            if (inode.links_count == 0) {
                return FileOperationType::FILE_DELETED;
            } else if (inode.links_count > 1) {
                return FileOperationType::HARD_LINK_CREATED;
            }
            
            // Check for recent modifications (simplified)
            if (inode.mtime > 0 || inode.ctime > 0) {
                return FileOperationType::FILE_MODIFIED;
            }
        }
    }
    
    return FileOperationType::UNKNOWN;
}

// Convert operation type to string
std::string JournalParser::getOperationTypeString(FileOperationType op_type) {
    switch (op_type) {
        case FileOperationType::FILE_CREATED: return "file_created";
        case FileOperationType::FILE_DELETED: return "file_deleted";
        case FileOperationType::FILE_RENAMED: return "file_renamed";
        case FileOperationType::FILE_MODIFIED: return "file_modified";
        case FileOperationType::DIRECTORY_CREATED: return "directory_created";
        case FileOperationType::DIRECTORY_DELETED: return "directory_deleted";
        case FileOperationType::HARD_LINK_CREATED: return "hard_link_created";
        case FileOperationType::HARD_LINK_REMOVED: return "hard_link_removed";
        case FileOperationType::PERMISSIONS_CHANGED: return "permissions_changed";
        case FileOperationType::OWNERSHIP_CHANGED: return "ownership_changed";
        default: return "unknown";
    }
}

// Convert change type to string
std::string JournalParser::getChangeTypeString(ChangeType change_type) {
    switch (change_type) {
        case ChangeType::NEW_ENTRY: return "new_entry";
        case ChangeType::REMOVED_ENTRY: return "removed_entry";
        case ChangeType::MODIFIED_ENTRY: return "modified_entry";
        case ChangeType::NAME_CHANGE: return "name_change";
        case ChangeType::INODE_CHANGE: return "inode_change";
        case ChangeType::SIZE_CHANGE: return "size_change";
        case ChangeType::LINK_COUNT_CHANGE: return "link_count_change";
        case ChangeType::PERMISSION_CHANGE: return "permission_change";
        case ChangeType::OWNERSHIP_CHANGE: return "ownership_change";
        default: return "unknown";
    }
}

// Analyze directory changes to determine change type
ChangeType JournalParser::analyzeDirectoryChanges(const std::vector<EXT4DirectoryEntry>& entries) {
    if (entries.empty()) {
        return ChangeType::UNKNOWN;
    }
    
    // This is simplified - real implementation would compare before/after states
    // For now, assume new entries indicate new files
    for (const auto& entry : entries) {
        if (entry.inode > 0 && entry.name != "." && entry.name != "..") {
            // Look for patterns that indicate different types of changes
            if (entry.name.find("~") != std::string::npos || 
                entry.name.find(".tmp") != std::string::npos) {
                return ChangeType::MODIFIED_ENTRY;
            }
            return ChangeType::NEW_ENTRY;
        }
    }
    
    return ChangeType::UNKNOWN;
}

// Phase 3 Implementation: DirectoryTreeBuilder class methods

DirectoryTreeBuilder::DirectoryTreeBuilder() : root_inode(EXT4_ROOT_INODE) {
    // Initialize root directory node
    DirectoryNode root_node;
    root_node.inode_number = EXT4_ROOT_INODE;
    root_node.parent_inode = EXT4_ROOT_INODE; // Root is its own parent
    root_node.name = "/";
    root_node.full_path = "/";
    root_node.is_directory = true;
    nodes[EXT4_ROOT_INODE] = root_node;
    path_cache[EXT4_ROOT_INODE] = "/";
}

DirectoryTreeBuilder::~DirectoryTreeBuilder() {
    nodes.clear();
    path_cache.clear();
    name_to_inode.clear();
}

void DirectoryTreeBuilder::addDirectoryEntry(uint32_t dir_inode, const EXT4DirectoryEntry& entry) {
    if (entry.inode == 0 || entry.name.empty()) {
        return;
    }
    
    // Skip self and parent references
    if (entry.name == "." || entry.name == "..") {
        return;
    }
    
    // Update or create node
    bool is_dir = (entry.file_type == EXT4_FT_DIR_DIR);
    updateNode(entry.inode, dir_inode, entry.name, is_dir);
    
    // Add to parent's children list
    auto parent_it = nodes.find(dir_inode);
    if (parent_it != nodes.end()) {
        auto& children = parent_it->second.children;
        if (std::find(children.begin(), children.end(), entry.inode) == children.end()) {
            children.push_back(entry.inode);
        }
    }
    
    // Clear cached paths since tree structure changed
    path_cache.clear();
}

void DirectoryTreeBuilder::addInodeInfo(uint32_t inode, const EXT4Inode& inode_data) {
    auto it = nodes.find(inode);
    if (it != nodes.end()) {
        // Update existing node with inode information
        it->second.is_directory = ((inode_data.mode & EXT4_FT_DIR) == EXT4_FT_DIR);
    }
}

void DirectoryTreeBuilder::updateNode(uint32_t inode, uint32_t parent_inode, const std::string& name, bool is_dir) {
    DirectoryNode& node = nodes[inode];
    node.inode_number = inode;
    node.parent_inode = parent_inode;
    node.name = name;
    node.is_directory = is_dir;
    node.full_path = ""; // Will be computed on demand
    
    // Update reverse lookup
    std::string lookup_key = std::to_string(parent_inode) + "/" + name;
    name_to_inode[lookup_key] = inode;
}

std::string DirectoryTreeBuilder::buildFullPath(uint32_t inode) {
    // Check cache first
    auto cache_it = path_cache.find(inode);
    if (cache_it != path_cache.end()) {
        return cache_it->second;
    }
    
    // Handle special cases
    if (inode == EXT4_ROOT_INODE) {
        path_cache[inode] = "/";
        return "/";
    }
    
    if (inode == EXT4_LOST_FOUND_INODE) {
        path_cache[inode] = "/lost+found";
        return "/lost+found";
    }
    
    // Find the node
    auto it = nodes.find(inode);
    if (it == nodes.end()) {
        std::string unknown_path = "/unknown_inode_" + std::to_string(inode);
        path_cache[inode] = unknown_path;
        return unknown_path;
    }
    
    const DirectoryNode& node = it->second;
    
    // Prevent infinite recursion
    static std::unordered_set<uint32_t> visiting;
    if (visiting.find(inode) != visiting.end()) {
        std::string cycle_path = "/cycle_detected_" + std::to_string(inode);
        path_cache[inode] = cycle_path;
        return cycle_path;
    }
    
    visiting.insert(inode);
    
    // Recursively build parent path
    std::string parent_path;
    if (node.parent_inode == inode) {
        // This node is its own parent (shouldn't happen except for root)
        parent_path = "";
    } else if (node.parent_inode == EXT4_ROOT_INODE) {
        parent_path = "";
    } else {
        parent_path = buildFullPath(node.parent_inode);
    }
    
    visiting.erase(inode);
    
    // Construct full path
    std::string full_path;
    if (parent_path.empty() || parent_path == "/") {
        full_path = "/" + node.name;
    } else {
        full_path = parent_path + "/" + node.name;
    }
    
    // Cache and return
    path_cache[inode] = full_path;
    return full_path;
}

std::string DirectoryTreeBuilder::resolvePath(uint32_t inode) {
    return buildFullPath(inode);
}

std::string DirectoryTreeBuilder::getParentPath(uint32_t inode) {
    auto it = nodes.find(inode);
    if (it != nodes.end() && it->second.parent_inode != inode) {
        return buildFullPath(it->second.parent_inode);
    }
    return "/";
}

bool DirectoryTreeBuilder::isValidPath(const std::string& path) {
    return !path.empty() && path[0] == '/' && path.find("cycle_detected") == std::string::npos;
}

bool DirectoryTreeBuilder::hasNode(uint32_t inode) const {
    return nodes.find(inode) != nodes.end();
}

const DirectoryNode* DirectoryTreeBuilder::getNode(uint32_t inode) const {
    auto it = nodes.find(inode);
    return (it != nodes.end()) ? &it->second : nullptr;
}

void DirectoryTreeBuilder::clearCache() {
    path_cache.clear();
}

void DirectoryTreeBuilder::printTree(uint32_t root_inode, int depth) const {
    auto it = nodes.find(root_inode);
    if (it == nodes.end()) return;
    
    const DirectoryNode& node = it->second;
    
    // Print indentation
    for (int i = 0; i < depth; ++i) {
        std::cout << "  ";
    }
    
    std::cout << node.name << " (inode: " << node.inode_number << ")" << std::endl;
    
    // Recursively print children
    if (depth < 10) { // Prevent excessive depth
        for (uint32_t child_inode : node.children) {
            printTree(child_inode, depth + 1);
        }
    }
}

// Phase 3 JournalParser methods

std::string JournalParser::buildFullPath(uint32_t inode) {
    return directory_tree.buildFullPath(inode);
}

std::string JournalParser::resolveInodePath(uint32_t inode) {
    return directory_tree.resolvePath(inode);
}

void JournalParser::updateDirectoryTree(const std::vector<EXT4DirectoryEntry>& entries, uint32_t parent_inode) {
    for (const auto& entry : entries) {
        directory_tree.addDirectoryEntry(parent_inode, entry);
    }
}

void JournalParser::updateDirectoryTreeFromInodes(const std::vector<EXT4Inode>& inodes, const std::vector<uint32_t>& inode_numbers) {
    for (size_t i = 0; i < inodes.size() && i < inode_numbers.size(); ++i) {
        directory_tree.addInodeInfo(inode_numbers[i], inodes[i]);
    }
}

std::string JournalParser::handleSpecialPaths(uint32_t inode, const std::string& name) {
    if (isRootDirectory(inode)) {
        return "/";
    }
    
    if (isLostAndFound(inode)) {
        return "/lost+found";
    }
    
    // Handle other special cases
    if (name.empty()) {
        return "/unknown_" + std::to_string(inode);
    }
    
    return name;
}

bool JournalParser::isRootDirectory(uint32_t inode) {
    return inode == 2; // EXT4 root directory inode
}

bool JournalParser::isLostAndFound(uint32_t inode) {
    return inode == 11; // Typical lost+found inode
}