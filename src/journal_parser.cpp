#include "journal_parser.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <ctime>
#include <algorithm>

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
    
    for (long offset = journal_offset; offset < journal_offset + journal_size; offset += BLOCK_SIZE) {
        if (!image_handler.readBytes(offset, block_buffer, BLOCK_SIZE)) {
            continue; // Skip unreadable blocks
        }
        
        JournalHeader header;
        if (!parseJournalHeader(block_buffer, header)) {
            continue; // Skip blocks without valid journal header
        }
        
        // Filter by sequence number if specified
        if (start_seq >= 0 && (int)header.sequence < start_seq) {
            continue;
        }
        if (end_seq >= 0 && (int)header.sequence > end_seq) {
            break;
        }
        
        JournalBlockType block_type = static_cast<JournalBlockType>(header.block_type);
        
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
                    
                    transactions.push_back(trans);
                    
                    // Process data blocks for this transaction
                    for (const auto& desc : current_descriptors) {
                        JournalTransaction data_trans;
                        data_trans.timestamp = trans.timestamp;
                        data_trans.transaction_seq = header.sequence;
                        data_trans.block_type = "data";
                        data_trans.fs_block_num = desc.fs_block_num;
                        data_trans.operation_type = "filesystem_update";
                        data_trans.affected_inode = 0; // Would need filesystem analysis to determine
                        data_trans.file_path = "";
                        data_trans.data_size = BLOCK_SIZE;
                        data_trans.checksum = ""; // Would need actual data block to calculate
                        
                        transactions.push_back(data_trans);
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
                
                transactions.push_back(trans);
                break;
            }
        }
    }
    
    return transactions;
}

bool JournalParser::parseJournalHeader(const char* data, JournalHeader& header) {
    if (!data) return false;
    
    // Copy header data (assuming little-endian host)
    memcpy(&header.magic, data, 4);
    memcpy(&header.block_type, data + 4, 4);
    memcpy(&header.sequence, data + 8, 4);
    
    // Validate magic number
    return (header.magic == JBD2_MAGIC);
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