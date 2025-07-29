#ifndef JOURNAL_PARSER_H
#define JOURNAL_PARSER_H

#include <vector>
#include <string>
#include <cstdint>
#include "image_handler.h"

// JBD2 block types
enum class JournalBlockType {
    DESCRIPTOR = 1,
    COMMIT = 2,
    SUPERBLOCK_V1 = 3,
    SUPERBLOCK_V2 = 4,
    REVOCATION = 5
};

// Journal header structure (12 bytes)
struct JournalHeader {
    uint32_t magic;        // 0xC03B3998 for JBD2
    uint32_t block_type;   // Block type
    uint32_t sequence;     // Transaction sequence number
};

// Journal transaction record
struct JournalTransaction {
    std::string timestamp;          // ISO 8601 format
    uint32_t transaction_seq;       // Transaction sequence number
    std::string block_type;         // descriptor/data/commit/revocation
    uint64_t fs_block_num;         // Filesystem block number
    std::string operation_type;     // Inferred operation type
    uint64_t affected_inode;       // Inode number (if determinable)
    std::string file_path;         // File path (if recoverable)
    size_t data_size;              // Data block size
    std::string checksum;          // Block checksum (hex)
};

// Descriptor block entry
struct DescriptorEntry {
    uint64_t fs_block_num;
    uint32_t flags;
};

class JournalParser {
private:
    static const uint32_t JBD2_MAGIC = 0x9839B3C0; // Little-endian of 0xC03B3998
    static const size_t JOURNAL_HEADER_SIZE = 12;
    static const size_t BLOCK_SIZE = 4096; // Standard EXT block size
    
    // Helper methods
    bool parseJournalHeader(const char* data, JournalHeader& header);
    std::vector<DescriptorEntry> parseDescriptorBlock(const char* data, size_t size);
    bool parseCommitBlock(const char* data, size_t size, uint32_t& sequence);
    std::string inferOperationType(const char* data, size_t size);
    std::string calculateChecksum(const char* data, size_t size);
    std::string formatTimestamp(uint64_t unix_timestamp);
    std::string blockTypeToString(JournalBlockType type);
    
    // Journal superblock parsing
    struct JournalSuperblock {
        uint32_t block_size;
        uint32_t max_len;
        uint32_t first_transaction;
        uint32_t sequence;
    };
    
    bool parseJournalSuperblock(ImageHandler& image_handler, long offset, JournalSuperblock& sb);

public:
    JournalParser();
    ~JournalParser();
    
    // Main parsing interface
    std::vector<JournalTransaction> parseJournal(ImageHandler& image_handler, 
                                                int start_seq = -1, 
                                                int end_seq = -1);
    
    // Utility methods
    bool validateJournalStructure(ImageHandler& image_handler);
    size_t getEstimatedTransactionCount(ImageHandler& image_handler);
};

#endif // JOURNAL_PARSER_H