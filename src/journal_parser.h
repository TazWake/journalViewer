#ifndef JOURNAL_PARSER_H
#define JOURNAL_PARSER_H

#include <vector>
#include <string>
#include <cstdint>
#include <unordered_map>
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

// EXT4 inode structure (128 bytes)
struct EXT4Inode {
    uint16_t mode;          // File type and permissions
    uint16_t uid;           // User ID (lower 16 bits)
    uint32_t size_lo;       // File size (lower 32 bits)
    uint32_t atime;         // Access time
    uint32_t ctime;         // Change time
    uint32_t mtime;         // Modification time
    uint32_t dtime;         // Deletion time
    uint16_t gid;           // Group ID (lower 16 bits)
    uint16_t links_count;   // Hard link count
    uint32_t blocks_lo;     // Block count (lower 32 bits)
    uint32_t flags;         // Inode flags
    uint32_t osd1;          // OS dependent 1
    uint32_t block[15];     // Block pointers/extents
    uint32_t generation;    // File version
    uint32_t file_acl_lo;   // Extended attributes (lower 32 bits)
    uint32_t size_hi;       // File size (upper 32 bits)
    uint32_t obso_faddr;    // Obsolete fragment address
    uint16_t blocks_hi;     // Block count (upper 16 bits)
    uint16_t file_acl_hi;   // Extended attributes (upper 16 bits)
    uint16_t uid_hi;        // User ID (upper 16 bits)
    uint16_t gid_hi;        // Group ID (upper 16 bits)
    uint16_t checksum_lo;   // Inode checksum (lower 16 bits)
    uint16_t reserved;      // Reserved
    uint16_t extra_isize;   // Size of extra inode fields
    uint16_t checksum_hi;   // Inode checksum (upper 16 bits)
    uint32_t ctime_extra;   // Extra change time
    uint32_t mtime_extra;   // Extra modification time
    uint32_t atime_extra;   // Extra access time
    uint32_t crtime;        // Creation time
    uint32_t crtime_extra;  // Extra creation time
};

// Block content types
enum class BlockContentType {
    UNKNOWN,
    INODE_TABLE,
    DIRECTORY,
    FILE_DATA,
    METADATA
};

// EXT4 directory entry structure
struct EXT4DirectoryEntry {
    uint32_t inode;         // Inode number
    uint16_t rec_len;       // Record length
    uint8_t name_len;       // Name length
    uint8_t file_type;      // File type
    std::string name;       // Filename (variable length)
};

// File operation types for Phase 2
enum class FileOperationType {
    UNKNOWN,
    FILE_CREATED,
    FILE_DELETED,
    FILE_RENAMED,
    FILE_MODIFIED,
    DIRECTORY_CREATED,
    DIRECTORY_DELETED,
    HARD_LINK_CREATED,
    HARD_LINK_REMOVED,
    PERMISSIONS_CHANGED,
    OWNERSHIP_CHANGED
};

// Change type for tracking modifications
enum class ChangeType {
    UNKNOWN,
    NEW_ENTRY,
    REMOVED_ENTRY,
    MODIFIED_ENTRY,
    NAME_CHANGE,
    INODE_CHANGE,
    SIZE_CHANGE,
    LINK_COUNT_CHANGE,
    PERMISSION_CHANGE,
    OWNERSHIP_CHANGE
};

// Journal transaction record with Phase 1 enhancements
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
    
    // Phase 1 additions
    std::string file_type;         // File type (regular_file, directory, symlink, etc.)
    uint64_t file_size;            // File size from inode
    uint32_t inode_number;         // Specific inode number
    uint16_t link_count;           // Hard link count
    
    // Phase 2 additions
    std::string filename;          // Filename from directory entry
    uint32_t parent_dir_inode;     // Parent directory inode number
    std::string change_type;       // Type of change (new_entry, removed_entry, etc.)
    
    // Phase 3 additions
    std::string full_path;         // Complete file path from root
};

// Descriptor block entry
struct DescriptorEntry {
    uint64_t fs_block_num;
    uint32_t flags;
};

// Directory tree node for Phase 3
struct DirectoryNode {
    uint32_t inode_number;
    uint32_t parent_inode;
    std::string name;
    std::string full_path;
    bool is_directory;
    std::vector<uint32_t> children;
    
    DirectoryNode() : inode_number(0), parent_inode(0), name(""), full_path(""), is_directory(false) {}
};

// Phase 3: Directory tree builder and path resolver
class DirectoryTreeBuilder {
private:
    std::unordered_map<uint32_t, DirectoryNode> nodes;           // inode -> node mapping
    std::unordered_map<uint32_t, std::string> path_cache;        // inode -> cached full path
    std::unordered_map<std::string, uint32_t> name_to_inode;     // name -> inode mapping
    uint32_t root_inode;
    
    static const uint32_t EXT4_ROOT_INODE = 2;
    static const uint32_t EXT4_LOST_FOUND_INODE = 11;
    static const size_t MAX_PATH_DEPTH = 256;
    
public:
    DirectoryTreeBuilder();
    ~DirectoryTreeBuilder();
    
    // Core functionality
    void addDirectoryEntry(uint32_t dir_inode, const EXT4DirectoryEntry& entry);
    void addInodeInfo(uint32_t inode, const EXT4Inode& inode_data);
    std::string buildFullPath(uint32_t inode);
    void clearCache();
    
    // Path resolution
    std::string resolvePath(uint32_t inode);
    std::string getParentPath(uint32_t inode);
    bool isValidPath(const std::string& path);
    
    // Tree management
    void updateNode(uint32_t inode, uint32_t parent_inode, const std::string& name, bool is_dir);
    bool hasNode(uint32_t inode) const;
    const DirectoryNode* getNode(uint32_t inode) const;
    
    // Statistics and debugging
    size_t getNodeCount() const { return nodes.size(); }
    size_t getCacheSize() const { return path_cache.size(); }
    void printTree(uint32_t root_inode = EXT4_ROOT_INODE, int depth = 0) const;
};

class JournalParser {
private:
    static const uint32_t JBD2_MAGIC = 0x9839B3C0; // Little-endian of 0xC03B3998
    static const uint32_t JBD_MAGIC = 0x98393BC0;  // Little-endian of 0xC03B3998 (JBD/EXT3)
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
    
    // Phase 1: Inode and block analysis
    bool parseInodeBlock(const char* data, size_t size, std::vector<EXT4Inode>& inodes, std::vector<uint32_t>& inode_numbers);
    BlockContentType identifyBlockType(const char* data, size_t size);
    std::string getFileTypeString(uint16_t mode);
    uint64_t getFullFileSize(const EXT4Inode& inode);
    uint32_t getFullUID(const EXT4Inode& inode);
    uint32_t getFullGID(const EXT4Inode& inode);
    
    // Phase 2: Directory operations detection
    bool parseDirectoryBlock(const char* data, size_t size, std::vector<EXT4DirectoryEntry>& entries);
    FileOperationType inferFileOperation(const std::vector<EXT4DirectoryEntry>& entries, 
                                       const std::vector<EXT4Inode>& inodes,
                                       uint32_t transaction_seq);
    std::string getOperationTypeString(FileOperationType op_type);
    std::string getChangeTypeString(ChangeType change_type);
    ChangeType analyzeDirectoryChanges(const std::vector<EXT4DirectoryEntry>& entries);
    
    // Phase 3: Path resolution and directory tree management
    DirectoryTreeBuilder directory_tree;
    std::string buildFullPath(uint32_t inode);
    std::string resolveInodePath(uint32_t inode);
    void updateDirectoryTree(const std::vector<EXT4DirectoryEntry>& entries, uint32_t parent_inode);
    void updateDirectoryTreeFromInodes(const std::vector<EXT4Inode>& inodes, const std::vector<uint32_t>& inode_numbers);
    std::string handleSpecialPaths(uint32_t inode, const std::string& name);
    bool isRootDirectory(uint32_t inode);
    bool isLostAndFound(uint32_t inode);
    
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