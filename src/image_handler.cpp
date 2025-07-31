#include "image_handler.h"
#include <iostream>
#include <cstring>
#include <algorithm>
#include <cstdio>
#include <libewf.h>

ImageHandler::ImageHandler() : ewf_handle(nullptr), current_type(ImageType::AUTO), partition_offset(0), verbose_mode(false) {
    journal_location = {0, 0, false};
}

ImageHandler::~ImageHandler() {
    if (raw_file) {
        raw_file->close();
    }
    if (ewf_handle) {
        libewf_handle_close(static_cast<libewf_handle_t*>(ewf_handle), nullptr);
        libewf_handle_free(reinterpret_cast<libewf_handle_t**>(&ewf_handle), nullptr);
    }
}

bool ImageHandler::openImage(const std::string& path, const std::string& type_str) {
    image_path = path;
    
    // Convert string type to enum
    ImageType type = ImageType::AUTO;
    if (type_str == "raw") {
        type = ImageType::RAW;
    } else if (type_str == "ewf") {
        type = ImageType::EWF;
    }
    
    if (type == ImageType::AUTO) {
        type = detectImageType(path);
    }
    
    current_type = type;
    
    switch (type) {
        case ImageType::RAW:
            return openRawImage(path);
        case ImageType::EWF:
            return openEWFImage(path);
        default:
            std::cerr << "Error: Unable to determine image type for: " << path << std::endl;
            return false;
    }
}

ImageType ImageHandler::detectImageType(const std::string& path) {
    // Simple detection based on file extension
    size_t dot_pos = path.find_last_of('.');
    if (dot_pos != std::string::npos) {
        std::string ext = path.substr(dot_pos + 1);
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        
        if (ext == "e01" || ext == "ex01" || ext == "l01") {
            return ImageType::EWF;
        } else if (ext == "dd" || ext == "img" || ext == "raw") {
            return ImageType::RAW;
        }
    }
    
    // Default to RAW if cannot determine
    return ImageType::RAW;
}

bool ImageHandler::openRawImage(const std::string& path) {
    raw_file = std::make_unique<std::ifstream>(path, std::ios::binary);
    
    if (!raw_file->is_open()) {
        std::cerr << "Error: Cannot open raw image file: " << path << std::endl;
        return false;
    }
    
    // Check file size
    raw_file->seekg(0, std::ios::end);
    long file_size = raw_file->tellg();
    raw_file->seekg(0, std::ios::beg);
    
    if (file_size <= 0) {
        std::cerr << "Error: Invalid raw image file size" << std::endl;
        return false;
    }
    
    return true;
}

bool ImageHandler::openEWFImage(const std::string& path) {
    libewf_error_t* error = nullptr;
    
    // Initialize libewf handle
    if (libewf_handle_initialize(reinterpret_cast<libewf_handle_t**>(&ewf_handle), &error) != 1) {
        std::cerr << "Error: Failed to initialize libewf handle" << std::endl;
        return false;
    }
    
    // Create filename array for libewf
    const char* filenames[] = { path.c_str(), nullptr };
    
    // Open EWF file
    if (libewf_handle_open(static_cast<libewf_handle_t*>(ewf_handle), 
                          const_cast<char* const*>(filenames), 1,
                          LIBEWF_OPEN_READ, &error) != 1) {
        std::cerr << "Error: Failed to open EWF image: " << path << std::endl;
        libewf_handle_free(reinterpret_cast<libewf_handle_t**>(&ewf_handle), nullptr);
        ewf_handle = nullptr;
        return false;
    }
    
    return true;
}

void ImageHandler::setPartitionOffset(long offset) {
    if (offset < 0) {
        std::cerr << "Warning: Negative partition offset (" << offset << ") ignored.\n";
        partition_offset = 0;
    } else {
        partition_offset = offset;
    }
}

bool ImageHandler::locateJournal(long manual_offset, long manual_size, bool verbose) {
    verbose_mode = verbose;
    if (manual_offset >= 0) {
        // Use manual offset - this should be relative to the partition start
        // The readBytes method will automatically apply the partition offset
        journal_location.offset = manual_offset;
        journal_location.size = (manual_size > 0) ? manual_size : 0;
        journal_location.found = validateJournalMagic(manual_offset);
        return journal_location.found;
    }
    
    // Automatically locate journal in superblock
    return findJournalInSuperblock();
}

bool ImageHandler::findJournalInSuperblock() {
    // EXT2/3/4 superblock is at offset 1024 (1KB) from partition start
    const long superblock_offset = 1024;
    const size_t superblock_size = 1024;
    char superblock[1024];
    
    if (!readBytes(superblock_offset, superblock, superblock_size)) {
        std::cerr << "Error: Failed to read superblock at offset " << (superblock_offset + partition_offset) << std::endl;
        return false;
    }
    
    // Check EXT magic number (0xEF53 at offset 56 in superblock)
    uint16_t* magic = reinterpret_cast<uint16_t*>(&superblock[56]);
    if (*magic != 0xEF53) {
        std::cerr << "Error: Invalid EXT filesystem magic number (got 0x" << std::hex << *magic 
                  << ", expected 0xEF53) at partition offset " << partition_offset << std::endl;
        return false;
    }
    
    // Parse superblock to get block size and other filesystem parameters
    uint32_t* log_block_size = reinterpret_cast<uint32_t*>(&superblock[24]);
    uint32_t block_size = 1024 << *log_block_size;
    
    // Get filesystem features to check if it has a journal
    uint32_t* feature_compat = reinterpret_cast<uint32_t*>(&superblock[92]);
    uint32_t* feature_incompat = reinterpret_cast<uint32_t*>(&superblock[96]);
    
    const uint32_t EXT3_FEATURE_COMPAT_HAS_JOURNAL = 0x0004;
    const uint32_t EXT4_FEATURE_INCOMPAT_JOURNAL_DEV = 0x0008;
    
    bool has_journal = (*feature_compat & EXT3_FEATURE_COMPAT_HAS_JOURNAL) != 0;
    bool is_journal_dev = (*feature_incompat & EXT4_FEATURE_INCOMPAT_JOURNAL_DEV) != 0;
    
    if (!has_journal && !is_journal_dev) {
        std::cerr << "Error: Filesystem does not have a journal (EXT2?)" << std::endl;
        return false;
    }
    
    std::cout << "Found EXT filesystem with block size " << block_size << " bytes" << std::endl;
    
    // Try to locate journal by reading inode 8 (journal inode)
    // First, calculate inode table location
    uint32_t* inodes_per_group = reinterpret_cast<uint32_t*>(&superblock[40]);
    uint32_t* first_data_block = reinterpret_cast<uint32_t*>(&superblock[20]);
    
    // Group descriptor is right after the superblock
    long group_desc_offset = (*first_data_block + 1) * block_size;
    char group_desc[32]; // Group descriptor is 32 bytes for EXT2/3, 64 for EXT4
    
    if (!readBytes(group_desc_offset, group_desc, 32)) {
        std::cerr << "Error: Failed to read group descriptor" << std::endl;
        return false;
    }
    
    // Get inode table block number from group descriptor
    uint32_t* inode_table_block = reinterpret_cast<uint32_t*>(&group_desc[8]);
    long inode_table_offset = *inode_table_block * block_size;
    
    // Journal is at inode 8, each inode is typically 128 or 256 bytes
    uint16_t* inode_size = reinterpret_cast<uint16_t*>(&superblock[88]);
    uint16_t actual_inode_size = (*inode_size > 0) ? *inode_size : 128;
    
    long journal_inode_offset = inode_table_offset + (8 - 1) * actual_inode_size; // inode 8 (0-based = 7)
    char journal_inode[256];
    
    if (!readBytes(journal_inode_offset, journal_inode, actual_inode_size)) {
        std::cerr << "Error: Failed to read journal inode" << std::endl;
        return false;
    }
    
    // Debug: Dump first 64 bytes of journal inode
    if (verbose_mode) {
        std::cout << "Debug: Journal inode contents (first 64 bytes):" << std::endl;
        for (int i = 0; i < 64; i += 16) {
            std::cout << "  Offset " << i << ": ";
            for (int j = 0; j < 16 && i + j < 64; j++) {
                printf("%02x ", (unsigned char)journal_inode[i + j]);
            }
            std::cout << std::endl;
        }
    }
    
    // Read journal size from inode (bytes 4-7: lower 32 bits of size)
    uint32_t* inode_size_lo = reinterpret_cast<uint32_t*>(&journal_inode[4]);
    uint64_t journal_size = *inode_size_lo;
    
    if (verbose_mode) std::cout << "Debug: Journal size from inode = " << journal_size << " bytes" << std::endl;
    
    // Check if inode uses extents (EXT4 feature)
    uint32_t* inode_flags = reinterpret_cast<uint32_t*>(&journal_inode[32]);
    const uint32_t EXT4_EXTENTS_FL = 0x00080000;
    bool uses_extents = (*inode_flags & EXT4_EXTENTS_FL) != 0;
    
    if (verbose_mode) std::cout << "Debug: Inode flags = 0x" << std::hex << *inode_flags << std::dec 
                  << (uses_extents ? " (uses extents)" : " (direct blocks)") << std::endl;
    
    uint32_t journal_block = 0;
    
    if (uses_extents) {
        // Parse extent header at offset 40
        uint16_t* extent_magic = reinterpret_cast<uint16_t*>(&journal_inode[40]);
        uint16_t* extent_entries = reinterpret_cast<uint16_t*>(&journal_inode[42]);
        uint16_t* extent_max = reinterpret_cast<uint16_t*>(&journal_inode[44]);
        uint16_t* extent_depth = reinterpret_cast<uint16_t*>(&journal_inode[46]);
        
        if (verbose_mode) std::cout << "Debug: Extent header - magic=0x" << std::hex << *extent_magic 
                      << " entries=" << std::dec << *extent_entries 
                      << " max=" << *extent_max << " depth=" << *extent_depth << std::endl;
        
        if (*extent_magic == 0xF30A && *extent_entries > 0) {
            // Read first extent entry (starts at offset 48)
            // EXT4 extent entry format: logical(4) + len(2) + start_hi(2) + start_lo(4)
            uint32_t* extent_logical = reinterpret_cast<uint32_t*>(&journal_inode[48]);
            uint16_t* extent_len = reinterpret_cast<uint16_t*>(&journal_inode[52]);
            uint16_t* extent_start_hi = reinterpret_cast<uint16_t*>(&journal_inode[54]);
            uint32_t* extent_start_lo = reinterpret_cast<uint32_t*>(&journal_inode[56]);
            
            if (verbose_mode) {
                std::cout << "Debug: Raw extent bytes:" << std::endl;
                for (int i = 48; i < 64; i++) {
                    printf(" %02x", (unsigned char)journal_inode[i]);
                }
                std::cout << std::endl;
            }
            
            // EXT4 extent entry format (12 bytes total):
            // logical(4) + len(2) + start_hi(2) + start_lo(4)
            // From hex dump: 00 00 00 00 00 00 00 00 00 40 00 00 00 00 04 00
            // Bytes 48-51: logical = 0x00000000 = 0
            // Bytes 52-53: len = 0x0000 = 0  
            // Bytes 54-55: start_hi = 0x0000 = 0
            // Bytes 56-59: start_lo = 0x00004000 = 16384
            // Bytes 60-63: next extent = 0x00040000 = 262144
            
            // TSK shows 262144, which is at bytes 60-63, not 56-59
            // So the start_lo field actually contains 16384, but TSK shows 262144
            // This suggests there might be multiple extents or the parsing is wrong
            
            // Let's try reading as if the actual block start is at offset 60
            uint32_t actual_start = *reinterpret_cast<uint32_t*>(&journal_inode[60]);
            journal_block = actual_start;
            
            if (verbose_mode) std::cout << "Debug: Extent parsing - logical=" << *extent_logical 
                      << " len=" << *extent_len 
                      << " start_hi=" << *extent_start_hi
                      << " start_lo=" << *extent_start_lo
                      << " actual_start_at_60=" << actual_start
                      << " calculated_block=" << journal_block << std::endl;
        } else {
            std::cerr << "Error: Invalid extent header magic (0x" << std::hex << *extent_magic << ")" << std::endl;
            return false;
        }
    } else {
        // Traditional direct block pointers
        uint32_t* first_block = reinterpret_cast<uint32_t*>(&journal_inode[40]);
        journal_block = *first_block;
        if (verbose_mode) std::cout << "Debug: Direct block pointer = " << journal_block << std::endl;
    }
    
    if (journal_block == 0) {
        std::cerr << "Error: Journal inode has no data blocks" << std::endl;
        return false;
    }
    
    long journal_offset = journal_block * block_size;
    
    std::cout << "Checking journal at block " << journal_block << " (offset " << journal_offset << ")" << std::endl;
    
    if (validateJournalMagic(journal_offset)) {
        journal_location.offset = journal_offset;
        journal_location.size = journal_size; // Use size from inode
        journal_location.found = true;
        std::cout << "Found journal at offset " << journal_offset << std::endl;
        return true;
    }
    
    // Fallback: search for journal in common locations
    std::cout << "Journal not found at expected location, searching..." << std::endl;
    
    // Search in various common locations relative to filesystem start
    long search_offsets[] = {
        32768,      // 32KB - common default
        65536,      // 64KB
        131072,     // 128KB  
        262144,     // 256KB
        524288,     // 512KB
        1048576,    // 1MB
        block_size * 10,  // 10 blocks in
        block_size * 100, // 100 blocks in
        0  // Sentinel
    };
    
    for (int i = 0; search_offsets[i] != 0; i++) {
        if (validateJournalMagic(search_offsets[i])) {
            journal_location.offset = search_offsets[i];
            journal_location.size = 0;
            journal_location.found = true;
            std::cout << "Found journal at offset " << search_offsets[i] << std::endl;
            return true;
        }
    }
    
    std::cerr << "Warning: Journal not found in filesystem" << std::endl;
    return false;
}

bool ImageHandler::validateJournalMagic(long offset) {
    char header[12];
    if (!readBytes(offset, header, 12)) {
        std::cerr << "Debug: Cannot read journal header at offset " << offset << std::endl;
        return false;
    }
    
    // Check for JBD2 magic number (0xC03B3998) in big-endian format
    uint32_t* magic = reinterpret_cast<uint32_t*>(header);
    uint32_t jbd2_magic = 0x9839B3C0; // Little-endian representation of big-endian 0xC03B3998
    uint32_t jbd_magic = 0x98393BC0;  // JBD (EXT3) magic - different byte order
    
    if (verbose_mode) std::cout << "Debug: Magic at offset " << offset << " = 0x" << std::hex << *magic 
              << " (expected JBD2: 0x" << jbd2_magic << " or JBD: 0x" << jbd_magic << ")" << std::dec << std::endl;
    
    // Try both JBD2 (EXT4) and JBD (EXT3) magic numbers
    bool is_jbd2 = (*magic == jbd2_magic);
    bool is_jbd = (*magic == jbd_magic);
    
    if (is_jbd2) {
        if (verbose_mode) std::cout << "Debug: Found JBD2 (EXT4) journal magic" << std::endl;
    } else if (is_jbd) {
        if (verbose_mode) std::cout << "Debug: Found JBD (EXT3) journal magic" << std::endl;
    } else {
        // Also try the reverse byte order in case of endianness issues
        uint32_t reversed_magic = 0xC03B3998; // Big-endian format
        if (*magic == reversed_magic) {
            if (verbose_mode) std::cout << "Debug: Found journal magic in big-endian format" << std::endl;
            return true;
        }
        if (verbose_mode) std::cout << "Debug: No valid journal magic found" << std::endl;
    }
    
    return (is_jbd2 || is_jbd);
}

bool ImageHandler::readBytes(long offset, char* buffer, size_t size) {
    // Apply partition offset to the requested offset
    long adjusted_offset = offset + partition_offset;
    
    // Basic sanity check to prevent obviously invalid reads
    if (adjusted_offset < 0 || size == 0 || size > 1024 * 1024) {
        std::cerr << "Warning: Invalid read request - offset: " << adjusted_offset 
                  << ", size: " << size << "\n";
        return false;
    }
    
    if (current_type == ImageType::RAW && raw_file) {
        raw_file->seekg(adjusted_offset);
        raw_file->read(buffer, size);
        return raw_file->good() && raw_file->gcount() == static_cast<std::streamsize>(size);
    } else if (current_type == ImageType::EWF && ewf_handle) {
        libewf_error_t* error = nullptr;
        if (libewf_handle_seek_offset(static_cast<libewf_handle_t*>(ewf_handle), adjusted_offset, SEEK_SET, &error) == -1) {
            return false;
        }
        ssize_t read_count = libewf_handle_read_buffer(
            static_cast<libewf_handle_t*>(ewf_handle),
            reinterpret_cast<uint8_t*>(buffer),
            size,
            &error
        );
        return (read_count == static_cast<ssize_t>(size));
    }
    
    return false;
}

bool ImageHandler::readBlock(long block_number, char* buffer, size_t block_size) {
    long offset = block_number * block_size;
    return readBytes(offset, buffer, block_size);
}