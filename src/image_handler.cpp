#include "image_handler.h"
#include <iostream>
#include <cstring>
#include <algorithm>
#include <libewf.h>

ImageHandler::ImageHandler() : ewf_handle(nullptr), current_type(ImageType::AUTO) {
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

bool ImageHandler::locateJournal(long manual_offset, long manual_size) {
    if (manual_offset >= 0) {
        // Use manual offset
        journal_location.offset = manual_offset;
        journal_location.size = (manual_size > 0) ? manual_size : 0;
        journal_location.found = validateJournalMagic(manual_offset);
        return journal_location.found;
    }
    
    // Automatically locate journal in superblock
    return findJournalInSuperblock();
}

bool ImageHandler::findJournalInSuperblock() {
    // EXT2/3/4 superblock is at offset 1024 (1KB)
    const long superblock_offset = 1024;
    const size_t superblock_size = 1024;
    char superblock[1024];
    
    if (!readBytes(superblock_offset, superblock, superblock_size)) {
        std::cerr << "Error: Failed to read superblock" << std::endl;
        return false;
    }
    
    // Check EXT magic number (0xEF53 at offset 56 in superblock)
    uint16_t* magic = reinterpret_cast<uint16_t*>(&superblock[56]);
    if (*magic != 0xEF53) {
        std::cerr << "Error: Invalid EXT filesystem magic number" << std::endl;
        return false;
    }
    
    // For EXT3/4, journal is typically at inode 8
    // This is a simplified implementation - in reality, we'd need to:
    // 1. Parse the superblock to get block size and inode table location
    // 2. Read inode 8 to get journal location
    // 3. Validate journal superblock
    
    // For now, use a common default location (simplified)
    long estimated_journal_offset = 32768; // Common location after superblock area
    
    if (validateJournalMagic(estimated_journal_offset)) {
        journal_location.offset = estimated_journal_offset;
        journal_location.size = 0; // Will be determined from journal superblock
        journal_location.found = true;
        return true;
    }
    
    // If not found at common location, search in first few MB
    for (long offset = 8192; offset < 1048576; offset += 4096) {
        if (validateJournalMagic(offset)) {
            journal_location.offset = offset;
            journal_location.size = 0;
            journal_location.found = true;
            return true;
        }
    }
    
    std::cerr << "Warning: Journal not found in filesystem" << std::endl;
    return false;
}

bool ImageHandler::validateJournalMagic(long offset) {
    char header[12];
    if (!readBytes(offset, header, 12)) {
        return false;
    }
    
    // Check for JBD2 magic number (0xC03B3998) in big-endian format
    uint32_t* magic = reinterpret_cast<uint32_t*>(header);
    uint32_t jbd2_magic = 0x9839B3C0; // Little-endian representation of big-endian 0xC03B3998
    
    return (*magic == jbd2_magic);
}

bool ImageHandler::readBytes(long offset, char* buffer, size_t size) {
    if (current_type == ImageType::RAW && raw_file) {
        raw_file->seekg(offset);
        raw_file->read(buffer, size);
        return raw_file->good() && raw_file->gcount() == static_cast<std::streamsize>(size);
    } else if (current_type == ImageType::EWF && ewf_handle) {
        libewf_error_t* error = nullptr;
        if (libewf_handle_seek_offset(static_cast<libewf_handle_t*>(ewf_handle), offset, SEEK_SET, &error) == -1) {
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