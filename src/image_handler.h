#ifndef IMAGE_HANDLER_H
#define IMAGE_HANDLER_H

#include <string>
#include <memory>
#include <fstream>

enum class ImageType {
    AUTO,
    RAW,
    EWF
};

struct JournalLocation {
    long offset;
    long size;
    bool found;
};

class ImageHandler {
private:
    std::unique_ptr<std::ifstream> raw_file;
    void* ewf_handle;  // libewf handle
    ImageType current_type;
    std::string image_path;
    JournalLocation journal_location;
    long partition_offset;
    bool verbose_mode;
    
    // Helper methods
    ImageType detectImageType(const std::string& path);
    bool openRawImage(const std::string& path);
    bool openEWFImage(const std::string& path);
    bool findJournalInSuperblock();
    bool validateJournalMagic(long offset);

public:
    ImageHandler();
    ~ImageHandler();
    
    // Main interface methods
    bool openImage(const std::string& path, const std::string& type_str = "auto");
    void setPartitionOffset(long offset);
    bool locateJournal(long manual_offset = -1, long manual_size = -1, bool verbose = false);
    
    // Data reading methods
    bool readBytes(long offset, char* buffer, size_t size);
    bool readBlock(long block_number, char* buffer, size_t block_size = 4096);
    
    // Getters
    long getJournalOffset() const { return journal_location.offset; }
    long getJournalSize() const { return journal_location.size; }
    bool isJournalFound() const { return journal_location.found; }
    long getPartitionOffset() const { return partition_offset; }
    ImageType getImageType() const { return current_type; }
    const std::string& getImagePath() const { return image_path; }
};

#endif // IMAGE_HANDLER_H