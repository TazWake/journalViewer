#ifndef CSV_EXPORTER_H
#define CSV_EXPORTER_H

#include <string>
#include <vector>
#include <fstream>
#include "journal_parser.h"

class CSVExporter {
private:
    static const std::string CSV_HEADER;
    
    // Helper methods
    std::string escapeCSVField(const std::string& field);
    std::string formatCSVRow(const JournalTransaction& transaction);
    bool validateOutputPath(const std::string& path);

public:
    CSVExporter();
    ~CSVExporter();
    
    // Main export interface
    bool exportToCSV(const std::vector<JournalTransaction>& transactions,
                     const std::string& output_path,
                     bool include_header = true);
    
    // Utility methods
    bool appendToCSV(const std::vector<JournalTransaction>& transactions,
                     const std::string& output_path);
    
    size_t getExportedCount() const { return exported_count; }
    
private:
    size_t exported_count;
};

#endif // CSV_EXPORTER_H