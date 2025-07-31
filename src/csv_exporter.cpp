#include "csv_exporter.h"
#include <iostream>
#include <sstream>
#include <algorithm>

const std::string CSVExporter::CSV_HEADER = 
    "relative_time,transaction_seq,block_type,fs_block_num,operation_type,affected_inode,file_path,data_size,checksum,file_type,file_size,inode_number,link_count,filename,parent_dir_inode,change_type,full_path";

CSVExporter::CSVExporter() : exported_count(0) {
}

CSVExporter::~CSVExporter() {
}

bool CSVExporter::exportToCSV(const std::vector<JournalTransaction>& transactions,
                              const std::string& output_path,
                              bool include_header) {
    
    if (!validateOutputPath(output_path)) {
        std::cerr << "Error: Invalid output path: " << output_path << std::endl;
        return false;
    }
    
    std::ofstream file(output_path);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot create output file: " << output_path << std::endl;
        return false;
    }
    
    exported_count = 0;
    
    try {
        // Write header if requested
        if (include_header) {
            file << CSV_HEADER << "\n";
        }
        
        // Write transaction records
        for (const auto& transaction : transactions) {
            std::string csv_row = formatCSVRow(transaction);
            file << csv_row << "\n";
            exported_count++;
            
            // Flush periodically for large datasets
            if (exported_count % 1000 == 0) {
                file.flush();
            }
        }
        
        file.close();
        
        std::cout << "Successfully exported " << exported_count 
                  << " journal transactions to " << output_path << std::endl;
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error writing CSV file: " << e.what() << std::endl;
        file.close();
        return false;
    }
}

bool CSVExporter::appendToCSV(const std::vector<JournalTransaction>& transactions,
                              const std::string& output_path) {
    
    std::ofstream file(output_path, std::ios::app);
    if (!file.is_open()) {
        std::cerr << "Error: Cannot open file for appending: " << output_path << std::endl;
        return false;
    }
    
    size_t initial_count = exported_count;
    
    try {
        // Write transaction records
        for (const auto& transaction : transactions) {
            std::string csv_row = formatCSVRow(transaction);
            file << csv_row << "\n";
            exported_count++;
        }
        
        file.close();
        
        std::cout << "Successfully appended " << (exported_count - initial_count)
                  << " journal transactions to " << output_path << std::endl;
        
        return true;
        
    } catch (const std::exception& e) {
        std::cerr << "Error appending to CSV file: " << e.what() << std::endl;
        file.close();
        return false;
    }
}

std::string CSVExporter::formatCSVRow(const JournalTransaction& transaction) {
    std::stringstream ss;
    
    // relative_time
    ss << escapeCSVField(transaction.relative_time) << ",";
    
    // transaction_seq
    ss << transaction.transaction_seq << ",";
    
    // block_type
    ss << escapeCSVField(transaction.block_type) << ",";
    
    // fs_block_num
    ss << transaction.fs_block_num << ",";
    
    // operation_type
    ss << escapeCSVField(transaction.operation_type) << ",";
    
    // affected_inode
    ss << transaction.affected_inode << ",";
    
    // file_path
    ss << escapeCSVField(transaction.file_path) << ",";
    
    // data_size
    ss << transaction.data_size << ",";
    
    // checksum
    ss << escapeCSVField(transaction.checksum) << ",";
    
    // Phase 1 fields
    // file_type
    ss << escapeCSVField(transaction.file_type) << ",";
    
    // file_size
    ss << transaction.file_size << ",";
    
    // inode_number
    ss << transaction.inode_number << ",";
    
    // link_count
    ss << transaction.link_count << ",";
    
    // Phase 2 fields
    // filename
    ss << escapeCSVField(transaction.filename) << ",";
    
    // parent_dir_inode
    ss << transaction.parent_dir_inode << ",";
    
    // change_type
    ss << escapeCSVField(transaction.change_type) << ",";
    
    // Phase 3 fields
    // full_path
    ss << escapeCSVField(transaction.full_path);
    
    return ss.str();
}

std::string CSVExporter::escapeCSVField(const std::string& field) {
    if (field.empty()) {
        return "";
    }
    
    // Check if field needs quoting (contains comma, quote, or newline)
    bool needs_quoting = (field.find(',') != std::string::npos ||
                         field.find('"') != std::string::npos ||
                         field.find('\n') != std::string::npos ||
                         field.find('\r') != std::string::npos);
    
    if (!needs_quoting) {
        return field;
    }
    
    // Escape quotes by doubling them and wrap in quotes
    std::string escaped = field;
    size_t pos = 0;
    while ((pos = escaped.find('"', pos)) != std::string::npos) {
        escaped.insert(pos, "\"");
        pos += 2;
    }
    
    return "\"" + escaped + "\"";
}

bool CSVExporter::validateOutputPath(const std::string& path) {
    if (path.empty()) {
        return false;
    }
    
    // Basic validation - check if path seems reasonable
    // This is simplified - could be enhanced with more thorough path validation
    
    // Check for invalid characters (Windows specific)
    const std::string invalid_chars = "<>:\"|?*";
    for (char c : invalid_chars) {
        if (path.find(c) != std::string::npos) {
            return false;
        }
    }
    
    // Check if it ends with .csv
    if (path.length() >= 4) {
        std::string extension = path.substr(path.length() - 4);
        std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
        if (extension != ".csv") {
            std::cerr << "Warning: Output file does not have .csv extension" << std::endl;
        }
    }
    
    return true;
}