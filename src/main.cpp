#include <iostream>
#include <string>
#include <cstring>
#include <getopt.h>
#include "image_handler.h"
#include "journal_parser.h"
#include "csv_exporter.h"

void print_usage(const char* program_name) {
    std::cout << "Usage: " << program_name << " -i <image_file> -o <output.csv> [options]\n\n";
    std::cout << "Required arguments:\n";
    std::cout << "  -i, --image <file>     Input image file path\n";
    std::cout << "  -o, --output <file>    Output CSV file path\n\n";
    std::cout << "Optional arguments:\n";
    std::cout << "  -t, --type <type>      Image type (auto|raw|ewf) [default: auto]\n";
    std::cout << "  -v, --verbose          Verbose output\n";
    std::cout << "  -h, --help             Display this help information\n";
    std::cout << "      --version          Display version information\n";
    std::cout << "      --journal-offset   Manual journal offset (bytes)\n";
    std::cout << "      --journal-size     Manual journal size (bytes)\n";
    std::cout << "      --partition-offset <sectors>  Partition offset in 512-byte sectors\n";
    std::cout << "      --partition-offset-bytes <bytes>  Partition offset in bytes\n";
    std::cout << "      --sector-size <size>  Sector size in bytes [default: 512]\n";
    std::cout << "      --start-seq        Start from specific sequence number\n";
    std::cout << "      --end-seq          End at specific sequence number\n";
    std::cout << "      --no-header        Omit CSV header row\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << program_name << " -i evidence.E01 -o journal_analysis.csv -v\n";
    std::cout << "  " << program_name << " -i disk.dd -o output.csv --journal-offset 1048576\n";
    std::cout << "  " << program_name << " -i evidence.E01 -o filtered.csv --start-seq 100 --end-seq 200\n";
    std::cout << "  " << program_name << " -i starkskunk5.E01 -o partition6.csv --partition-offset 227328\n";
    std::cout << "  " << program_name << " -i starkskunk5.E01 -o partition6.csv --partition-offset-bytes 116391936\n";
}

void print_version() {
    std::cout << "ext-journal-analyzer version 1.0.0\n";
    std::cout << "EXT3/4 Journal Forensics Tool\n";
}

int main(int argc, char* argv[]) {
    std::string input_image;
    std::string output_csv;
    std::string image_type = "auto";
    bool verbose = false;
    bool no_header = false;
    long journal_offset = -1;
    long journal_size = -1;
    long partition_offset_sectors = -1;
    long partition_offset_bytes = -1;
    int sector_size = 512;
    int start_seq = -1;
    int end_seq = -1;

    // Long options
    static struct option long_options[] = {
        {"image", required_argument, 0, 'i'},
        {"output", required_argument, 0, 'o'},
        {"type", required_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 0},
        {"journal-offset", required_argument, 0, 0},
        {"journal-size", required_argument, 0, 0},
        {"partition-offset", required_argument, 0, 0},
        {"partition-offset-bytes", required_argument, 0, 0},
        {"sector-size", required_argument, 0, 0},
        {"start-seq", required_argument, 0, 0},
        {"end-seq", required_argument, 0, 0},
        {"no-header", no_argument, 0, 0},
        {0, 0, 0, 0}
    };

    int c;
    int option_index = 0;
    
    while ((c = getopt_long(argc, argv, "i:o:t:vh", long_options, &option_index)) != -1) {
        switch (c) {
            case 'i':
                input_image = optarg;
                break;
            case 'o':
                output_csv = optarg;
                break;
            case 't':
                image_type = optarg;
                break;
            case 'v':
                verbose = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            case 0:
                if (strcmp(long_options[option_index].name, "version") == 0) {
                    print_version();
                    return 0;
                } else if (strcmp(long_options[option_index].name, "journal-offset") == 0) {
                    journal_offset = std::stol(optarg);
                } else if (strcmp(long_options[option_index].name, "journal-size") == 0) {
                    journal_size = std::stol(optarg);
                } else if (strcmp(long_options[option_index].name, "partition-offset") == 0) {
                    partition_offset_sectors = std::stol(optarg);
                } else if (strcmp(long_options[option_index].name, "partition-offset-bytes") == 0) {
                    partition_offset_bytes = std::stol(optarg);
                } else if (strcmp(long_options[option_index].name, "sector-size") == 0) {
                    sector_size = std::stoi(optarg);
                } else if (strcmp(long_options[option_index].name, "start-seq") == 0) {
                    start_seq = std::stoi(optarg);
                } else if (strcmp(long_options[option_index].name, "end-seq") == 0) {
                    end_seq = std::stoi(optarg);
                } else if (strcmp(long_options[option_index].name, "no-header") == 0) {
                    no_header = true;
                }
                break;
            case '?':
                std::cerr << "Unknown option. Use -h for help.\n";
                return 1;
            default:
                return 1;
        }
    }

    // Validate required arguments
    if (input_image.empty() || output_csv.empty()) {
        std::cerr << "Error: Both input image (-i) and output CSV (-o) are required.\n";
        print_usage(argv[0]);
        return 1;
    }

    // Validate image type
    if (image_type != "auto" && image_type != "raw" && image_type != "ewf") {
        std::cerr << "Error: Invalid image type. Must be auto, raw, or ewf.\n";
        return 1;
    }

    // Validate and calculate partition offset
    long final_partition_offset = 0;
    if (partition_offset_sectors >= 0 && partition_offset_bytes >= 0) {
        std::cerr << "Error: Cannot specify both --partition-offset and --partition-offset-bytes.\n";
        return 1;
    }
    
    if (partition_offset_sectors >= 0) {
        if (sector_size <= 0 || sector_size > 8192) {
            std::cerr << "Error: Invalid sector size. Must be between 1 and 8192 bytes.\n";
            return 1;
        }
        final_partition_offset = partition_offset_sectors * sector_size;
    } else if (partition_offset_bytes >= 0) {
        final_partition_offset = partition_offset_bytes;
    }
    
    if (final_partition_offset < 0) {
        std::cerr << "Error: Partition offset cannot be negative.\n";
        return 1;
    }
    
    // Additional validation for reasonable partition offset values
    const long max_reasonable_offset = 1024LL * 1024 * 1024 * 1024; // 1TB
    if (final_partition_offset > max_reasonable_offset) {
        std::cerr << "Warning: Partition offset (" << final_partition_offset 
                  << " bytes) is unusually large. This may cause issues.\n";
    }

    if (verbose) {
        std::cout << "ext-journal-analyzer starting...\n";
        std::cout << "Input image: " << input_image << "\n";
        std::cout << "Output CSV: " << output_csv << "\n";
        std::cout << "Image type: " << image_type << "\n";
        if (final_partition_offset > 0) {
            std::cout << "Partition offset: " << final_partition_offset << " bytes\n";
        }
    }

    try {
        // Initialize components
        ImageHandler image_handler;
        JournalParser journal_parser;
        CSVExporter csv_exporter;

        // Open image
        if (verbose) std::cout << "Opening image file...\n";
        if (!image_handler.openImage(input_image, image_type)) {
            std::cerr << "Error: Failed to open image file: " << input_image << "\n";
            return 1;
        }

        // Set partition offset if specified
        if (final_partition_offset > 0) {
            image_handler.setPartitionOffset(final_partition_offset);
            if (verbose) std::cout << "Applied partition offset: " << final_partition_offset << " bytes\n";
        }

        // Locate journal
        if (verbose) std::cout << "Locating journal...\n";
        if (!image_handler.locateJournal(journal_offset, journal_size, verbose)) {
            std::cerr << "Error: Failed to locate journal in image.\n";
            return 1;
        }

        // Parse journal
        if (verbose) std::cout << "Parsing journal transactions...\n";
        auto transactions = journal_parser.parseJournal(image_handler, start_seq, end_seq, verbose);
        
        if (transactions.empty()) {
            std::cerr << "Warning: No journal transactions found.\n";
        } else {
            if (verbose) std::cout << "Found " << transactions.size() << " journal transactions.\n";
        }

        // Export to CSV
        if (verbose) std::cout << "Exporting to CSV...\n";
        if (!csv_exporter.exportToCSV(transactions, output_csv, !no_header)) {
            std::cerr << "Error: Failed to export CSV file: " << output_csv << "\n";
            return 1;
        }

        if (verbose) std::cout << "Analysis complete. Output written to: " << output_csv << "\n";
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}