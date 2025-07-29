cmake_minimum_required(VERSION 3.10)
project(ext-journal-analyzer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBEWF REQUIRED libewf)

# Include directories
include_directories(${LIBEWF_INCLUDE_DIRS})
include_directories(src)

# Link directories
link_directories(${LIBEWF_LIBRARY_DIRS})

# Source files
set(SOURCES
    src/main.cpp
    src/image_handler.cpp
    src/journal_parser.cpp
    src/csv_exporter.cpp
)

# Header files
set(HEADERS
    src/image_handler.h
    src/journal_parser.h
    src/csv_exporter.h
)

# Create executable
add_executable(ext-journal-analyzer ${SOURCES} ${HEADERS})

# Link libraries
target_link_libraries(ext-journal-analyzer ${LIBEWF_LIBRARIES})

# Compiler flags
target_compile_options(ext-journal-analyzer PRIVATE ${LIBEWF_CFLAGS_OTHER})

# Install target
install(TARGETS ext-journal-analyzer DESTINATION bin)