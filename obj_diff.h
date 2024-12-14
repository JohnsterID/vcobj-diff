#pragma once

#include <nlohmann/json.hpp>
#include <fmt/format.h>
#include <Zydis/Zydis.h>
#include <filesystem>
#include <fstream>
#include <vector>
#include <set>
#include <string>
#include <array>

using json = nlohmann::json;
namespace fs = std::filesystem;

// Constants
namespace {
    constexpr uint16_t IMAGE_FILE_MACHINE_I386 = 0x014c;
    constexpr uint16_t IMAGE_FILE_MACHINE_AMD64 = 0x8664;

    constexpr uint32_t IMAGE_SCN_CNT_CODE = 0x00000020;
    constexpr uint32_t IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040;
    constexpr uint32_t IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080;
    constexpr uint32_t IMAGE_SCN_MEM_EXECUTE = 0x20000000;
    constexpr uint32_t IMAGE_SCN_MEM_READ = 0x40000000;
    constexpr uint32_t IMAGE_SCN_MEM_WRITE = 0x80000000;
}

// COFF Format Structures
namespace COFF {
#pragma pack(push, 1)
    struct Header {
        uint16_t Machine;
        uint16_t NumberOfSections;
        uint32_t TimeDateStamp;
        uint32_t PointerToSymbolTable;
        uint32_t NumberOfSymbols;
        uint16_t SizeOfOptionalHeader;
        uint16_t Characteristics;
    };

    struct SectionHeader {
        char Name[8];
        uint32_t VirtualSize;
        uint32_t VirtualAddress;
        uint32_t SizeOfRawData;
        uint32_t PointerToRawData;
        uint32_t PointerToRelocations;
        uint32_t PointerToLineNumbers;
        uint16_t NumberOfRelocations;
        uint16_t NumberOfLineNumbers;
        uint32_t Characteristics;
    };

    struct SymbolRecord {
        union {
            char ShortName[8];
            struct {
                uint32_t Zeros;
                uint32_t Offset;
            } LongName;
        } Name;
        uint32_t Value;
        int16_t SectionNumber;
        uint16_t Type;
        uint8_t StorageClass;
        uint8_t NumberOfAuxSymbols;
    };

    struct StringTable {
        uint32_t Size;  // Including the size field itself
        // Followed by null-terminated strings
    };
#pragma pack(pop)
}

// Program Structures
struct Instruction {
    uint64_t address;
    std::string mnemonic;
    std::string operands;
    std::vector<uint8_t> bytes;

    bool operator==(const Instruction& other) const {
        return address == other.address &&
            mnemonic == other.mnemonic &&
            operands == other.operands &&
            bytes == other.bytes;
    }
};

struct Symbol {
    std::string name;
    uint64_t value;
    uint16_t section_number;
    uint16_t type;
    uint8_t storage_class;
    uint8_t number_of_aux_symbols;

    bool operator==(const Symbol& other) const;
    bool operator<(const Symbol& other) const;
};

struct Section {
    std::string name;
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size;
    uint32_t characteristics;
    std::vector<uint8_t> content;
    std::vector<Instruction> instructions;

    bool operator==(const Section& other) const;
    bool operator<(const Section& other) const;
};

class AssemblyDecoder {
private:
    ZydisDecoder decoder;
    ZydisFormatter formatter;

public:
    AssemblyDecoder();
    std::vector<Instruction> decode_section(const std::vector<uint8_t>& content, uint64_t base_address = 0);
};

class ObjFile {
public:
    std::set<Symbol> symbols;
    std::set<Section> sections;

    static ObjFile parse(const std::string& filepath);

private:
    static std::string read_string(const std::vector<char>& string_table, uint32_t offset);
};

// Helper functions
std::string format_instruction(const Instruction& instr);
void print_assembly_diff(const json& diff);

// Comparison functions
json compare_instructions(const std::vector<Instruction>& instrs1,
    const std::vector<Instruction>& instrs2);

json compare_obj_files(const ObjFile& obj1, const ObjFile& obj2);