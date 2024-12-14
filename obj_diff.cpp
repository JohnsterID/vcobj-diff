#include "obj_diff.h"
#include <cxxopts.hpp>
#include <iomanip>
#include <iostream>
#include <sstream>

// Symbol implementation
bool Symbol::operator==(const Symbol& other) const {
    return name == other.name &&
        value == other.value &&
        section_number == other.section_number &&
        type == other.type &&
        storage_class == other.storage_class &&
        number_of_aux_symbols == other.number_of_aux_symbols;
}

bool Symbol::operator<(const Symbol& other) const {
    return name < other.name;
}

// Section implementation
bool Section::operator==(const Section& other) const {
    return name == other.name &&
        virtual_size == other.virtual_size &&
        virtual_address == other.virtual_address &&
        size == other.size &&
        characteristics == other.characteristics &&
        content == other.content;
}

bool Section::operator<(const Section& other) const {
    return name < other.name;
}

// Helper function implementations
std::string format_instruction(const Instruction& instr) {
    std::stringstream ss;
    ss << std::setw(8) << std::setfill('0') << std::hex << instr.address << "  ";

    // Format bytes
    for (uint8_t byte : instr.bytes) {
        ss << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(byte) << " ";
    }
    // Pad bytes to align assembly
    size_t padding = 10 - instr.bytes.size();
    for (size_t i = 0; i < padding; i++) {
        ss << "   ";
    }

    ss << std::setfill(' ') << std::setw(8) << std::left << instr.mnemonic;
    ss << " " << instr.operands;
    return ss.str();
}

void print_assembly_diff(const json& diff) {
    for (const auto& change : diff) {
        std::cout << "\n----------------------------------------\n";

        // Print context before
        if (change.contains("context_before")) {
            std::cout << "Context before:\n";
            for (const auto& line : change["context_before"]) {
                std::cout << "  " << line << "\n";
            }
        }

        // Print the change
        std::string type = change["type"];
        if (type == "added") {
            std::cout << "+ " << change["new_instruction"] << "\n";
        }
        else if (type == "removed") {
            std::cout << "- " << change["old_instruction"] << "\n";
        }
        else if (type == "modified") {
            std::cout << "- " << change["old_instruction"] << "\n";
            std::cout << "+ " << change["new_instruction"] << "\n";
        }

        // Print context after
        if (change.contains("context_after")) {
            std::cout << "Context after:\n";
            for (const auto& line : change["context_after"]) {
                std::cout << "  " << line << "\n";
            }
        }

        std::cout << "----------------------------------------\n";
    }
}

// AssemblyDecoder implementation
AssemblyDecoder::AssemblyDecoder() {
    if (!ZYAN_SUCCESS(ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32))) {
        throw std::runtime_error("Failed to initialize Zydis decoder");
    }

    if (!ZYAN_SUCCESS(ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL))) {
        throw std::runtime_error("Failed to initialize Zydis formatter");
    }

    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SEGMENT, ZYAN_TRUE);
    ZydisFormatterSetProperty(&formatter, ZYDIS_FORMATTER_PROP_FORCE_SIZE, ZYAN_TRUE);
}

std::vector<Instruction> AssemblyDecoder::decode_section(const std::vector<uint8_t>& content, uint64_t base_address) {
    std::vector<Instruction> instructions;
    size_t offset = 0;

    while (offset < content.size()) {
        ZydisDecodedInstruction decoded_instruction;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder,
            content.data() + offset,
            content.size() - offset,
            &decoded_instruction,
            operands))) {
            offset++;
            continue;
        }

        char buffer[256];
        if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(
            &formatter,
            &decoded_instruction,
            operands,
            decoded_instruction.operand_count,
            buffer,
            sizeof(buffer),
            base_address + offset,
            nullptr))) {
            offset += decoded_instruction.length;
            continue;
        }

        std::string formatted(buffer);
        size_t space_pos = formatted.find(' ');
        std::string mnemonic = (space_pos != std::string::npos) ?
            formatted.substr(0, space_pos) : formatted;
        std::string operands_str = (space_pos != std::string::npos) ?
            formatted.substr(space_pos + 1) : "";

        std::vector<uint8_t> instr_bytes(
            content.begin() + offset,
            content.begin() + offset + decoded_instruction.length
        );

        instructions.push_back({
            base_address + offset,
            mnemonic,
            operands_str,
            instr_bytes
            });

        offset += decoded_instruction.length;
    }

    return instructions;
}

// String table helper
std::string ObjFile::read_string(const std::vector<char>& string_table, uint32_t offset) {
    if (offset >= string_table.size()) {
        return "";
    }
    return std::string(string_table.data() + offset);
}

// ObjFile implementation
ObjFile ObjFile::parse(const std::string& filepath) {
    ObjFile result;
    AssemblyDecoder decoder;

    try {
        std::cout << "Attempting to parse: " << filepath << std::endl;
        std::cout << "File size: " << fs::file_size(filepath) << " bytes" << std::endl;

        std::ifstream file(filepath, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot open file");
        }

        // Read COFF header
        COFF::Header coff_header;
        file.read(reinterpret_cast<char*>(&coff_header), sizeof(coff_header));
        if (!file.good()) {
            throw std::runtime_error("Failed to read COFF header");
        }

        // Validate machine type
        if (coff_header.Machine != IMAGE_FILE_MACHINE_I386 &&
            coff_header.Machine != IMAGE_FILE_MACHINE_AMD64) {
            throw std::runtime_error(fmt::format("Unsupported machine type: 0x{:04x}",
                coff_header.Machine));
        }

        // Read section headers
        std::vector<COFF::SectionHeader> section_headers(coff_header.NumberOfSections);
        for (auto& section_header : section_headers) {
            file.read(reinterpret_cast<char*>(&section_header), sizeof(COFF::SectionHeader));
            if (!file.good()) {
                throw std::runtime_error("Failed to read section header");
            }
        }

        // Read string table
        file.seekg(coff_header.PointerToSymbolTable +
            coff_header.NumberOfSymbols * sizeof(COFF::SymbolRecord));
        uint32_t string_table_size;
        file.read(reinterpret_cast<char*>(&string_table_size), sizeof(uint32_t));

        std::vector<char> string_table(string_table_size);
        file.read(string_table.data(), string_table_size);

        // Read symbols
        file.seekg(coff_header.PointerToSymbolTable);
        for (uint32_t i = 0; i < coff_header.NumberOfSymbols; i++) {
            COFF::SymbolRecord symbol;
            file.read(reinterpret_cast<char*>(&symbol), sizeof(COFF::SymbolRecord));

            std::string name;
            if (symbol.Name.ShortName[0] == 0) {
                // Long name - read from string table
                name = read_string(string_table, symbol.Name.LongName.Offset);
            }
            else {
                // Short name - directly from the record
                name = std::string(symbol.Name.ShortName,
                    strnlen(symbol.Name.ShortName, sizeof(symbol.Name.ShortName)));
            }

            Symbol sym{
                name,
                symbol.Value,
                static_cast<uint16_t>(symbol.SectionNumber),
                symbol.Type,
                symbol.StorageClass,
                symbol.NumberOfAuxSymbols
            };
            result.symbols.insert(sym);

            // Skip auxiliary symbol records
            i += symbol.NumberOfAuxSymbols;
        }

        // Read sections
        for (const auto& header : section_headers) {
            std::vector<uint8_t> content;
            if (header.PointerToRawData > 0 && header.SizeOfRawData > 0) {
                content.resize(header.SizeOfRawData);
                file.seekg(header.PointerToRawData);
                file.read(reinterpret_cast<char*>(content.data()), header.SizeOfRawData);
            }

            std::string name(header.Name, strnlen(header.Name, sizeof(header.Name)));

            Section sec{
                name,
                header.VirtualSize,
                header.VirtualAddress,
                header.SizeOfRawData,
                header.Characteristics,
                std::move(content)
            };

            // Decode instructions for code sections
            if (header.Characteristics & IMAGE_SCN_CNT_CODE) {
                sec.instructions = decoder.decode_section(sec.content, header.VirtualAddress);
            }

            result.sections.insert(std::move(sec));
        }

    }
    catch (const std::exception& e) {
        throw std::runtime_error(
            fmt::format("Error parsing file {}: {}", filepath, e.what()));
    }

    return result;
}

// Comparison function implementations
json compare_instructions(const std::vector<Instruction>& instrs1,
    const std::vector<Instruction>& instrs2) {
    json diff;
    size_t i = 0, j = 0;
    int context_lines = 3; // Number of context lines before/after changes

    auto add_context = [](const std::vector<Instruction>& instrs, size_t start, size_t end) {
        std::vector<std::string> context;
        for (size_t idx = start; idx < end && idx < instrs.size(); idx++) {
            context.push_back(format_instruction(instrs[idx]));
        }
        return context;
        };

    while (i < instrs1.size() || j < instrs2.size()) {
        if (i >= instrs1.size()) {
            // Extra instructions in file2
            json change;
            change["type"] = "added";
            change["new_instruction"] = format_instruction(instrs2[j]);

            // Add context before
            if (j >= context_lines) {
                change["context_before"] = add_context(instrs2, j - context_lines, j);
            }
            // Add context after
            change["context_after"] = add_context(instrs2, j + 1, j + 1 + context_lines);

            diff.push_back(change);
            j++;
        }
        else if (j >= instrs2.size()) {
            // Extra instructions in file1
            json change;
            change["type"] = "removed";
            change["old_instruction"] = format_instruction(instrs1[i]);

            // Add context before
            if (i >= context_lines) {
                change["context_before"] = add_context(instrs1, i - context_lines, i);
            }
            // Add context after
            change["context_after"] = add_context(instrs1, i + 1, i + 1 + context_lines);

            diff.push_back(change);
            i++;
        }
        else if (instrs1[i].mnemonic != instrs2[j].mnemonic ||
            instrs1[i].operands != instrs2[j].operands) {
            // Instructions differ
            json change;
            change["type"] = "modified";
            change["old_instruction"] = format_instruction(instrs1[i]);
            change["new_instruction"] = format_instruction(instrs2[j]);

            // Add context before
            if (i >= context_lines && j >= context_lines) {
                change["context_before_old"] = add_context(instrs1, i - context_lines, i);
                change["context_before_new"] = add_context(instrs2, j - context_lines, j);
            }
            // Add context after
            change["context_after_old"] = add_context(instrs1, i + 1, i + 1 + context_lines);
            change["context_after_new"] = add_context(instrs2, j + 1, j + 1 + context_lines);

            diff.push_back(change);
            i++;
            j++;
        }
        else {
            // Instructions match
            i++;
            j++;
        }
    }

    return diff;
}

json compare_obj_files(const ObjFile& obj1, const ObjFile& obj2) {
    json diff;

    // Compare symbols
    json symbol_diff;
    std::set<std::string> all_symbol_names;
    for (const auto& sym : obj1.symbols) all_symbol_names.insert(sym.name);
    for (const auto& sym : obj2.symbols) all_symbol_names.insert(sym.name);

    for (const auto& name : all_symbol_names) {
        auto it1 = std::find_if(obj1.symbols.begin(), obj1.symbols.end(),
            [&name](const Symbol& s) { return s.name == name; });
        auto it2 = std::find_if(obj2.symbols.begin(), obj2.symbols.end(),
            [&name](const Symbol& s) { return s.name == name; });

        if (it1 == obj1.symbols.end()) {
            symbol_diff[name] = "Only in file 2";
        }
        else if (it2 == obj2.symbols.end()) {
            symbol_diff[name] = "Only in file 1";
        }
        else if (!(*it1 == *it2)) {
            symbol_diff[name] = {
                {"file1", {
                    {"value", it1->value},
                    {"section_number", it1->section_number},
                    {"type", it1->type},
                    {"storage_class", it1->storage_class}
                }},
                {"file2", {
                    {"value", it2->value},
                    {"section_number", it2->section_number},
                    {"type", it2->type},
                    {"storage_class", it2->storage_class}
                }}
            };
        }
    }

    if (!symbol_diff.empty()) {
        diff["symbols"] = symbol_diff;
    }

    // Compare sections
    json section_diff;
    std::set<std::string> all_section_names;
    for (const auto& sec : obj1.sections) all_section_names.insert(sec.name);
    for (const auto& sec : obj2.sections) all_section_names.insert(sec.name);

    for (const auto& name : all_section_names) {
        auto it1 = std::find_if(obj1.sections.begin(), obj1.sections.end(),
            [&name](const Section& s) { return s.name == name; });
        auto it2 = std::find_if(obj2.sections.begin(), obj2.sections.end(),
            [&name](const Section& s) { return s.name == name; });

        if (it1 == obj1.sections.end()) {
            section_diff[name] = "Only in file 2";
        }
        else if (it2 == obj2.sections.end()) {
            section_diff[name] = "Only in file 1";
        }
        else if (!(*it1 == *it2)) {
            json section_info = {
                {"file1", {
                    {"virtual_size", it1->virtual_size},
                    {"virtual_address", it1->virtual_address},
                    {"size", it1->size},
                    {"characteristics", fmt::format("0x{:08x}", it1->characteristics)}
                }},
                {"file2", {
                    {"virtual_size", it2->virtual_size},
                    {"virtual_address", it2->virtual_address},
                    {"size", it2->size},
                    {"characteristics", fmt::format("0x{:08x}", it2->characteristics)}
                }}
            };

            // Add instruction diff for code sections
            if (!it1->instructions.empty() || !it2->instructions.empty()) {
                auto instruction_diff = compare_instructions(it1->instructions, it2->instructions);
                if (!instruction_diff.empty()) {
                    section_info["assembly_diff"] = instruction_diff;
                }
            }

            section_diff[name] = section_info;
        }
    }

    if (!section_diff.empty()) {
        diff["sections"] = section_diff;
    }

    return diff;
}

int main(int argc, char* argv[]) {
    try {
        cxxopts::Options options("obj-diff", "Visual C++ 6.0 OBJ file differ");
        options.add_options()
            ("f,file1", "First OBJ file", cxxopts::value<std::string>())
            ("s,file2", "Second OBJ file", cxxopts::value<std::string>())
            ("o,output", "Output JSON file", cxxopts::value<std::string>())
            ("a,assembly", "Show only assembly differences", cxxopts::value<bool>()->default_value("false"))
            ("h,help", "Print usage")
            ;

        auto result = options.parse(argc, argv);

        if (result.count("help") || !result.count("file1") || !result.count("file2")) {
            std::cout << options.help() << std::endl;
            return 0;
        }

        std::string file1_path = result["file1"].as<std::string>();
        std::string file2_path = result["file2"].as<std::string>();

        if (!fs::exists(file1_path) || !fs::exists(file2_path)) {
            throw std::runtime_error("One or both input files do not exist");
        }

        ObjFile obj1 = ObjFile::parse(file1_path);
        ObjFile obj2 = ObjFile::parse(file2_path);

        if (result["assembly"].as<bool>()) {
            // Find text sections
            auto text1 = std::find_if(obj1.sections.begin(), obj1.sections.end(),
                [](const Section& s) { return s.name == ".text"; });
            auto text2 = std::find_if(obj2.sections.begin(), obj2.sections.end(),
                [](const Section& s) { return s.name == ".text"; });

            if (text1 != obj1.sections.end() && text2 != obj2.sections.end()) {
                auto assembly_diff = compare_instructions(text1->instructions, text2->instructions);
                print_assembly_diff(assembly_diff);
            }
            else {
                std::cout << "No .text sections found to compare\n";
            }
        }
        else {
            json diff = compare_obj_files(obj1, obj2);

            if (result.count("output")) {
                std::string output_path = result["output"].as<std::string>();
                std::ofstream out(output_path);
                out << diff.dump(2);
            }
            else {
                std::cout << diff.dump(2) << std::endl;
            }
        }

        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}