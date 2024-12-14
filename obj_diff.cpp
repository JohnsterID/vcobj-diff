#include "obj_diff.h"
#include <cxxopts.hpp>
#include <iomanip>
#include <iostream>
#include <sstream>

// Format detection implementation
ObjFormat ObjFile::detect_format(std::ifstream& file) {
    uint8_t first_byte;
    file.read(reinterpret_cast<char*>(&first_byte), 1);
    file.seekg(0);

    // OMF files start with THEADR (0x80) or LHEADR (0x82)
    if (first_byte == OMF_THEADR || first_byte == OMF_LHEADR) {
        return ObjFormat::OMF;
    }
    // COFF files start with machine type
    else if (first_byte == 0x4C || first_byte == 0x64) { // 0x014C (i386) or 0x8664 (x64)
        return ObjFormat::COFF;
    }

    return ObjFormat::UNKNOWN;
}

// OMF Parser implementation
uint8_t OMFParser::calculate_checksum(const std::vector<uint8_t>& record_data) {
    uint8_t sum = 0;
    for (uint8_t byte : record_data) {
        sum += byte;
    }
    return static_cast<uint8_t>(-sum);
}

std::string OMFParser::read_name(std::ifstream& file) {
    uint8_t length;
    file.read(reinterpret_cast<char*>(&length), 1);

    std::string name;
    name.resize(length);
    file.read(&name[0], length);

    return name;
}

void OMFParser::parse_lnames(std::ifstream& file, const OMF::RecordHeader& header) {
    size_t bytes_read = 0;
    while (bytes_read < header.length - 1) { // -1 for checksum
        std::string name = read_name(file);
        name_table.push_back(name);
        bytes_read += name.length() + 1; // +1 for length byte
    }

    // Read checksum
    uint8_t checksum;
    file.read(reinterpret_cast<char*>(&checksum), 1);
}

void OMFParser::parse_segdef(std::ifstream& file, const OMF::RecordHeader& header) {
    OMF::SEGDEF segdef;
    file.read(reinterpret_cast<char*>(&segdef), sizeof(OMF::SEGDEF));

    Section section;
    section.name = name_table[segdef.name_idx - 1]; // Indexes are 1-based
    section.virtual_size = segdef.length;
    section.virtual_address = 0; // Will be determined by linker
    section.size = segdef.length;

    // Convert OMF segment attributes to characteristics
    uint32_t characteristics = 0;
    uint8_t align = (segdef.acbp >> 5) & 0x07;
    uint8_t combine = (segdef.acbp >> 2) & 0x07;
    bool big = (segdef.acbp >> 1) & 0x01;
    bool use32 = segdef.acbp & 0x01;

    // Set characteristics based on attributes
    if (use32) {
        characteristics |= 0x01000000; // Use32 flag
    }
    if (big) {
        section.size = use32 ? 0xFFFFFFFF : 0x10000;
    }

    section.characteristics = characteristics;
    sections.push_back(section);

    // Read checksum
    uint8_t checksum;
    file.read(reinterpret_cast<char*>(&checksum), 1);
}

void OMFParser::parse_pubdef(std::ifstream& file, const OMF::RecordHeader& header) {
    OMF::PUBDEF pubdef;
    file.read(reinterpret_cast<char*>(&pubdef), sizeof(OMF::PUBDEF));

    while (file.tellg() < header.length - 1) {
        Symbol symbol;
        symbol.name = read_name(file);

        // Read offset
        uint16_t offset;
        file.read(reinterpret_cast<char*>(&offset), 2);
        symbol.value = offset;

        // Read type index (usually 0)
        uint8_t type_index;
        file.read(reinterpret_cast<char*>(&type_index), 1);

        symbol.section_number = pubdef.segment_idx;
        symbol.type = type_index;
        symbol.storage_class = 2; // External
        symbol.number_of_aux_symbols = 0;

        symbols.push_back(symbol);
    }

    // Read checksum
    uint8_t checksum;
    file.read(reinterpret_cast<char*>(&checksum), 1);
}

void OMFParser::parse_ledata(std::ifstream& file, const OMF::RecordHeader& header) {
    uint8_t segment_idx;
    file.read(reinterpret_cast<char*>(&segment_idx), 1);

    uint16_t offset;
    file.read(reinterpret_cast<char*>(&offset), 2);

    // Read data
    size_t data_size = header.length - 4; // -3 for segment_idx and offset, -1 for checksum
    std::vector<uint8_t> data(data_size);
    file.read(reinterpret_cast<char*>(data.data()), data_size);

    // Add data to appropriate section
    if (segment_idx > 0 && segment_idx <= sections.size()) {
        auto& section = sections[segment_idx - 1];
        if (section.content.size() < offset + data_size) {
            section.content.resize(offset + data_size);
        }
        std::copy(data.begin(), data.end(), section.content.begin() + offset);
    }

    // Read checksum
    uint8_t checksum;
    file.read(reinterpret_cast<char*>(&checksum), 1);
}

ObjFile OMFParser::parse(std::ifstream& file) {
    ObjFile result;
    result.format = ObjFormat::OMF;

    while (file.good() && !file.eof()) {
        OMF::RecordHeader header;
        file.read(reinterpret_cast<char*>(&header), sizeof(header));

        if (file.eof()) break;

        switch (header.type) {
        case OMF_THEADR:
        case OMF_LHEADR:
            // Skip header record
            file.seekg(header.length, std::ios::cur);
            break;

        case OMF_LNAMES:
            parse_lnames(file, header);
            break;

        case OMF_SEGDEF:
            parse_segdef(file, header);
            break;

        case OMF_PUBDEF:
            parse_pubdef(file, header);
            break;

        case OMF_LEDATA:
            parse_ledata(file, header);
            break;

        case OMF_MODEND:
            goto end_parse;

        default:
            // Skip unknown record
            file.seekg(header.length, std::ios::cur);
            break;
        }
    }

end_parse:
    // Convert internal structures to ObjFile format
    result.sections.insert(sections.begin(), sections.end());
    result.symbols.insert(symbols.begin(), symbols.end());

    return result;
}

// COFF implementation
ObjFile ObjFile::parse_coff(std::ifstream& file) {
    ObjFile result;
    result.format = ObjFormat::COFF;

    // Read COFF header
    COFF::Header coff_header;
    file.read(reinterpret_cast<char*>(&coff_header), sizeof(coff_header));

    std::cout << "COFF Header:" << std::endl;
    std::cout << "  Number of symbols: " << coff_header.NumberOfSymbols << std::endl;
    std::cout << "  Symbol table offset: 0x" << std::hex << coff_header.PointerToSymbolTable << std::dec << std::endl;

    // Read section headers
    std::vector<COFF::SectionHeader> section_headers(coff_header.NumberOfSections);
    for (auto& header : section_headers) {
        file.read(reinterpret_cast<char*>(&header), sizeof(COFF::SectionHeader));
    }

    // First read string table size
    file.seekg(coff_header.PointerToSymbolTable +
        coff_header.NumberOfSymbols * sizeof(COFF::SymbolRecord));
    uint32_t string_table_size;
    file.read(reinterpret_cast<char*>(&string_table_size), sizeof(uint32_t));

    std::cout << "String table size: " << string_table_size << " bytes" << std::endl;

    // Read string table
    std::vector<char> string_table;
    if (string_table_size > sizeof(uint32_t)) {
        string_table.resize(string_table_size - sizeof(uint32_t));
        file.read(string_table.data(), string_table_size - sizeof(uint32_t));
    }

    // Read symbols
    file.seekg(coff_header.PointerToSymbolTable);
    std::cout << "\nParsing symbols:" << std::endl;

    for (uint32_t i = 0; i < coff_header.NumberOfSymbols; ++i) {
        COFF::SymbolRecord symbol;
        file.read(reinterpret_cast<char*>(&symbol), sizeof(COFF::SymbolRecord));

        std::string name;
        if (symbol.Name.ShortName[0] == 0) {
            // Long name from string table
            uint32_t offset = symbol.Name.LongName.Offset;
            name = read_string(string_table, offset);
            std::cout << "  Long name symbol at offset " << offset << ": " << name << std::endl;
        }
        else {
            // Short name directly from symbol record
            char short_name[9] = { 0 }; // One extra for null termination
            std::memcpy(short_name, symbol.Name.ShortName, 8);
            name = short_name;
            std::cout << "  Short name symbol: " << name << std::endl;
        }

        if (!name.empty()) {
            Symbol sym{
                name,
                symbol.Value,
                static_cast<uint16_t>(symbol.SectionNumber),
                symbol.Type,
                symbol.StorageClass,
                symbol.NumberOfAuxSymbols
            };
            result.symbols.insert(sym);

            std::cout << "    Value: 0x" << std::hex << symbol.Value << std::dec << std::endl;
            std::cout << "    Section: " << symbol.SectionNumber << std::endl;
            std::cout << "    Type: 0x" << std::hex << symbol.Type << std::dec << std::endl;
            std::cout << "    Storage Class: 0x" << std::hex << (int)symbol.StorageClass << std::dec << std::endl;
            std::cout << "    Aux Symbols: " << (int)symbol.NumberOfAuxSymbols << std::endl;
        }

        // Skip auxiliary symbol records
        i += symbol.NumberOfAuxSymbols;
        file.seekg(symbol.NumberOfAuxSymbols * sizeof(COFF::SymbolRecord), std::ios::cur);
    }

    std::cout << "\nTotal symbols parsed: " << result.symbols.size() << std::endl;

    // Read sections
    AssemblyDecoder decoder;
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

    return result;
}

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

std::string ObjFile::read_string(const std::vector<char>& string_table, uint32_t offset) {
    if (offset >= string_table.size()) {
        return "";
    }
    const char* str = string_table.data() + offset;
    return std::string(str, strnlen(str, string_table.size() - offset));
}

// Main implementation
ObjFile ObjFile::parse(const std::string& filepath) {
    try {
        std::cout << "Parsing file: " << filepath << std::endl;
        std::ifstream file(filepath, std::ios::binary);
        if (!file) {
            throw std::runtime_error("Cannot open file");
        }

        ObjFormat format = detect_format(file);
        file.seekg(0);

        switch (format) {
        case ObjFormat::OMF: {
            OMFParser parser;
            return parser.parse(file);
        }
        case ObjFormat::COFF: {
            return parse_coff(file);
        }
        default:
            throw std::runtime_error("Unknown object file format");
        }
    }
    catch (const std::exception& e) {
        throw std::runtime_error(
            fmt::format("Error parsing file {}: {}", filepath, e.what()));
    }
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
    std::set<std::string> all_symbol_names;
    json symbol_diff;

    // Collect all symbol names
    for (const auto& sym : obj1.symbols) {
        if (!sym.name.empty()) {  // Only process non-empty symbol names
            all_symbol_names.insert(sym.name);
        }
    }
    for (const auto& sym : obj2.symbols) {
        if (!sym.name.empty()) {  // Only process non-empty symbol names
            all_symbol_names.insert(sym.name);
        }
    }

    // Compare symbols
    for (const auto& name : all_symbol_names) {
        auto it1 = std::find_if(obj1.symbols.begin(), obj1.symbols.end(),
            [&name](const Symbol& s) { return s.name == name; });
        auto it2 = std::find_if(obj2.symbols.begin(), obj2.symbols.end(),
            [&name](const Symbol& s) { return s.name == name; });

        if (it1 == obj1.symbols.end()) {
            symbol_diff[name] = {
                {"status", "added"},
                {"symbol", it2->to_json()}
            };
        }
        else if (it2 == obj2.symbols.end()) {
            symbol_diff[name] = {
                {"status", "removed"},
                {"symbol", it1->to_json()}
            };
        }
        else if (!(*it1 == *it2)) {
            symbol_diff[name] = {
                {"status", "modified"},
                {"file1", it1->to_json()},
                {"file2", it2->to_json()}
            };
        }
    }

    // Only add symbols to diff if there are differences
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
            section_diff[name] = {
                {"status", "added"},
                {"format", obj2.format == ObjFormat::OMF ? "OMF" : "COFF"}
            };
        }
        else if (it2 == obj2.sections.end()) {
            section_diff[name] = {
                {"status", "removed"},
                {"format", obj1.format == ObjFormat::OMF ? "OMF" : "COFF"}
            };
        }
        else if (!(*it1 == *it2)) {
            json section_info = {
                {"format1", obj1.format == ObjFormat::OMF ? "OMF" : "COFF"},
                {"format2", obj2.format == ObjFormat::OMF ? "OMF" : "COFF"},
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

    // Add format information
    diff["file1_format"] = obj1.format == ObjFormat::OMF ? "OMF" : "COFF";
    diff["file2_format"] = obj2.format == ObjFormat::OMF ? "OMF" : "COFF";

    return diff;
}

int main(int argc, char* argv[]) {
    try {
        cxxopts::Options options("obj-diff", "Object file differ for COFF and OMF formats");
        options.add_options()
            ("f,file1", "First object file", cxxopts::value<std::string>())
            ("s,file2", "Second object file", cxxopts::value<std::string>())
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
                [](const Section& s) { return s.name == ".text" || s.name == "CODE"; });
            auto text2 = std::find_if(obj2.sections.begin(), obj2.sections.end(),
                [](const Section& s) { return s.name == ".text" || s.name == "CODE"; });

            if (text1 != obj1.sections.end() && text2 != obj2.sections.end()) {
                auto assembly_diff = compare_instructions(text1->instructions, text2->instructions);
                print_assembly_diff(assembly_diff);
            }
            else {
                std::cout << "No code sections found to compare\n";
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