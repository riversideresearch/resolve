/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include <string>
#include <filesystem>
#include <fstream>

#include "resolve_facts/resolve_facts.hpp"

#include "argparse/argparse.hpp"
#include "glaze/glaze.hpp"

using namespace resolve_facts;

int main(int argc, char *argv[]) {
    argparse::ArgumentParser program("resolve_read_props");

    program.add_argument("-f", "--facts_dir")
        .help("directory containing facts files");
    program.add_argument("node_id")
        .nargs(argparse::nargs_pattern::at_least_one)
        .help("node id to retrive properties for");

    try {
        program.parse_args(argc, argv);
    } catch (const std::exception &err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }

    if (!program.present<std::string>("facts_dir")) {
        std::exit(1);
    }
    std::filesystem::path facts_dir = program.get<std::string>("facts_dir");
    
    std::ifstream facts_f(facts_dir / "facts.facts");
    const auto facts = ProgramFacts::deserialize(facts_f);
    facts_f.close();

    for (const auto &id : program.get<std::vector<std::string>>("node_id")) {
        const Node &node = facts.getNode(from_string(id));
        {
            glz::basic_ostream_buffer<std::ostream> out(std::cout);
            auto err = glz::write<glz::opts{.prettify = true}>(node, out);
        }
        std::cout << std::endl;
    }
}
