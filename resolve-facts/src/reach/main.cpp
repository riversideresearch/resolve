/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

// reach

#include <chrono>
#include <cxxabi.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "argparse/argparse.hpp"

#include "config.hpp"
#include "reach/facts.hpp"
#include "reach/facts_view.hpp"
#include "reach/ffi.h"
#include "reach/util.hpp"

using namespace std;
using namespace chrono;
namespace fs = filesystem;
using json = nlohmann::json;

string take_error(ReachError *error) {
  if (!error) {
    return "unknown libreach error";
  }
  const string message{reinterpret_cast<const char *>(reach_error_data(error)),
                       reach_error_len(error)};
  reach_error_free(error);
  return message;
}

ReachStringView reach_string(const string &value) {
  return {reinterpret_cast<const uint8_t *>(value.data()), value.size()};
}

ReachNodeId reach_node_id(const NNodeId id) { return {id.first, id.second}; }

string reach_edge_type_to_string(const ReachEdgeType type) {
  switch (type) {
  case REACH_EDGE_DIRECT_CALL:
    return "DirectCall";
  case REACH_EDGE_INDIRECT_CALL:
    return "IndirectCall";
  case REACH_EDGE_CONTAINS:
    return "Contains";
  case REACH_EDGE_SUCCESSOR:
    return "Succ";
  case REACH_EDGE_EXTERNAL:
    return "Extern";
  case REACH_EDGE_EXTERNAL_INDIRECT_CALL:
    return "ExternIndirectCall";
  default:
    throw runtime_error("unknown reach edge type");
  }
}

// Load config from input file if it was given, then allow any
// explicitly given command line arguments to override the input file.
conf::config load_config(const argparse::ArgumentParser &program) {
  try {
    const optional<string> in_path = program.present<string>("input");
    conf::config conf;
    if (in_path.has_value()) {
      const auto conf_opt = conf::load_config_from_file(in_path.value());
      if (conf_opt.has_value()) {
        conf = conf_opt.value();
      }
    }
    if (program.present<string>("facts")) {
      conf.facts_path = program.get<string>("facts");
    }
    // TODO: argument passing with new id format
    if (program.present<string>("src") && program.present<string>("dst")) {
      auto src_str = program.get<string>("src");
      auto dst_str = program.get<string>("dst");
      auto srcs = util::split(src_str, ',');
      auto dsts = util::split(dst_str, ',');

      conf.queries.push_back({{std::stoi(srcs[0]), std::stoi(srcs[1])},
                              {std::stoi(dsts[0]), std::stoi(dsts[1])}});
    }
    conf.dynlink = program.get<bool>("dynlink") || conf.dynlink;
    if (program.present<string>("output")) {
      conf.out_path = program.present<string>("output");
    }
    if (program.present<string>("dlsym-log")) {
      conf.dlsym_log_path = program.present<string>("dlsym-log");
    }
    if (program.present<string>("graph")) {
      conf.graph_type = program.get<string>("graph");
    } else if (conf.graph_type == "") {
      conf.graph_type = "cfg";
    }
    if (program.present<size_t>("num-paths")) {
      conf.num_paths = program.get<size_t>("num-paths");
    } else if (!conf.num_paths.has_value()) {
      conf.num_paths = 1;
    }
    conf.validate_facts =
        program.get<bool>("validate-facts") || conf.validate_facts;

    if (program.present<string>("path")) {
      auto path = program.get<string>("path");
      auto path_split = util::split(path, ',');

      for (const auto &p : path_split) {
        // split on first ';' only to allow c++ namespaced names
        // e.g. graph.cpp;graph::build_from_program_facts
        auto idx = p.find(';');
        // No file specified
        if (idx == std::string::npos) {
          conf.candidate_path.emplace_back(std::nullopt, p);
        } else {
          auto path = p.substr(0, idx);
          auto node = p.substr(idx + 1);
          conf.candidate_path.emplace_back(path, node);
        }
      }
    }

    conf.verbose = program.get<bool>("verbose") || conf.verbose;
    return conf;
  } catch (exception &e) {
    throw runtime_error("argparse error: " + string(e.what()));
  }
}

optional<vector<dlsym::loaded_symbol>>
build_loaded_syms(const optional<fs::path> &path) {
  if (path.has_value()) {
    const auto log_opt = dlsym::load_log_from_file(path.value());
    if (!log_opt.has_value()) {
      return {};
    }
    const auto log = log_opt.value();
    vector<dlsym::loaded_symbol> syms;
    // Ensure no duplicate entries
    for (const auto &sym : log.loaded_symbols) {
      if (find(syms.begin(), syms.end(), sym) == syms.end()) {
        syms.push_back(sym);
      }
    }
    return {syms};
  } else {
    return {};
  }
}

void validate_config(const conf::config &conf) {
  if (!fs::exists(conf.facts_path)) {
    cerr << "CONFIG ERROR: facts_path " << conf.facts_path << " doesn't exist."
         << endl;
    exit(1);
  }
}

void print_config(const conf::config &conf) {
  const json j = conf;
  cout << setw(4) << j << endl;
}

int main(int argc, char *argv[]) {
  argparse::ArgumentParser program("reach");

  program.add_argument("-f", "--facts").help("facts file path");
  program.add_argument("-s", "--src").help("source node in graph");
  program.add_argument("-d", "--dst").help("destination node in graph");
  program.add_argument("-i", "--input").help("JSON input path");
  program.add_argument("-o", "--output").help("JSON output path");
  program.add_argument("-dl", "--dynlink")
      .help(
          "treat functions with external linkage as having their address taken")
      .flag();
  program.add_argument("-ds", "--dlsym-log")
      .help("path to file containing dlsym log of loaded symbols");
  program.add_argument("-g", "--graph")
      .help("graph type (\"simple\", \"cfg\", or \"call\"). Default \"cfg\"");
  program.add_argument("-p", "--path")
      .help("candidate path of comma-separated function_name or "
            "file;function_name");
  program.add_argument("-n", "--num-paths")
      .help("number of paths to generate (n shortest)")
      .scan<'i', size_t>();
  program.add_argument("--validate-facts")
      .help("validate facts database after loading")
      .flag();
  program.add_argument("--verbose")
      .help("print misc information to stdout")
      .flag();

  try {
    program.parse_args(argc, argv);
  } catch (const std::exception &err) {
    cerr << err.what() << endl;
    cerr << program;
    exit(1);
  }

  conf::config conf = load_config(program);
  if (conf.verbose) {
    cout << "Loaded config:" << endl;
    print_config(conf);
  }
  validate_config(conf);
  const auto loaded_syms = build_loaded_syms(conf.dlsym_log_path);

  // Execute reachability queries.
  // First, build graph.

  if (conf.graph_type != "cfg") {
    cerr << "unknown graph type: '" << conf.graph_type << endl;
    exit(-1);
  }

  time_point<system_clock> t0 = system_clock::now();
  const auto facts = reach_facts::FactsOwner::read({conf.facts_path});
  const auto pf = facts.view();

  duration<double> facts_load_time = system_clock::now() - t0;

  if (conf.verbose) {

    auto nodes = 0;
    auto edges = 0;
    for (const auto &[_, m] : pf.modules) {
      nodes += m.nodes.size();
      edges += m.edges.size();
    }
    cout << "Loaded facts in " << facts_load_time.count()
         << " seconds. # nodes = " << nodes << " # edges = " << edges << endl;
  }

  vector<ReachLoadedSymbol> symbol_views;
  if (loaded_syms) {
    symbol_views.reserve(loaded_syms->size());
    for (const auto &symbol : *loaded_syms) {
      symbol_views.push_back(
          {reach_string(symbol.symbol), reach_string(symbol.library)});
    }
  }
  const ReachBuildOptions build_options = {
      symbol_views.data(),
      symbol_views.size(),
      static_cast<uint8_t>(conf.dynlink),
      static_cast<uint8_t>(loaded_syms.has_value()),
  };

  t0 = system_clock::now();
  ReachError *build_error = nullptr;
  using GraphPtr = unique_ptr<ReachGraph, decltype(&reach_graph_free)>;
  const GraphPtr g{reach_graph_build(facts.get(), &build_options, &build_error),
                   reach_graph_free};
  if (!g) {
    throw runtime_error(take_error(build_error));
  }
  duration<double> graph_build_time = system_clock::now() - t0;

  if (conf.verbose) {
    cout << "Loaded graph in " << graph_build_time.count()
         << " seconds. # edges = " << reach_graph_edge_count(g.get()) << endl;
  }

  // Then execute queries against the graph and accumulate results.

  output::results res;
  res.facts_load_time = facts_load_time.count();
  res.graph_build_time = graph_build_time.count();

  std::vector<NNodeId> candidate_ids;

  auto find_node = [&](const auto &node) -> std::optional<NNodeId> {
    for (const auto &[mid, m] : pf.modules) {
      if (node.file &&
          !m.nodes.at(0).source_file().value_or("").contains(*node.file)) {
        continue;
      }

      for (const auto &[nid, n] : m.nodes) {
        if (n.type() == facts_rs::NodeType::Function && n.name().has_value()) {
          const auto name = n.name().value();
          // Try an exact match on the function name
          if (name == node.function_name) {
            return std::optional{std::make_pair(mid, nid)};
          }

          // If that doesn't work attempt to demangle the name
          // Sadly __cxa_demangle either requires a malloced pointer as input,
          // or returns a (fresh) malloced pointer as a result.
          // Calling free() in 2025 is sad. I tried to be fancy with a
          // shared_ptr with a custom deallocator but was getting malloc
          // corruption errors.
          const string mangled{name};
          auto ret = abi::__cxa_demangle(mangled.c_str(), NULL, NULL, NULL);

          if (ret) {
            std::string demangled{ret};
            free(ret);

            if (demangled.contains(node.function_name)) {
              return std::optional{std::make_pair(mid, nid)};
            }
          }
        }
      }
    }
    return std::nullopt;
  };

  for (const auto &p : conf.candidate_path) {
    auto id = find_node(p);
    if (!id.has_value()) {
      cerr << "No matching node found for candidate path node (file: "
           << p.file.value_or("<none>") << ", function: " << p.function_name
           << ")\n";
    } else {
      candidate_ids.push_back(id.value());
    }
  }

  if (conf.candidate_path.size() > 1 && candidate_ids.size() < 2) {
    cerr << "Candidate path specified but not enough nodes found; path: \n";
    for (const auto &p : conf.candidate_path) {
      cerr << "\t file:" << p.file.value_or("<none>")
           << ", name: " << p.function_name << "\n";
    }
  } else if (candidate_ids.size() >= 2) {
    for (auto i = 0; i < candidate_ids.size() - 1; i += 1) {
      conf.queries.emplace_back(candidate_ids[i], candidate_ids[i + 1]);
    }
  }

  for (const auto &q : conf.queries) {
    t0 = system_clock::now();
    output::query_result qres;
    qres.src = q.src;
    qres.dst = q.dst;

    auto print_missing = [&](auto node, auto type) {
      cerr << "node " << type << " " << resolve_facts::to_string(node)
           << " not found" << endl;
    };

    // The graph may not have any edges from the src as all may be of the form
    // (dst -> src) If the explicit edge does not exist at least check that the
    // id is found in the total list of nodes
    auto has_src = pf.containsNode(q.src);
    auto has_dst = pf.containsNode(q.dst);

    if (!has_src) {
      print_missing(q.src, "src");
    }
    if (!has_dst) {
      print_missing(q.dst, "dst");
    }

    // If both src and dst exist, try to find path.
    if (has_src && has_dst) {

      ReachError *query_error = nullptr;
      using QueryPtr =
          unique_ptr<ReachQueryResult, decltype(&reach_query_result_free)>;
      const QueryPtr paths{
          reach_graph_query(g.get(), reach_node_id(q.src), reach_node_id(q.dst),
                            conf.num_paths.value(), &query_error),
          reach_query_result_free};
      if (!paths) {
        throw runtime_error(take_error(query_error));
      }

      duration<double> query_time = system_clock::now() - t0;
      qres.query_time = query_time.count();

      for (size_t i = 0; i < reach_query_result_path_count(paths.get()); ++i) {
        ReachPathView path{};
        if (!reach_query_result_path(paths.get(), i, &path)) {
          throw runtime_error("libreach returned an invalid path result");
        }

        vector<NNodeId> p_ids;
        p_ids.reserve(path.node_count);
        for (size_t j = 0; j < path.node_count; ++j) {
          p_ids.emplace_back(path.nodes[j].module, path.nodes[j].node);
        }

        vector<string> edges;
        edges.reserve(path.edge_count);
        for (size_t j = 0; j < path.edge_count; ++j) {
          edges.push_back(reach_edge_type_to_string(path.edges[j]));
        }

        qres.paths.push_back({p_ids, edges});
      }
    } else {
      exit(-1);
    }

    res.query_results.push_back(qres);
  }

  // Dump results object to out_path if it exists, else to stdout.
  const json j = res;
  if (conf.out_path.has_value()) {
    ofstream f(conf.out_path.value());
    f << setw(4) << j << endl;
  } else {
    cout << setw(4) << j << endl;
  }

  // for (const auto& qres : res.query_results) {
  //   cout << "# paths: " << qres.paths.size() << endl;
  // }
}
