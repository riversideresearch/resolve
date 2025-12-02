/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

// reach

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "argparse.hpp"
#include "config.hpp"
#include "facts.hpp"
#include "graph.hpp"
#include "search.hpp"
#include "util.hpp"

using namespace std;
using namespace chrono;
namespace fs = filesystem;
using json = nlohmann::json;

// Load config from input file if it was given, then allow any
// explicitly given command line arguments to override the input file.
conf::config load_config(const argparse::ArgumentParser& program) {
  try {
    const optional<string> in_path = program.present<string>("input");
    conf::config conf;
    if (in_path.has_value()) {
      const auto conf_opt = conf::load_config_from_file(in_path.value());
      if (conf_opt.has_value()) {
        conf = conf_opt.value();
      }
    }
    if (program.present<string>("facts_dir")) {
      conf.facts_dir = program.get<string>("facts_dir");
    }
    // TODO: argument passing with new id format
    if (program.present<string>("src") && program.present<string>("dst")) {
      auto src_str = program.get<string>("src");
      auto dst_str = program.get<string>("dst");
      auto srcs = util::split(src_str, ',');
      auto dsts = util::split(dst_str, ',');
      
      conf.queries.push_back({
          { std::stoi(srcs[0]), std::stoi(srcs[1]) },
          { std::stoi(dsts[0]), std::stoi(dsts[1]) }
        });
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
    conf.verbose = program.get<bool>("verbose") || conf.verbose;
    return conf;
  }
  catch (exception &e) {
    throw runtime_error("argparse error: " + string(e.what()));
  }
}

optional<vector<dlsym::loaded_symbol>>
build_loaded_syms(const optional<fs::path>& path) {
  if (path.has_value()) {
    const auto log_opt = dlsym::load_log_from_file(path.value());
    if (!log_opt.has_value()) {
      return {};
    }
    const auto log = log_opt.value();
    vector<dlsym::loaded_symbol> syms;
    // Ensure no duplicate entries
    for (const auto& sym : log.loaded_symbols) {
      if (find(syms.begin(), syms.end(), sym) == syms.end()) {
        syms.push_back(sym);
      }
    }
    return { syms };
  } else {
    return {};
  }
}

void validate_config(const conf::config& conf) {
  if (!fs::exists(conf.facts_dir)) {
    cerr << "CONFIG ERROR: facts_dir "
         << conf.facts_dir << " doesn't exist." << endl;
    exit(1);
  }
}

void print_config(const conf::config &conf) {
  const json j = conf;
  cout << setw(4) << j << endl;
}

int main(int argc, char* argv[]) {
  argparse::ArgumentParser program("reach");

  program.add_argument("-f", "--facts_dir")
    .help("directory containing facts files");
  program.add_argument("-s", "--src")
    .help("source node in graph");
  program.add_argument("-d", "--dst")
    .help("destination node in graph");
  program.add_argument("-i", "--input")
    .help("JSON input path");
  program.add_argument("-o", "--output")
    .help("JSON output path");
  program.add_argument("-dl", "--dynlink")
    .help("treat functions with external linkage as having their address taken")
    .flag();
  program.add_argument("-ds", "--dlsym-log")
    .help("path to file containing dlsym log of loaded symbols");
  program.add_argument("-o", "--output")
    .help("JSON output path");
  program.add_argument("-g", "--graph")
    .help("graph type (\"simple\", \"cfg\", or \"call\"). Default \"cfg\"");
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
  }
  catch (const std::exception& err) {
    cerr << err.what() << endl;
    cerr << program;
    exit(1);
  }

  const conf::config conf = load_config(program);
  if (conf.verbose) {
    cout << "Loaded config:" << endl;
    print_config(conf);
  }
  validate_config(conf);
  const auto loaded_syms = build_loaded_syms(conf.dlsym_log_path);

  // Execute reachability queries.
  // First, build graph.

  typedef graph::T
    (*graph_builder)(const resolve_facts::ProgramFacts&, bool,
                     const optional<vector<dlsym::loaded_symbol>>&);

  const unordered_map<string, graph_builder> graph_builders = {
    { "cfg", graph::build_from_program_facts },
  };

  if (!graph_builders.contains(conf.graph_type)) {
    cerr << "unknown graph type: '" << conf.graph_type << endl;
    exit(-1);
  }

  time_point<system_clock> t0 = system_clock::now();
  ifstream facts(conf.facts_dir / "facts.facts");
  const auto pf = resolve_facts::ProgramFacts::deserialize(facts);
  facts.close();

  duration<double> facts_load_time = system_clock::now() - t0;


  if (conf.verbose) {

    auto nodes = 0;
    auto edges = 0;
    for (const auto& [_, m]: pf.modules) {
      nodes += m.nodes.size();
      edges += m.edges.size();
    }
    cout << "Loaded facts in " << facts_load_time.count()
         << " seconds. # nodes = " << nodes
         << " # edges = " << edges << endl;
  }

  t0 = system_clock::now();
  const auto g = graph_builders.at(conf.graph_type)(pf, conf.dynlink, loaded_syms);
  duration<double> graph_build_time = system_clock::now() - t0;

  if (conf.verbose) {
    auto edges = 0;
    for (const auto& [_, e]: g.edges) {
      edges += e.size();
    }

    cout << "Loaded graph in " << graph_build_time.count()
         << " seconds. # edges = " << edges << endl;
  }
  if (!graph::wf(g.edges)) {
    cerr << "WARNING: graph not well-formed" << endl;
  }

  // Then execute queries against the graph and accumulate results.

  output::results res;
  res.facts_load_time = facts_load_time.count();
  res.graph_build_time = graph_build_time.count();

  for (const auto &q : conf.queries) {
    t0 = system_clock::now();
    output::query_result qres;
    qres.src = q.src;
    qres.dst = q.dst;

    auto print_missing = [&](auto node, auto type) {
      cerr << "node " << type << " " << resolve_facts::to_string(node) << " not found" << endl;
    };

    // The graph may not have any edges from the src as all may be of the form (dst -> src)
    // If the explicit edge does not exist at least check that the id is found in the total list of nodes
    auto has_src = g.edges.contains(q.src) || pf.containsNode(q.src);
    auto has_dst = g.edges.contains(q.dst) || pf.containsNode(q.dst);

    if (!has_src) {
      print_missing(q.src, "src");
    }
    if (!has_dst) {
      print_missing(q.dst, "dst");
    }

    // If both src and dst exist, try to find path.
    if (has_src && has_dst) {

      const auto paths = search::k_paths_yen(g.edges, q.dst,
                                             q.src, conf.num_paths.value());

      duration<double> query_time = system_clock::now() - t0;
      qres.query_time = query_time.count();

      vector<double> weights;
      for (const auto& p : paths) {
        weights.push_back(graph::path_weight(p));
      }
      if (!is_sorted(weights.begin(), weights.end())) {
        cerr << "WARNING: paths not sorted by weight" << endl;
      }

      for (const auto& path : paths) {
        vector<NNodeId> p_ids;
        vector<string> edges;
        for (const auto& e : path) {
          const auto id = e.node;
          p_ids.push_back(id);
          edges.push_back(EdgeType_to_string(e.type));
        }

        reverse(p_ids.begin(), p_ids.end());
        reverse(edges.begin(), edges.end());
        edges.pop_back();

        qres.paths.push_back({ p_ids, edges });
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
