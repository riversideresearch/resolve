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
    /*
    if (program.present<string>("src") && program.present<string>("dst")) {
      conf.queries.push_back({
          program.get<string>("src"),
          program.get<string>("dst"),
        });
    }
    */
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

  const unordered_map<string, facts::LoadOptions> load_options = {
    { "simple", graph::SIMPLE_LOAD_OPTIONS },
    { "cfg", graph::CFG_LOAD_OPTIONS },
    { "instr-cfg", graph::CFG_LOAD_OPTIONS },
    { "call", graph::CALL_LOAD_OPTIONS },
  };

  typedef pair<graph::handle_map, graph::T>
    (*graph_builder)(const facts::database&, bool,
                     const optional<vector<dlsym::loaded_symbol>>&);

  const unordered_map<string, graph_builder> graph_builders = {
    { "simple", graph::build_simple_graph },
    { "cfg", graph::build_cfg },
    { "instr-cfg", graph::build_instr_cfg },
    { "call", graph::build_call_graph }
  };

  if (!graph_builders.contains(conf.graph_type)) {
    cerr << "unknown graph type: '" << conf.graph_type << endl;
    exit(-1);
  }

  time_point<system_clock> t0 = system_clock::now();
  const auto db = load(conf.facts_dir, load_options.at(conf.graph_type));
  duration<double> facts_load_time = system_clock::now() - t0;

  if (conf.verbose) {
    cout << "Loaded facts in " << facts_load_time.count()
         << " seconds. # nodes = " << db.node_type.size() << endl;
  }
  if (conf.validate_facts) {
    t0 = system_clock::now();
    if (!facts::validate(db)) {
      cerr << "WARNING: facts failed validation!" << endl;
    }
    if (conf.verbose) {
      duration<double> facts_validate_time = system_clock::now() - t0;
      cout << "Validated facts in "
           << facts_validate_time.count() << " seconds" << endl;
    }
  }

  t0 = system_clock::now();
  const auto [hm, g] = graph_builders.at(conf.graph_type)
    (db, conf.dynlink, loaded_syms);
  duration<double> graph_build_time = system_clock::now() - t0;

  if (conf.verbose) {
    cout << "Loaded graph in " << graph_build_time.count()
         << " seconds. # nodes = " << g.edges.size() << endl;
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

    const auto src_handle_opt = hm.getHandleOpt(q.src);
    const auto dst_handle_opt = hm.getHandleOpt(q.dst);

    auto print_missing = [&](auto node) {
      const auto [m, n] = node;
      cerr << "node '(" << m << ", " << n << ")' not found" << endl;
    };

    if (!src_handle_opt.has_value()) {
      print_missing(q.src);
    }
    if (!dst_handle_opt.has_value()) {
      print_missing(q.dst);
    }

    // If both src and dst exist, try to find path.
    if (src_handle_opt.has_value() && dst_handle_opt.has_value()) {
      const auto [src_handle, dst_handle] = pair { src_handle_opt.value(),
                                                   dst_handle_opt.value() };

      // const auto p_opt = search::path_bfs(g.edges, dst_handle, src_handle);
      // const auto p_opt = search::path_dijkstra(g.edges, dst_handle, src_handle);
      // vector<vector<graph::edge>> paths;
      // if (p_opt.has_value()) {
      //   paths.push_back(p_opt.value());
      // }

      const auto paths = search::k_paths_yen(g.edges, dst_handle,
                                             src_handle, conf.num_paths.value());

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
          const auto id = hm.getId(e.node);
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
