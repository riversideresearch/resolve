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
    if (program.present<string>("src") && program.present<string>("dst")) {
      conf.queries.push_back({
          program.get<string>("src"),
          program.get<string>("dst"),
        });
    }
    if (program.present<bool>("dynlink")) {
      conf.dynlink = program.get<bool>("dynlink");
    } else {
      conf.dynlink = conf.dynlink.has_value() && conf.dynlink.value();
    }
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
  program.add_argument("-m", "--distmap")
    .help("enable to output distance map and blacklist for query destination")
    .implicit_value(true);
  program.add_argument("-dl", "--dynlink")
    .help("treat functions with external linkage as having their address taken")
    .implicit_value(true);
  program.add_argument("-ds", "--dlsym-log")
    .help("path to file containing dlsym log of loaded symbols");
  program.add_argument("-o", "--output")
    .help("JSON output path");
  program.add_argument("-g", "--graph")
    .help("graph type (\"simple\", \"cfg\", or \"call\"). Default \"cfg\"");
  program.add_argument("-n", "--num-paths")
    .help("number of paths to generate (n shortest)")
    .scan<'i', size_t>();;

  try {
    program.parse_args(argc, argv);
  }
  catch (const std::exception& err) {
    cerr << err.what() << endl;
    cerr << program;
    exit(1);
  }

  const conf::config conf = load_config(program);
  validate_config(conf);
  const auto loaded_syms = build_loaded_syms(conf.dlsym_log_path);

  // Execute reachability queries.

  // First, build graph.

  typedef pair<graph::handle_map, graph::T>
    (*graph_builder)(const filesystem::path&, bool,
                     const optional<vector<dlsym::loaded_symbol>>&);

  const unordered_map<string, graph_builder> graph_builders = {
    { "simple", [](const filesystem::path& facts_dir,
                   bool dynlink,
                   const optional<vector<dlsym::loaded_symbol>>& loaded_syms) {
      const auto db = load(facts_dir, graph::SIMPLE_LOAD_OPTIONS);
      return graph::build_simple_graph(db, dynlink, loaded_syms);
    }},
    { "cfg", [](const filesystem::path& facts_dir,
                bool dynlink,
                const optional<vector<dlsym::loaded_symbol>>& loaded_syms) {
      const auto db = load(facts_dir, graph::CFG_LOAD_OPTIONS);
      return graph::build_cfg(db, dynlink, loaded_syms);
    }},
    { "instr_cfg", [](const filesystem::path& facts_dir,
                      bool dynlink,
                      const optional<vector<dlsym::loaded_symbol>>& loaded_syms) {
      const auto db = load(facts_dir, graph::CFG_LOAD_OPTIONS);
      return graph::build_instr_cfg(db, dynlink, loaded_syms);
    }},
    { "call", [](const filesystem::path& facts_dir,
                 bool dynlink,
                 const optional<vector<dlsym::loaded_symbol>>& loaded_syms) {
      const auto db = load(facts_dir, graph::CALL_LOAD_OPTIONS);
      return graph::build_call_graph(db, dynlink, loaded_syms);
    }},
  };

  if (!graph_builders.contains(conf.graph_type)) {
    cerr << "unknown graph type: '" << conf.graph_type << endl;
    exit(-1);
  }

  const time_point<system_clock> t0 = system_clock::now();
  const auto [hm, g] = graph_builders.at(conf.graph_type)(conf.facts_dir,
                                                          conf.dynlink.value(),
                                                          loaded_syms);
  const time_point<system_clock> t1 = system_clock::now();
  duration<double> load_time = t1 - t0;

  if (!graph::wf(g.edges)) {
    cerr << "WARNING: graph not well-formed" << endl;
  }

  // Then execute queries against the graph and accumulate results.

  output::results res;
  res.load_time = load_time.count();

  for (const auto& q : conf.queries) {
    output::query_result qres;
    qres.src = q.src;
    qres.dst = q.dst;

    const auto src_handle_opt = hm.getHandleOpt(q.src);
    const auto dst_handle_opt = hm.getHandleOpt(q.dst);

    if (!src_handle_opt.has_value()) {
      cerr << "node '" << q.src << "' not found" << endl;
    }
    if (!dst_handle_opt.has_value()) {
      cerr << "node '" << q.dst << "' not found" << endl;
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

      const time_point<system_clock> t2 = system_clock::now();
      duration<double> query_time = t2 - t1;
      qres.query_time = query_time.count();

      vector<double> weights;
      for (const auto& p : paths) {
        weights.push_back(graph::path_weight(p));
      }
      if (!is_sorted(weights.begin(), weights.end())) {
        cerr << "WARNING: paths not sorted by weight" << endl;
      }

      for (const auto& path : paths) {
        vector<string> p_ids;
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
