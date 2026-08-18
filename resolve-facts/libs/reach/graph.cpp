/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#include <algorithm>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "reach/facts.hpp"
#include "reach/facts_view.hpp"
#include "reach/graph.hpp"
#include "reach/util.hpp"

using namespace reach_facts;
using namespace graph;
using namespace std;
using symbol = dlsym::loaded_symbol;
using EdgeKind = resolve_facts::EdgeKind;
using NodeType = resolve_facts::NodeType;

std::string graph::EdgeType_to_string(EdgeType ety) {
  switch (ety) {
  case EdgeType::DirectCall:
    return "DirectCall";
  case EdgeType::IndirectCall:
    return "IndirectCall";
  case EdgeType::Contains:
    return "Contains";
  case EdgeType::Succ:
    return "Succ";
  case EdgeType::Extern:
    return "Extern";
  case EdgeType::ExternIndirectCall:
    return "ExternIndirectCall";
  case EdgeType::Self:
    return "Self";
  default:
    throw runtime_error("unreachable");
  }
}

double graph::path_weight(const vector<edge> &path) {
  double w = 0.0;
  for (const auto &e : path) {
    w += e.weight;
  }
  return w;
}

bool graph::wf(const E &g) { return true; }

// Add edge [l->r].
void T::addEdge(NNodeId l, NNodeId r, EdgeType ety, double weight) {
  auto [it, exists] = edges.try_emplace(l);

  it->second.insert({r, weight, ety});
}

// Transform set of loaded symbols into set of matching node ids. If
// [loaded_syms] doesn't have a value, we do nothing here and the
// graph constructions don't do any filtering of external functions
// for indirect calls.
vector<NNodeId>
map_loaded_symbols_to_ids(const database &db,
                          const optional<vector<symbol>> &loaded_syms) {
  if (!loaded_syms.has_value()) {
    return {};
  }
  const auto syms = loaded_syms.value();
  vector<NNodeId> loaded_ids;
  // TODO: currently O(NM)
  for (const auto &[id, ty] : db.node_type) {
    if (ty == NodeType::Function) {
      auto fn = db.name.at(id);
      for (const auto &sym : syms) {
        if (sym.symbol == fn) {
          loaded_ids.push_back(id);
          break;
        }
      }
    }
  }
  return loaded_ids;
}

T graph::build_from_program_facts(const facts_rs::FactsBuf *facts, bool dynlink,
                                  const optional<vector<symbol>> &loaded_syms) {
  const reach_facts::ProgramFactsView pf{facts};

  T g;

  // adapted from build_cfg
  // Need to be able to look up triple (bb -> instr -> call)
  NodeMap<NNodeId> calls;
  NodeMap<std::vector<NNodeId>> bb_calls;

  // For indirect calls we want to get all function that match a signature
  std::unordered_map<string_view, std::vector<NNodeId>> address_taken_by_sig;

  // We want to be able to link all externs of the same name together
  // and also externs to dynamic symbols if applicable.
  unordered_map<string_view, vector<NNodeId>> externs_by_name;

  std::unordered_set<NNodeId, resolve_facts::pair_hash> loaded_ids;
  std::vector<symbol> syms;
  if (loaded_syms.has_value()) {
    syms = *loaded_syms;
  }

  for (uint32_t mid = 0; mid < pf.module_count(); ++mid) {
    const auto m = pf.module(mid);

    for (const auto &e : m.edges()) {
      const auto s = e.src;
      const auto d = e.dst;
      auto sid = std::make_pair(mid, s);
      auto did = std::make_pair(mid, d);

      // fn to first block
      if (edge_has_kind(e, facts_rs::EdgeKind::EntryPoint)) {
        g.addEdge(did, sid, EdgeType::Contains);
      }
      // BB control flow
      if (edge_has_kind(e, facts_rs::EdgeKind::ControlFlowTo)) {
        g.addEdge(did, sid, EdgeType::Succ);
      }
      if (edge_has_kind(e, facts_rs::EdgeKind::Calls)) {
        calls.emplace(sid, did);
      }

      if (edge_has_kind(e, facts_rs::EdgeKind::Contains) &&
          m.node(s).type() == facts_rs::NodeType::BasicBlock &&
          m.node(d).call_type().has_value()) {
        bb_calls[sid].push_back(did);
      }
    }

    for (uint32_t nid = 0; nid < m.nodes().size(); ++nid) {
      const auto n = m.node(nid);
      auto id = std::make_pair(mid, nid);
      if (n.linkage() == facts_rs::Linkage::ExternalLinkage) {
        externs_by_name[*n.name()].push_back(id);
      }

      if (n.address_taken()) {
        auto sig = *n.function_type();
        address_taken_by_sig[sig].push_back(id);
      }

      if (n.type() == facts_rs::NodeType::Function && dynlink) {
        for (const auto &sym : syms) {
          if (n.name() && sym.symbol == *n.name()) {
            loaded_ids.emplace(id);
            break;
          }
        }
      }
    }
  }

  // Calls
  for (const auto &[bb, instrs] : bb_calls) {
    const auto [mid, bbid] = bb;
    const auto module = pf.module(mid);
    for (const auto &instr : instrs) {
      const auto [_, iid] = instr;
      const auto n = module.node(iid);
      const auto call_ty = n.call_type();
      // If direct, add one edge.
      if (call_ty == facts_rs::CallType::Direct) {
        const auto &call_id = calls.at(instr);
        g.addEdge(call_id, bb, EdgeType::DirectCall);

        // Special case for direct calls to [pthread_create]: add
        // edges for all address-taken functions with type signature
        // "ptr (ptr)".
        const auto &[_, cid] = call_id;

        const auto fn_name = module.node(cid).name();
        if (fn_name && *fn_name == "pthread_create") {
          for (const auto &fn : address_taken_by_sig.at("ptr (ptr)")) {
            g.addEdge(fn, bb, EdgeType::IndirectCall, INDIRECT_WEIGHT);
          }
        }

        continue;
      }

      if (address_taken_by_sig.contains(*n.function_type())) {
        // Else indirect. Add edges for all compatible address-taken functions.
        for (const auto &fn : address_taken_by_sig.at(*n.function_type())) {
          g.addEdge(fn, bb, EdgeType::IndirectCall, INDIRECT_WEIGHT);
        }
      }

      // If dynlink flag is set, also take functions with external
      // linkage as possible call targets.
      // TODO: this
      if (dynlink) {
        for (const auto &[_, handles] : externs_by_name) {
          for (const auto &h : handles) {
            const auto n2 = pf.node(h);
            if (n2.type() == facts_rs::NodeType::Function &&
                n2.function_type() == n.function_type() &&
                (!loaded_syms.has_value() || loaded_ids.contains(h))) {
              g.addEdge(h, bb, EdgeType::ExternIndirectCall, INDIRECT_WEIGHT);
            }
          }
        }
      }
    }
  }

  // External linkage
  for (const auto &[_, handles] : externs_by_name) {
    for (size_t i = 0; i < handles.size(); i++) {
      for (size_t j = i + 1; j < handles.size(); j++) {
        g.addEdge(handles[i], handles[j], EdgeType::Extern, INDIRECT_WEIGHT);
        g.addEdge(handles[j], handles[i], EdgeType::Extern, INDIRECT_WEIGHT);
      }
    }
  }

  return g;
}

// Simple: edges (Contains(x -> y), DirectCall(instr -> fn), direct
// pthread(instr -> fn), indirect internal(instr -> fn), indirect extreanl(instr
// -> linked))

// Call: edges (DirectCall(fn -> fn), direct pthread(fn -> fn), indirect
// internal(fn -> fn), indirect external(fn -> linked), externals)

// cfg (Contains(fn -> bb), Succ(bb -> instr), Direct(bb -> instr -> fn), direct
// pthread(bb -> fn), Indirect(bb -> fn)
//      ExternIndirect(bb -> fn), Extern(sym -> sym)

// Call edges aren't directly from calling BB to entry BB of called
// function. Instead they go caller BB -> callee function -> entry
// point BB, with the extra function node in between. I think this is
// fine, maybe even desirable because it makes the path search
// algorithm consider function calls to be a bit more expensive (total
// weight 2, or 3 for externals because of ExternalLinkage edges) than
// BB successor edges. Including the function nodes also makes it
// possible to specify functions as targets for directed KLEE.

// instr_cfg (Contains(fn -> first_instr), Succ(instr -> instr),
// Succ(bb.last_instr -> bb.first_instr),
//            DirectCall(instr -> fn), direct pthread(instr -> fn),
//            IndirectCall(instr -> fn), IndirectExternal(instr -> fn),
//            Extern(sym -> sym)

// Same thing here as [build_cfg] (see above) wrt. Call edges going
// through intermediate function nodes.
T graph::build_instr_cfg(const facts_rs::FactsBuf *facts, bool dynlink,
                         const optional<vector<symbol>> &loaded_syms) {
  const reach_facts::ProgramFactsView pf{facts};
  T g;

  unordered_map<string_view, vector<NNodeId>> address_taken_by_sig;
  unordered_map<string_view, vector<NNodeId>> externs_by_name;
  unordered_set<NNodeId, resolve_facts::pair_hash> loaded_ids;

  for (uint32_t mid = 0; mid < pf.module_count(); ++mid) {
    const auto module = pf.module(mid);
    for (uint32_t nid = 0; nid < module.nodes().size(); ++nid) {
      const auto node = module.node(nid);
      const auto id = make_pair(mid, nid);

      if (node.linkage() == facts_rs::Linkage::ExternalLinkage) {
        externs_by_name[*node.name()].push_back(id);
      }
      if (node.address_taken()) {
        address_taken_by_sig[*node.function_type()].push_back(id);
      }
      if (dynlink && loaded_syms &&
          node.type() == facts_rs::NodeType::Function) {
        for (const auto &loaded : *loaded_syms) {
          if (node.name() && loaded.symbol == *node.name()) {
            loaded_ids.insert(id);
            break;
          }
        }
      }
    }
  }

  auto instruction_bounds = [](const reach_facts::ModuleView module,
                               const facts_rs::NodeID bb) {
    pair<optional<facts_rs::NodeID>, optional<facts_rs::NodeID>> result;
    for (const auto &edge : module.out_edges(bb)) {
      if (edge_has_kind(edge, facts_rs::EdgeKind::Contains) &&
          module.node(edge.dst).type() == facts_rs::NodeType::Instruction) {
        if (!result.first) {
          result.first = edge.dst;
        }
        result.second = edge.dst;
      }
    }
    return result;
  };

  for (uint32_t mid = 0; mid < pf.module_count(); ++mid) {
    const auto module = pf.module(mid);

    for (uint32_t bb = 0; bb < module.nodes().size(); ++bb) {
      if (module.node(bb).type() != facts_rs::NodeType::BasicBlock) {
        continue;
      }

      optional<facts_rs::NodeID> previous;
      for (const auto &edge : module.out_edges(bb)) {
        if (!edge_has_kind(edge, facts_rs::EdgeKind::Contains) ||
            module.node(edge.dst).type() != facts_rs::NodeType::Instruction) {
          continue;
        }

        const auto instruction = edge.dst;
        if (previous) {
          g.addEdge(make_pair(mid, instruction), make_pair(mid, *previous),
                    EdgeType::Succ);
        }
        previous = instruction;

        const auto node = module.node(instruction);
        const auto call_type = node.call_type();
        if (!call_type) {
          continue;
        }

        const auto instruction_id = make_pair(mid, instruction);
        if (*call_type == facts_rs::CallType::Direct) {
          optional<NNodeId> target;
          for (const auto &call : module.out_edges(instruction)) {
            if (edge_has_kind(call, facts_rs::EdgeKind::Calls)) {
              target = make_pair(mid, call.dst);
              break;
            }
          }
          if (!target) {
            throw runtime_error("direct call has no call edge");
          }

          g.addEdge(*target, instruction_id, EdgeType::DirectCall);
          const auto [_, target_node] = *target;
          if (module.node(target_node).name() == "pthread_create") {
            if (const auto it = address_taken_by_sig.find("ptr (ptr)");
                it != address_taken_by_sig.end()) {
              for (const auto &function : it->second) {
                g.addEdge(function, instruction_id, EdgeType::IndirectCall,
                          INDIRECT_WEIGHT);
              }
            }
          }
          continue;
        }

        const auto signature = node.function_type();
        if (!signature) {
          throw runtime_error("indirect call has no function type");
        }
        if (const auto it = address_taken_by_sig.find(*signature);
            it != address_taken_by_sig.end()) {
          for (const auto &function : it->second) {
            g.addEdge(function, instruction_id, EdgeType::IndirectCall,
                      INDIRECT_WEIGHT);
          }
        }

        if (dynlink) {
          for (const auto &[_, handles] : externs_by_name) {
            for (const auto &handle : handles) {
              const auto function = pf.node(handle);
              if (function.type() == facts_rs::NodeType::Function &&
                  function.function_type() == signature &&
                  (!loaded_syms || loaded_ids.contains(handle))) {
                g.addEdge(handle, instruction_id, EdgeType::ExternIndirectCall,
                          INDIRECT_WEIGHT);
              }
            }
          }
        }
      }
    }

    for (const auto &edge : module.edges()) {
      if (edge_has_kind(edge, facts_rs::EdgeKind::EntryPoint)) {
        const auto bounds = instruction_bounds(module, edge.dst);
        if (!bounds.first) {
          throw runtime_error("entry block has no instruction");
        }
        g.addEdge(make_pair(mid, *bounds.first), make_pair(mid, edge.src),
                  EdgeType::Contains);
      }
      if (edge_has_kind(edge, facts_rs::EdgeKind::ControlFlowTo)) {
        const auto source = instruction_bounds(module, edge.src);
        const auto destination = instruction_bounds(module, edge.dst);
        if (!source.second || !destination.first) {
          throw runtime_error("control-flow block has no instruction");
        }
        g.addEdge(make_pair(mid, *destination.first),
                  make_pair(mid, *source.second), EdgeType::Succ);
      }
    }
  }

  for (const auto &[_, handles] : externs_by_name) {
    for (size_t i = 0; i < handles.size(); ++i) {
      for (size_t j = i + 1; j < handles.size(); ++j) {
        g.addEdge(handles[i], handles[j], EdgeType::Extern, INDIRECT_WEIGHT);
        g.addEdge(handles[j], handles[i], EdgeType::Extern, INDIRECT_WEIGHT);
      }
    }
  }

  return g;
}

T graph::build_instr_cfg(const database &db, bool dynlink,
                         const optional<vector<symbol>> &loaded_syms) {
  const auto loaded_ids = map_loaded_symbols_to_ids(db, loaded_syms);

  T g;

  // function -> entry instruction
  for (const auto &[fn, bb] : db.function_entrypoints) {
    const auto &first_instr = db.contains.at(bb).front();
    g.addEdge(first_instr, fn, EdgeType::Contains);
  }

  // Intra-BB control flow (straight line)
  for (const auto &[bb, bb_ty] : db.node_type) {
    if (bb_ty != NodeType::BasicBlock) {
      continue;
    }
    const auto &instrs = db.contains.at(bb);
    for (size_t i = 0; i < instrs.size() - 1; i++) {
      g.addEdge(instrs[i + 1], instrs[i], EdgeType::Succ);
    }
  }

  // Inter-BB control flow
  for (const auto &[bb, succs] : db.control_flow) {
    for (const auto &succ : succs) {
      const auto &src_instr = db.contains.at(bb).back();
      const auto &dst_instr = db.contains.at(succ).front();
      g.addEdge(dst_instr, src_instr, EdgeType::Succ);
    }
  }

  // Calls
  for (const auto &[bb, instrs] : db.contains) {
    if (db.node_type.at(bb) != NodeType::BasicBlock) {
      continue;
    }
    for (const auto &instr : instrs) {
      if (!db.call_type.contains(instr)) {
        continue;
      }
      const auto &call_ty = db.call_type.at(instr);
      // If direct, add one edge.
      if (call_ty == CallType::Direct) {
        g.addEdge(db.calls.at(instr), instr, EdgeType::DirectCall);

        // Special case for direct calls to [pthread_create]: add
        // edges for all address-taken functions with type signature
        // "ptr (ptr)".
        const auto &call_id = db.calls.at(instr);
        const auto &fn_name = db.name.at(call_id);
        if (fn_name == "pthread_create") {
          for (const auto &fn : db.address_taken) {
            if (db.fun_sig.at(fn) == "ptr (ptr)") {
              g.addEdge(fn, instr, EdgeType::IndirectCall, INDIRECT_WEIGHT);
            }
          }
        }

        continue;
      }
      // Else indirect. Add edges for all compatible address-taken functions.
      for (const auto &fn : db.address_taken) {
        if (db.fun_sig.at(fn) == db.fun_sig.at(instr)) {
          g.addEdge(fn, instr, EdgeType::IndirectCall, INDIRECT_WEIGHT);
        }
      }
      // If dynlink flag is set, also take functions with external
      // linkage as possible call targets.
      if (dynlink) {
        for (const auto &[id, linkage] : db.linkage) {
          if (linkage == Linkage::ExternalLinkage &&
              db.node_type.at(id) == NodeType::Function &&
              db.fun_sig.at(instr) == db.fun_sig.at(id) &&
              (!loaded_syms.has_value() ||
               find(loaded_ids.begin(), loaded_ids.end(), id) !=
                   loaded_ids.end())) {
            g.addEdge(id, instr, EdgeType::ExternIndirectCall, INDIRECT_WEIGHT);
          }
        }
      }
    }
  }

  // External linkage
  unordered_map<string, vector<NNodeId>> name2handles;
  for (const auto &[id, linkage] : db.linkage) {
    if (linkage == Linkage::ExternalLinkage) {
      name2handles[db.name.at(id)].push_back(id);
    }
  }
  for (const auto &[_, handles] : name2handles) {
    for (size_t i = 0; i < handles.size(); i++) {
      for (size_t j = i + 1; j < handles.size(); j++) {
        g.addEdge(handles[i], handles[j], EdgeType::Extern, INDIRECT_WEIGHT);
        g.addEdge(handles[j], handles[i], EdgeType::Extern, INDIRECT_WEIGHT);
      }
    }
  }

  return g;
}
