#include <regex>

#include "facts.hpp"
#include "graph.hpp"
#include "util.hpp"

using namespace facts;
using namespace graph;
using namespace std;
using symbol = dlsym::loaded_symbol;
namespace fs = filesystem;

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

double graph::path_weight(const vector<edge>& path) {
  double w = 0.0;
  for (const auto& e : path) {
    w += e.weight;
  }
  return w;
}

bool graph::wf(const E& g) {
  for (const auto& es : g) {
    unordered_set<size_t> seen;
    for (const auto& e : es) {
      if (!seen.insert(e.node).second) {
	return false;
      }
    }
  }
  return true;
}

size_t handle_map::getHandle(const string& id) {
  if (id2handle.contains(id)) {
    return id2handle.at(id);
  } else {
    const size_t handle = handle2id.size();
    handle2id.push_back(id);
    id2handle.emplace(id, handle);
    return handle;
  }
}

size_t handle_map::getHandleConst(const string& id) const {
  return AT(id2handle, id);
}

optional<size_t> handle_map::getHandleOpt(const string& id) const {
  if (id2handle.contains(id)) {
    return id2handle.at(id);
  }
  else {
    return nullopt;
  }
}

std::string handle_map::getId(size_t handle) const {
  return AT(this->handle2id, handle);
}

// Add edge [l->r] with default weight and type.
void T::addEdge(size_t l, size_t r, EdgeType ety) {
  this->addEdge(l, r, ety, 1.0);
}

// Add edge [l->r]. Does nothing if [r] already exists in the
// adjacency list of [l].
void T::addEdge(size_t l, size_t r, EdgeType ety, double weight) {
  if (max(l, r) >= this->edges.size()) {
    this->edges.resize(max(l, r) + 1);
  }
  for (const auto& e : this->edges[l]) {
    if (e.node == r) {
      return;
    }
  }
  this->edges[l].push_back({ r, weight, ety });
}

// Determine if symbol 'sym' matches node id 'node_id'.
bool symbol_id_match(const dlsym::loaded_symbol& sym, const string& node_id) {
  const auto name_opt = util::name_of_id(node_id);
  if (!name_opt.has_value()) {
    return false;
  }
  const auto name = name_opt.value();
  if (name.size() && name[0] == 'f') {
    return string_view(name.data() + 1) == string_view(sym.symbol);
  }  
  return false;
}

// Transform set of loaded symbols into set of matching node ids. If
// [loaded_syms] doesn't have a value, we do nothing here and the
// graph constructions don't do any filtering of external functions
// for indirect calls.
vector<string>
map_loaded_symbols_to_ids(const database& db,
			  const optional<vector<symbol>>& loaded_syms) {
  if (!loaded_syms.has_value()) {
    return {};
  }
  const auto syms = loaded_syms.value();
  vector<string> loaded_ids;
  for (const auto& [id, _] : db.node_type) {
    for (const auto& sym : syms) {
      if (symbol_id_match(sym, id)) {
	loaded_ids.push_back(id);
	break;
      }
    }
  }
  return loaded_ids;
}

// loaded_syms is the set of symbols loaded with dlsym.
pair<handle_map, T>
graph::build_simple_graph(const database& db,
			  bool dynlink,
			  const optional<vector<symbol>>& loaded_syms) {
  const auto loaded_ids = map_loaded_symbols_to_ids(db, loaded_syms);

  handle_map hm;
  T g;

  // Contains
  for (const auto& [x, ys] : db.contains) {
    for (const auto& y : ys) {
      g.addEdge(hm.getHandle(y), hm.getHandle(x), EdgeType::Contains);
    }
  }

  // Direct calls
  for (const auto& [instr, fn] : db.calls) {
    g.addEdge(hm.getHandle(fn), hm.getHandle(instr), EdgeType::DirectCall);
  }

  // Indirect calls
  for (const auto& [instr, call_type] : db.call_type) {
    if (call_type == CallType::Indirect) {
      for (const auto& fn : db.address_taken) {
	if (AT(db.fun_sig, instr) == AT(db.fun_sig, fn)) {
	  g.addEdge(hm.getHandle(fn), hm.getHandle(instr),
		    EdgeType::IndirectCall, INDIRECT_WEIGHT);
	}
      }

      // If dynlink flag is set, also take functions with external
      // linkage as possible call targets.
      if (dynlink) {
	for (const auto& [id, linkage] : db.linkage) {
	  if (linkage == Linkage::ExternalLinkage &&
	      AT(db.node_type, id) == NodeType::Function &&
	      AT(db.fun_sig, instr) == AT(db.fun_sig, id) &&
	      (!loaded_syms.has_value() ||
	       find(loaded_ids.begin(), loaded_ids.end(), id) != loaded_ids.end())) {
	    g.addEdge(hm.getHandle(id), hm.getHandle(instr),
		      EdgeType::ExternIndirectCall, INDIRECT_WEIGHT);
	  }
	}
      }
    }
  }

  // External linkage
  unordered_map<string, vector<size_t>> name2handles;
  for (const auto& [id, linkage] : db.linkage) {
    if (linkage == Linkage::ExternalLinkage) {
      name2handles[AT(db.name, id)].push_back(hm.getHandle(id));
    }
  }
  for (const auto& [_, handles] : name2handles) {
    for (size_t i = 0; i < handles.size(); i++) {
      for (size_t j = i+1; j < handles.size(); j++) {
	g.addEdge(handles[i], handles[j], EdgeType::Extern, INDIRECT_WEIGHT);
	g.addEdge(handles[j], handles[i], EdgeType::Extern, INDIRECT_WEIGHT);
      }
    }
  }

  return { hm, g };
}

pair<handle_map, T>
graph::build_call_graph(const database& db,
			bool dynlink,
			const optional<vector<symbol>>& loaded_syms) {
  const auto loaded_ids = map_loaded_symbols_to_ids(db, loaded_syms);

  handle_map hm;
  T g;

  for (const auto& [f, bbs] : db.contains) {
    if (AT(db.node_type, f) != NodeType::Function) {
      continue;
    }
    for (const auto& bb : bbs) {
      if (AT(db.node_type, bb) != NodeType::BasicBlock) {
        continue;
      }
      for (const auto& instr : AT(db.contains, bb)) {
	if (!db.call_type.contains(instr)) {
	  continue;
	}
	const auto& call_ty = AT(db.call_type, instr);
	// If direct, add one edge.
	if (call_ty == CallType::Direct) {
	  g.addEdge(hm.getHandle(AT(db.calls, instr)), hm.getHandle(f),
		    EdgeType::DirectCall);
	  continue;
	}
	// Else indirect. Add edges for all compatible address-taken functions.
	for (const auto& fn : db.address_taken) {
	  if (AT(db.fun_sig, fn) == AT(db.fun_sig, instr)) {
	    g.addEdge(hm.getHandle(fn), hm.getHandle(f),
		      EdgeType::IndirectCall, INDIRECT_WEIGHT);
	  }
	}
	// If dynlink flag is set, also consider functions with
	// external linkage to be possible call targets.
	if (!dynlink) {
	  continue;
	}
	for (const auto& [id, linkage] : db.linkage) {
	  if (linkage == Linkage::ExternalLinkage &&
	      AT(db.node_type, id) == NodeType::Function &&
	      AT(db.fun_sig, instr) == AT(db.fun_sig, id) &&
	      (!loaded_syms.has_value() ||
	       find(loaded_ids.begin(), loaded_ids.end(), id) != loaded_ids.end())) {
	    g.addEdge(hm.getHandle(id), hm.getHandle(f),
		      EdgeType::ExternIndirectCall, INDIRECT_WEIGHT);
	  }
	}
      }
    }
  }

  // External linkage
  unordered_map<string, vector<size_t>> name2handles;
  for (const auto& [id, linkage] : db.linkage) {
    if (linkage == Linkage::ExternalLinkage) {
      name2handles[AT(db.name, id)].push_back(hm.getHandle(id));
    }
  }
  for (const auto& [_, handles] : name2handles) {
    for (size_t i = 0; i < handles.size(); i++) {
      for (size_t j = i+1; j < handles.size(); j++) {
	g.addEdge(handles[i], handles[j], EdgeType::Extern, INDIRECT_WEIGHT);
	g.addEdge(handles[j], handles[i], EdgeType::Extern, INDIRECT_WEIGHT);
      }
    }
  }

  return { hm, g };
}

// Call edges aren't directly from calling BB to entry BB of called
// function. Instead they go caller BB -> callee function -> entry
// point BB, with the extra function node in between. I think this is
// fine, maybe even desirable because it makes the path search
// algorithm consider function calls to be a bit more expensive (total
// weight 2, or 3 for externals because of ExternalLinkage edges) than
// BB successor edges. Including the function nodes also makes it
// possible to specify functions as targets for directed KLEE.
pair<handle_map, T>
graph::build_cfg(const database& db,
		 bool dynlink,
		 const optional<vector<symbol>>& loaded_syms) {  
  const auto loaded_ids = map_loaded_symbols_to_ids(db, loaded_syms);

  handle_map hm;
  T g;

  // function -> entry BB
  for (const auto& [fn, fn_ty] : db.node_type) {
    if (fn_ty != NodeType::Function || !db.contains.contains(fn)) {
      continue;
    }
    for (const auto& bb : db.contains.at(fn)) {
      const static regex pattern(".*:f.*:bb0");
      if (regex_match(bb, pattern)) {
	g.addEdge(hm.getHandle(bb), hm.getHandle(fn), EdgeType::Contains);
	goto next;
      }
    }
    throw runtime_error("no entry point found for function " + fn);
  next:;
  }

  // BB control flow
  for (const auto& [bb, succs] : db.control_flow) {
    for (const auto& succ : succs) {
      g.addEdge(hm.getHandle(succ), hm.getHandle(bb), EdgeType::Succ);
    }
  }

  // Calls
  for (const auto& [bb, instrs] : db.contains) {
    if (AT(db.node_type, bb) != NodeType::BasicBlock) {
      continue;
    }
    for (const auto& instr : instrs) {
      if (!db.call_type.contains(instr)) {
	continue;
      }
      const auto& call_ty = AT(db.call_type, instr);
      // If direct, add one edge.
      if (call_ty == CallType::Direct) {
	g.addEdge(hm.getHandle(AT(db.calls, instr)),
		  hm.getHandle(bb), EdgeType::DirectCall);
	continue;
      }
      // Else indirect. Add edges for all compatible address-taken functions.
      for (const auto& fn : db.address_taken) {
	if (AT(db.fun_sig, fn) == AT(db.fun_sig, instr)) {
	  g.addEdge(hm.getHandle(fn), hm.getHandle(bb),
		    EdgeType::IndirectCall, INDIRECT_WEIGHT);
	}
      }
      // If dynlink flag is set, also take functions with external
      // linkage as possible call targets.
      if (dynlink) {
	for (const auto& [id, linkage] : db.linkage) {
	  if (linkage == Linkage::ExternalLinkage &&
	      AT(db.node_type, id) == NodeType::Function &&
	      AT(db.fun_sig, instr) == AT(db.fun_sig, id) &&
	      (!loaded_syms.has_value() ||
	       find(loaded_ids.begin(), loaded_ids.end(), id) != loaded_ids.end())) {
	    g.addEdge(hm.getHandle(id), hm.getHandle(bb),
		      EdgeType::ExternIndirectCall, INDIRECT_WEIGHT);
	  }
	}
      }
    }
  }

  // External linkage
  unordered_map<string, vector<size_t>> name2handles;
  for (const auto& [id, linkage] : db.linkage) {
    if (linkage == Linkage::ExternalLinkage) {
      name2handles[AT(db.name, id)].push_back(hm.getHandle(id));
    }
  }
  for (const auto& [_, handles] : name2handles) {
    for (size_t i = 0; i < handles.size(); i++) {
      for (size_t j = i+1; j < handles.size(); j++) {
	g.addEdge(handles[i], handles[j], EdgeType::Extern, INDIRECT_WEIGHT);
	g.addEdge(handles[j], handles[i], EdgeType::Extern, INDIRECT_WEIGHT);
      }
    }
  }

  return { hm, g };
}

// Same thing here as [build_cfg] (see above) wrt. Call edges going
// through intermediate function nodes.
pair<handle_map, T>
graph::build_instr_cfg(const database& db,
		       bool dynlink,
		       const optional<vector<symbol>>& loaded_syms) {
  const auto loaded_ids = map_loaded_symbols_to_ids(db, loaded_syms);

  handle_map hm;
  T g;

  // function -> entry instruction
  for (const auto& [fn, fn_ty] : db.node_type) {
    if (fn_ty != NodeType::Function || !db.contains.contains(fn)) {
      continue;
    }
    for (const auto& bb : db.contains.at(fn)) {
      const static regex pattern(".*:f.*:bb0");
      if (regex_match(bb, pattern)) {
	const auto& instr = db.contains.at(bb).front();
	g.addEdge(hm.getHandle(instr), hm.getHandle(fn), EdgeType::Contains);
	goto next;
      }
    }
    throw runtime_error("no entry point found for function " + fn);
  next:;
  }

  // Intra-BB control flow (linear)
  for (const auto& [bb, bb_ty] : db.node_type) {
    if (bb_ty != NodeType::BasicBlock) {
      continue;
    }
    const auto& instrs = AT(db.contains, bb);
    for (size_t i = 0; i < instrs.size()-1; i++) {
      g.addEdge(hm.getHandle(instrs[i+1]), hm.getHandle(instrs[i]), EdgeType::Succ);
    }
  }

  // Inter-BB control flow
  for (const auto& [bb, succs] : db.control_flow) {
    for (const auto& succ : succs) {
      const auto& src_instr = db.contains.at(bb).back();
      const auto& dst_instr = db.contains.at(succ).front();
      g.addEdge(hm.getHandle(dst_instr), hm.getHandle(src_instr), EdgeType::Succ);
    }
  }

  // Calls
  for (const auto& [bb, instrs] : db.contains) {
    if (AT(db.node_type, bb) != NodeType::BasicBlock) {
      continue;
    }
    for (const auto& instr : instrs) {
      if (!db.call_type.contains(instr)) {
	continue;
      }
      const auto& call_ty = AT(db.call_type, instr);
      // If direct, add one edge.
      if (call_ty == CallType::Direct) {
	g.addEdge(hm.getHandle(AT(db.calls, instr)),
		  hm.getHandle(instr), EdgeType::DirectCall);
	continue;
      }
      // Else indirect. Add edges for all compatible address-taken functions.
      for (const auto& fn : db.address_taken) {
	if (AT(db.fun_sig, fn) == AT(db.fun_sig, instr)) {
	  g.addEdge(hm.getHandle(fn), hm.getHandle(instr),
		    EdgeType::IndirectCall, INDIRECT_WEIGHT);
	}
      }
      // If dynlink flag is set, also take functions with external
      // linkage as possible call targets.
      if (dynlink) {
	for (const auto& [id, linkage] : db.linkage) {
	  if (linkage == Linkage::ExternalLinkage &&
	      AT(db.node_type, id) == NodeType::Function &&
	      AT(db.fun_sig, instr) == AT(db.fun_sig, id) &&
	      (!loaded_syms.has_value() ||
	       find(loaded_ids.begin(), loaded_ids.end(), id) != loaded_ids.end())) {
	    g.addEdge(hm.getHandle(id), hm.getHandle(instr),
		      EdgeType::ExternIndirectCall, INDIRECT_WEIGHT);
	  }
	}
      }
    }
  }

  // External linkage
  unordered_map<string, vector<size_t>> name2handles;
  for (const auto& [id, linkage] : db.linkage) {
    if (linkage == Linkage::ExternalLinkage) {
      name2handles[AT(db.name, id)].push_back(hm.getHandle(id));
    }
  }
  for (const auto& [_, handles] : name2handles) {
    for (size_t i = 0; i < handles.size(); i++) {
      for (size_t j = i+1; j < handles.size(); j++) {
	g.addEdge(handles[i], handles[j], EdgeType::Extern, INDIRECT_WEIGHT);
	g.addEdge(handles[j], handles[i], EdgeType::Extern, INDIRECT_WEIGHT);
      }
    }
  }

  return { hm, g };
}
