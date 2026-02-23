
#include "resolve_facts.hpp"
#include "glaze/glaze.hpp"


using namespace resolve_facts;

template<>
struct glz::meta<EdgeId> {
  using T = EdgeId;
};

// Custom serialization to look like an array
// When using a normal std::pair<int, int> glaze serializes as "{\"first\":second}".
// Use a custom struct to represent the pair ids as overriding the serialization for std::pair
// caused other compilation errors as glaze expected a "write_pair_contents" function of a particular form.
namespace glz {
  template <>
  struct from<JSON, EdgeId>
  {
    template <auto Opts>
    static void op(EdgeId& value, is_context auto&& ctx, auto&& it, auto&& end)
    {

      if (match_invalid_end<'[', Opts>(ctx, it, end)) {
        return;
      }
      parse<JSON>::op<Opts>(value.first, ctx, it, end);
      match<','>(ctx, it);
      parse<JSON>::op<Opts>(value.second, ctx, it, end);
      match<']'>(ctx, it);
    }
  };

  template <>
  struct to<JSON, EdgeId>
  {
    template <auto Opts>
    static void op(const EdgeId& value, is_context auto&& ctx, auto&& b, auto&& ix) noexcept
    {
      dump<'['>(b, ix);
      serialize<JSON>::op<Opts>(value.first, ctx, b, ix);
      dump<','>(b, ix);
      serialize<JSON>::op<Opts>(value.second, ctx, b, ix);
      dump<']'>(b, ix);
    }
  };
}

// Serialize enums as their string names
template <>
struct glz::meta<NodeType> {
  using enum NodeType;
  static constexpr auto value = enumerate(
    Module,
    GlobalVariable,
    Function,
    Argument,
    BasicBlock,
    Instruction
  );
};

template <>
struct glz::meta<Linkage> {
  using enum Linkage;
  static constexpr auto value = enumerate(
    ExternalLinkage,
    Other
  );
};

template <>
struct glz::meta<CallType> {
  using enum CallType;
  static constexpr auto value = enumerate(
    Direct,
    Indirect
  );
};

template <>
struct glz::meta<Node> {
  using T = Node;
  static constexpr auto value = object(
    &T::type,
    &T::name,
    &T::linkage,
    &T::call_type,
    &T::idx,
    &T::function_type,
    &T::address_taken,
    &T::opcode,
    &T::source_file,
    &T::source_loc
  );
};

template <>
struct glz::meta<EdgeKind> {
  using enum EdgeKind;
  static constexpr auto value = enumerate(
    Contains,
    Calls,
    References,
    EntryPoint,
    ControlFlowTo,
    DataFlowTo
  );
};

template <>
struct glz::meta<Edge> {
  using T = Edge;
  static constexpr auto value = object(&T::kinds);
};

template <>
struct glz::meta<ModuleFacts> {
  using T = ModuleFacts;
  static constexpr auto value = object(
      &T::nodes,
      &T::edges
  );
};

template <>
struct glz::meta<ProgramFacts> {
  static constexpr glz::version_t version{1, 0, 0};
};

std::string ModuleFacts::serialize() const {
  std::string json = glz::write_json(*this).value();
  return json;
}

ModuleFacts ModuleFacts::deserialize(std::istream& facts) {

  ModuleFacts f;
  std::string line;
  if (std::getline(facts, line)) {
    auto error = glz::read<glz::opts{.minified=true}>(f, line);
    if (error) {
      std::cerr << glz::format_error(error, line) << std::endl;
    }
  }
  return f;
}

std::string ProgramFacts::serialize() const {
  std::string json = glz::write_json(*this).value();
  return json;
}

ProgramFacts ProgramFacts::deserialize(std::istream& facts) {
  // The stream might be multiple ProgramFacts concatenated together,
  // but separated by a newline. Merge them together.

  ProgramFacts pf;

  std::string line;
  auto i = 0;
  while (std::getline(facts, line)) {
    i += line.size();
    ProgramFacts f;
    auto error = glz::read<glz::opts{.minified=true}>(f, line);
    if (error) {
      std::cerr << glz::format_error(error, line) << std::endl;
    }

    pf.modules.merge(f.modules);

    if (f.modules.size() > 0) {
      for (const auto& [k,_]: f.modules) {
        std::cerr << "Duplicate module id in facts: " << k << std::endl;
      }
    }
  }

  //std::cout << "Found " << pf.modules.size() << " modules with total size " << i << std::endl;

  return pf;
}

const Node& ProgramFacts::getModuleOfNode(const NamespacedNodeId& nodeId) const {
  const auto [mid, _] = nodeId;

  return modules.at(mid).nodes.at(mid);
}

bool ProgramFacts::containsNode(const NamespacedNodeId& nodeId) const {
  const auto [mid, nid] = nodeId;

  return modules.contains(mid) && modules.at(mid).nodes.contains(nid);
}

const Node& ProgramFacts::getNode(const NamespacedNodeId& nodeId) const {
  const auto [mid, nid] = nodeId;

  return modules.at(mid).nodes.at(nid);
}

std::string resolve_facts::to_string(const NamespacedNodeId& id) {
  return "(" + std::to_string(id.first) + "," + std::to_string(id.second) + ")";
}
