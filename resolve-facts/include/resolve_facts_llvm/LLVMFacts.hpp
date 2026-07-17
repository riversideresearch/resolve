/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#ifndef RESOLVE_LLVM_LLVMFACTS_HPP
#define RESOLVE_LLVM_LLVMFACTS_HPP

#include "facts_rs.hpp"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/FileSystem.h"

#include <cassert>
#include <cstdint>
#include <stdexcept>
#include <unordered_map>

using NodeId = uint32_t;

// Owns a Rust FactsBuf for the duration of the C++ embedding call.
class SerializedFacts {
  FactsBuf *buf = nullptr;

public:
  explicit SerializedFacts(FactsBuf *buf) : buf(buf) {}
  ~SerializedFacts() { facts_buf_free(buf); }

  SerializedFacts(const SerializedFacts &) = delete;
  SerializedFacts &operator=(const SerializedFacts &) = delete;

  llvm::ArrayRef<uint8_t> bytes() const {
    return {facts_buf_data(buf), facts_buf_len(buf)};
  }
};

// LLVM-specific ID mapping and a thin recording facade over the opaque Rust
// ProgramFacts context. This owns no C++ facts model.
class LLVMFacts {
  ProgramFacts *facts = new_program_facts();
  NodeId next_node_id = 1;

  std::unordered_map<const llvm::Module *, NodeId> moduleIDs;
  std::unordered_map<const llvm::Function *, NodeId> functionIDs;
  std::unordered_map<const llvm::BasicBlock *, NodeId> basicBlockIDs;
  std::unordered_map<const llvm::Argument *, NodeId> argumentIDs;
  std::unordered_map<const llvm::Instruction *, NodeId> instructionIDs;
  std::unordered_map<const llvm::GlobalVariable *, NodeId> globalVarIDs;

  void recordNewModule(const NodeId id, const size_t size_hint) {
    ::record_new_module(facts, id, size_hint);
  }

  void recordNode(const NodeId module, const NodeId id, const NodeType type) {
    ::record_node(facts, module, id, type);
  }

  template <typename N> NodeId nodeId(const N &node) { return addNode(node); }

  template <typename N> NodeId moduleId(const N &node) {
    return getModuleId(node);
  }

public:
  LLVMFacts() {
    if (!facts) {
      throw std::runtime_error("failed to allocate Rust ProgramFacts context");
    }
  }
  ~LLVMFacts() { free_program_facts(facts); }

  LLVMFacts(const LLVMFacts &) = delete;
  LLVMFacts &operator=(const LLVMFacts &) = delete;

  NodeId addNode(const llvm::Module &M) {
    if (moduleIDs.find(&M) == moduleIDs.end()) {
      llvm::SmallString<128> src_path = llvm::StringRef(M.getSourceFileName());
      llvm::sys::fs::make_absolute(src_path);
      auto id =
          static_cast<NodeId>(std::hash<std::string>{}(std::string(src_path)));

      moduleIDs[&M] = id;
      recordNewModule(id, 2 * M.getInstructionCount());
      recordNode(id, id, NodeType::Module);
      return id;
    }
    return moduleIDs[&M];
  }

  NodeId getModuleId(const llvm::Module &M) { return addNode(M); }

  template <typename T> NodeId getModuleId(const T &i) {
    const llvm::Module *module;

    constexpr bool parent_is_module =
        std::is_same_v<decltype(i.getParent()), const llvm::Module *>;
    constexpr bool is_argument = std::is_same_v<T, llvm::Argument>;
    if constexpr (parent_is_module) {
      module = i.getParent();
    } else if constexpr (is_argument) {
      module = i.getParent()->getParent();
    } else {
      module = i.getModule();
    }

    assert(module);
    return addNode(*module);
  }

  template <typename T> static std::size_t getIndexInParent(const T &item) {
    const auto &parent = *item.getParent();
    return std::distance(parent.begin(), item.getIterator());
  }

  NodeId addNode(const llvm::GlobalVariable &GV) {
    if (globalVarIDs.find(&GV) == globalVarIDs.end()) {
      const auto id = next_node_id++;
      globalVarIDs[&GV] = id;
      recordNode(getModuleId(GV), id, NodeType::GlobalVariable);
      return id;
    }
    return globalVarIDs[&GV];
  }

  NodeId addNode(const llvm::Function &F) {
    if (functionIDs.find(&F) == functionIDs.end()) {
      const auto id = next_node_id++;
      functionIDs[&F] = id;
      recordNode(getModuleId(F), id, NodeType::Function);
      return id;
    }
    return functionIDs[&F];
  }

  NodeId addNode(const llvm::Argument &A) {
    if (argumentIDs.find(&A) == argumentIDs.end()) {
      const auto id = next_node_id++;
      argumentIDs[&A] = id;
      recordNode(getModuleId(A), id, NodeType::Argument);
      return id;
    }
    return argumentIDs[&A];
  }

  NodeId addNode(const llvm::BasicBlock &BB) {
    if (basicBlockIDs.find(&BB) == basicBlockIDs.end()) {
      const auto id = next_node_id++;
      basicBlockIDs[&BB] = id;
      recordNode(getModuleId(BB), id, NodeType::BasicBlock);
      return id;
    }
    return basicBlockIDs[&BB];
  }

  NodeId addNode(const llvm::Instruction &I) {
    if (instructionIDs.find(&I) == instructionIDs.end()) {
      const auto id = next_node_id++;
      instructionIDs[&I] = id;
      recordNode(getModuleId(I), id, NodeType::Instruction);
      return id;
    }
    return instructionIDs[&I];
  }

  template <typename S, typename D>
  void addEdge(const S &src, const D &dst, const EdgeKind kind) {
    const auto m1 = getModuleId(src);
    const auto m2 = getModuleId(dst);
    assert(m1 == m2);
    ::record_edge(facts, m1, addNode(src), addNode(dst), kind);
  }

  template <typename N> void setIdx(const N &node, const uint32_t value) {
    ::record_node_idx(facts, moduleId(node), nodeId(node), value);
  }

  template <typename N>
  void setName(const N &node, const llvm::StringRef value) {
    ::record_node_name(facts, moduleId(node), nodeId(node),
                       reinterpret_cast<const uint8_t *>(value.data()),
                       value.size());
  }

  template <typename N>
  void setOpcode(const N &node, const llvm::StringRef value) {
    ::record_node_opcode(facts, moduleId(node), nodeId(node),
                         reinterpret_cast<const uint8_t *>(value.data()),
                         value.size());
  }

  template <typename N> void setLinkage(const N &node, const Linkage value) {
    ::record_node_linkage(facts, moduleId(node), nodeId(node), value);
  }

  template <typename N> void setCallType(const N &node, const CallType value) {
    ::record_node_call_type(facts, moduleId(node), nodeId(node), value);
  }

  template <typename N>
  void setSourceLoc(const N &node, const uint32_t line, const uint32_t col) {
    ::record_node_source_loc(facts, moduleId(node), nodeId(node), line, col);
  }

  template <typename N>
  void setSourceFile(const N &node, const llvm::StringRef value) {
    ::record_node_source_file(facts, moduleId(node), nodeId(node),
                              reinterpret_cast<const uint8_t *>(value.data()),
                              value.size());
  }

  template <typename N>
  void setFunctionType(const N &node, const llvm::StringRef value) {
    ::record_node_function_type(facts, moduleId(node), nodeId(node),
                                reinterpret_cast<const uint8_t *>(value.data()),
                                value.size());
  }

  template <typename N> void setAddressTaken(const N &node) {
    ::record_node_address_taken(facts, moduleId(node), nodeId(node), true);
  }

  SerializedFacts serialize() const {
    auto *buf = facts_serialize(facts);
    if (!buf) {
      throw std::runtime_error("failed to serialize Rust ProgramFacts context");
    }
    return SerializedFacts(buf);
  }
};

#endif // RESOLVE_LLVM_LLVMFACTS_HPP
