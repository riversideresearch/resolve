/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#ifndef RESOLVE_LLVM_LLVMFACTS_HPP
#define RESOLVE_LLVM_LLVMFACTS_HPP

#include "facts_rs.hpp"

#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Module.h"

#include <cassert>
#include <cstdint>
#include <unordered_map>

using NodeId = facts_rs::NodeID;

// Owns a Rust FactsBuf for the duration of the C++ embedding call.
class SerializedFacts {
  facts_rs::FactsBuf *buf = nullptr;

public:
  explicit SerializedFacts(facts_rs::FactsBuf *buf) : buf(buf) {}
  ~SerializedFacts() { facts_rs::facts_buf_free(buf); }

  SerializedFacts(const SerializedFacts &) = delete;
  SerializedFacts &operator=(const SerializedFacts &) = delete;

  llvm::ArrayRef<uint8_t> bytes() const {
    return {facts_rs::facts_buf_data(buf), facts_rs::facts_buf_len(buf)};
  }
};

// LLVM-specific ID mapping and a thin recording facade over the Rust builder.
// This owns no C++ facts model.
class LLVMFacts {
  facts_rs::FactsBuilder *facts = facts_rs::facts_builder_new();

  std::unordered_map<const llvm::Module *, facts_rs::ModuleHandle>
      moduleHandles;
  std::unordered_map<const llvm::Function *, NodeId> functionIDs;
  std::unordered_map<const llvm::BasicBlock *, NodeId> basicBlockIDs;
  std::unordered_map<const llvm::Argument *, NodeId> argumentIDs;
  std::unordered_map<const llvm::Instruction *, NodeId> instructionIDs;
  std::unordered_map<const llvm::GlobalVariable *, NodeId> globalVarIDs;

  facts_rs::ModuleHandle recordNewModule(const size_t size_hint) {
    const auto module = facts_rs::facts_builder_add_module(facts, size_hint);
    assert(module != facts_rs::INVALID_ID);
    return module;
  }

  NodeId recordNode(const facts_rs::ModuleHandle module,
                    const facts_rs::NodeType type) {
    const auto node = facts_rs::facts_builder_add_node(facts, module, type);
    assert(node != facts_rs::INVALID_ID);
    return node;
  }

  static void check(const bool success) {
    assert(success);
    (void)success;
  }

  facts_rs::ModuleHandle addModule(const llvm::Module &M) {
    if (const auto it = moduleHandles.find(&M); it != moduleHandles.end()) {
      return it->second;
    }

    const auto module = recordNewModule(2 * M.getInstructionCount());
    moduleHandles[&M] = module;
    [[maybe_unused]] const auto moduleNode =
        recordNode(module, facts_rs::NodeType::Module);
    assert(moduleNode == 0);
    return module;
  }

  template <typename N> NodeId nodeId(const N &node) { return addNode(node); }

  template <typename N> facts_rs::ModuleHandle moduleId(const N &node) {
    return getModuleId(node);
  }

public:
  LLVMFacts() = default;
  ~LLVMFacts() { facts_rs::facts_builder_free(facts); }

  LLVMFacts(const LLVMFacts &) = delete;
  LLVMFacts &operator=(const LLVMFacts &) = delete;

  NodeId addNode(const llvm::Module &M) {
    addModule(M);
    return 0;
  }

  facts_rs::ModuleHandle getModuleId(const llvm::Module &M) {
    return addModule(M);
  }

  template <typename T> facts_rs::ModuleHandle getModuleId(const T &i) {
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
    return addModule(*module);
  }

  template <typename T> static std::size_t getIndexInParent(const T &item) {
    const auto &parent = *item.getParent();
    return std::distance(parent.begin(), item.getIterator());
  }

  NodeId addNode(const llvm::GlobalVariable &GV) {
    if (globalVarIDs.find(&GV) == globalVarIDs.end()) {
      const auto id =
          recordNode(getModuleId(GV), facts_rs::NodeType::GlobalVariable);
      globalVarIDs[&GV] = id;
      return id;
    }
    return globalVarIDs[&GV];
  }

  NodeId addNode(const llvm::Function &F) {
    if (functionIDs.find(&F) == functionIDs.end()) {
      const auto id = recordNode(getModuleId(F), facts_rs::NodeType::Function);
      functionIDs[&F] = id;
      return id;
    }
    return functionIDs[&F];
  }

  NodeId addNode(const llvm::Argument &A) {
    if (argumentIDs.find(&A) == argumentIDs.end()) {
      const auto id = recordNode(getModuleId(A), facts_rs::NodeType::Argument);
      argumentIDs[&A] = id;
      return id;
    }
    return argumentIDs[&A];
  }

  NodeId addNode(const llvm::BasicBlock &BB) {
    if (basicBlockIDs.find(&BB) == basicBlockIDs.end()) {
      const auto id =
          recordNode(getModuleId(BB), facts_rs::NodeType::BasicBlock);
      basicBlockIDs[&BB] = id;
      return id;
    }
    return basicBlockIDs[&BB];
  }

  NodeId addNode(const llvm::Instruction &I) {
    if (instructionIDs.find(&I) == instructionIDs.end()) {
      const auto id =
          recordNode(getModuleId(I), facts_rs::NodeType::Instruction);
      instructionIDs[&I] = id;
      return id;
    }
    return instructionIDs[&I];
  }

  template <typename S, typename D>
  void addEdge(const S &src, const D &dst, const facts_rs::EdgeKind kind) {
    const auto m1 = getModuleId(src);
    [[maybe_unused]] const auto m2 = getModuleId(dst);
    assert(m1 == m2);
    check(facts_rs::facts_builder_add_edge(facts, m1, addNode(src),
                                           addNode(dst), kind));
  }

  template <typename N> void setIdx(const N &node, const uint32_t value) {
    check(facts_rs::facts_builder_set_node_idx(facts, moduleId(node),
                                               nodeId(node), value));
  }

  template <typename N>
  void setName(const N &node, const llvm::StringRef value) {
    check(facts_rs::facts_builder_set_node_name(
        facts, moduleId(node), nodeId(node),
        reinterpret_cast<const uint8_t *>(value.data()), value.size()));
  }

  template <typename N>
  void setOpcode(const N &node, const llvm::StringRef value) {
    check(facts_rs::facts_builder_set_node_opcode(
        facts, moduleId(node), nodeId(node),
        reinterpret_cast<const uint8_t *>(value.data()), value.size()));
  }

  template <typename N>
  void setLinkage(const N &node, const facts_rs::Linkage value) {
    check(facts_rs::facts_builder_set_node_linkage(facts, moduleId(node),
                                                   nodeId(node), value));
  }

  template <typename N>
  void setCallType(const N &node, const facts_rs::CallType value) {
    check(facts_rs::facts_builder_set_node_call_type(facts, moduleId(node),
                                                     nodeId(node), value));
  }

  template <typename N>
  void setSourceLoc(const N &node, const uint32_t line, const uint32_t col) {
    check(facts_rs::facts_builder_set_node_source_loc(facts, moduleId(node),
                                                      nodeId(node), line, col));
  }

  template <typename N>
  void setSourceFile(const N &node, const llvm::StringRef value) {
    check(facts_rs::facts_builder_set_node_source_file(
        facts, moduleId(node), nodeId(node),
        reinterpret_cast<const uint8_t *>(value.data()), value.size()));
  }

  template <typename N>
  void setFunctionType(const N &node, const llvm::StringRef value) {
    check(facts_rs::facts_builder_set_node_function_type(
        facts, moduleId(node), nodeId(node),
        reinterpret_cast<const uint8_t *>(value.data()), value.size()));
  }

  template <typename N> void setAddressTaken(const N &node) {
    check(facts_rs::facts_builder_set_node_address_taken(facts, moduleId(node),
                                                         nodeId(node), true));
  }

  SerializedFacts serialize() {
    auto *buf = facts_rs::facts_builder_freeze(facts);
    facts = nullptr;
    assert(buf);
    return SerializedFacts(buf);
  }
};

#endif // RESOLVE_LLVM_LLVMFACTS_HPP
