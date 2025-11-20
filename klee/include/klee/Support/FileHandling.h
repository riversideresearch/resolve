//===-- FileHandling.h ------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_FILEHANDLING_H
#define KLEE_FILEHANDLING_H

#include "klee/Support/CompilerWarning.h"
DISABLE_WARNING_PUSH
DISABLE_WARNING_DEPRECATED_DECLARATIONS
#include "llvm/Support/raw_ostream.h"
DISABLE_WARNING_POP

#include <memory>
#include <string>

#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include "json.h"

namespace klee {
std::unique_ptr<llvm::raw_fd_ostream>
klee_open_output_file(const std::string &path, std::string &error);

#ifdef HAVE_ZLIB_H
std::unique_ptr<llvm::raw_ostream>
klee_open_compressed_output_file(const std::string &path, std::string &error);
#endif

  // Definition copied from reach tool config.hpp.
  struct distmap_blacklist {
    std::unordered_map<std::string, size_t> distmap;
    std::unordered_set<std::string> blacklist;
  };
  NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(distmap_blacklist, distmap, blacklist);

  inline std::optional<distmap_blacklist>
  load_distmap_blacklist_from_file(const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f.is_open()) {
      return {};
    }
    nlohmann::json j;
    f >> j;
    return j.template get<distmap_blacklist>();
  }
  
} // namespace klee

#endif /* KLEE_FILEHANDLING_H */
