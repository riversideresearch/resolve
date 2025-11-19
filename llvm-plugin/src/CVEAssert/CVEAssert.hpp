/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */


#pragma once

/// Set me true to get more verbose printouts
extern bool CVE_ASSERT_DEBUG;

// Specifies the approach CVE_ASSERT should take
// to instrument sinks.
//
// values:
// SANE_PASS: attempt to continue past a sink by
//            returning a sane default value.
//
// EXIT:      exit the program with the EBOSS
//            exit code (3)
//