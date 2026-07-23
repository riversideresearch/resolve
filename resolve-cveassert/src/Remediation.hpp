/*
 *   Copyright (c) 2025 Riverside Research.
 *   LGPL-3; See LICENSE.txt in the repo root for details.
 */

#pragma once

enum class RemediationStrategies {
  NONE,     /* Skip remediation for this vulnerability */
  RECOVER,  /* Applies setjmp and longjmp in vulnerable function */
  SAT,      /* Uses saturating arithmetic */
  EXIT,     /* Inserts exit function call with exit code */
  WRAP,     /* Uses 2's complement arithmetic */
  CONTINUE, /* Invalid operations are ignored and return 0 */
  WIDEN     /* Widen potentially overflowing intermediate operations */
};

// TODO: Write comments for these options
enum class RemediationOutput { INLINE, PATCH };
