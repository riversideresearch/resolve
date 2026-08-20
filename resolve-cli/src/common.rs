// Copyright (c) 2025-2026 Riverside Research.
// LGPL-3; See LICENSE.txt in the repo root for details.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

pub fn require_file(path: &Path, step: &str) -> Result<()> {
    if !path.is_file() {
        bail!("{} did not produce required file: {}", step, path.display());
    }
    Ok(())
}

pub fn prepare_output_path(output_path: &Path, overwrite: bool) -> Result<()> {
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create parent directory: {}", parent.display()))?;
    }
    
    if output_path.exists() {
        if !overwrite {
            bail!(
                "output_path already exists: {}. Use --overwrite to replace it.",
                output_path.display()
            );
        }
        if output_path.is_dir() {
            fs::remove_dir_all(output_path)?;
        } else {
            fs::remove_file(output_path)?;
        }
    }
    Ok(())
}
