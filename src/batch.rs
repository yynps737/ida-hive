use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use crate::paths::worker_path;

pub struct OutputPlan {
    reported_path: String,
    target: PathBuf,
}

/// Resolve destinations before starting any workers. Every entry in a collision
/// group fails, regardless of input order or the requested concurrency.
pub fn plan_outputs(paths: &[String], output_dir: Option<&str>) -> Vec<Result<OutputPlan>> {
    let directory = output_dir.map(std::fs::create_dir_all).transpose();
    if let Err(e) = directory {
        return paths.iter().map(|_| Err(anyhow!("Cannot create output directory: {e}"))).collect();
    }

    let plans: Vec<Result<OutputPlan>> = paths.iter().map(|path| {
        let output = match output_dir {
            Some(dir) => {
                let filename = Path::new(path).file_name()
                    .ok_or_else(|| anyhow!("Input has no file name: {path}"))?;
                Path::new(dir).join(format!("{}.i64", filename.to_string_lossy()))
            }
            None => PathBuf::from(format!("{path}.i64")),
        };
        let parent = output.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or_else(|| Path::new("."));
        let parent = std::fs::canonicalize(parent)
            .with_context(|| format!("Cannot resolve output directory for {}", output.display()))?;
        let filename = output.file_name().ok_or_else(|| anyhow!("Output has no file name"))?;
        Ok(OutputPlan { reported_path: output.to_string_lossy().into_owned(), target: parent.join(filename) })
    }).collect();

    let mut counts = HashMap::new();
    for plan in plans.iter().flatten() {
        *counts.entry(plan.target.clone()).or_insert(0_usize) += 1;
    }
    plans.into_iter().map(|plan| {
        let plan = plan?;
        if counts[&plan.target] > 1 {
            return Err(anyhow!("Output collision: multiple inputs target {}. Use separate output directories.", plan.reported_path));
        }
        match std::fs::symlink_metadata(&plan.target) {
            Ok(_) => return Err(anyhow!("Output already exists: {}. Refusing to overwrite it.", plan.reported_path)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {},
            Err(e) => return Err(e).with_context(|| format!("Cannot inspect output {}", plan.reported_path)),
        }
        Ok(plan)
    }).collect()
}

impl OutputPlan {
    pub fn stage(self) -> Result<StagedOutput> {
        let parent = self.target.parent().ok_or_else(|| anyhow!("Output has no parent directory"))?;
        let directory = parent.join(format!(".ida-hive-output-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&directory).context("Cannot create database staging directory")?;
        Ok(StagedOutput { plan: self, file: directory.join("database.i64"), directory })
    }
}

/// Staging is on the destination filesystem. Hard-link publication is atomic and
/// fails if *any* entry already occupies the target (including symlinks and case
/// aliases on insensitive filesystems). This also protects separate server runs.
pub struct StagedOutput {
    plan: OutputPlan,
    file: PathBuf,
    directory: PathBuf,
}

impl StagedOutput {
    pub fn worker_path(&self) -> String {
        worker_path(&self.file)
    }

    pub fn publish(&self) -> Result<String> {
        std::fs::hard_link(&self.file, &self.plan.target).map_err(|e| {
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                anyhow!("Output already exists: {}. Refusing to overwrite it.", self.plan.reported_path)
            } else {
                anyhow!("Cannot publish {} without overwriting (filesystem must support hard links): {e}", self.plan.reported_path)
            }
        })?;
        Ok(self.plan.reported_path.clone())
    }
}

impl Drop for StagedOutput {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}
