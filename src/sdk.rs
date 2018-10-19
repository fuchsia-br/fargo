// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::get_target_triple;
use crate::utils::is_mac;
use crate::X64;
use failure::{bail, Error};
use std::env;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

/// The `TargetOptions` struct bundles together a number of parameters specific to
/// the Fuchsia target that need to be passed through various internal functions. For
/// the moment there is no way to set anything but the `release_os` field, but this
/// will change when fargo starts supporting ARM targets.
#[derive(Debug)]
pub struct TargetOptions<'a, 'b> {
    pub device_name: Option<&'b str>,
    pub config: &'a FuchsiaConfig,
}

impl<'a, 'b> TargetOptions<'a, 'b> {
    /// Constructs a new `TargetOptions`.
    ///
    /// # Examples
    ///
    /// ```
    /// use fargo::{FuchsiaConfig, TargetOptions};
    ///
    /// let target_options =
    ///     TargetOptions::new(&FuchsiaConfig::default(), Some("ivy-donut-grew-stoop"));
    /// ```

    pub fn new(config: &'a FuchsiaConfig, device_name: Option<&'b str>) -> TargetOptions<'a, 'b> {
        TargetOptions {
            device_name: device_name,
            config: config,
        }
    }
}

fn get_path_from_env(env_name: &str, require_dir: bool) -> Result<Option<PathBuf>, Error> {
    if let Ok(file_value) = env::var(env_name) {
        let file_path = PathBuf::from(&file_value);
        if !file_path.exists() {
            bail!(
                "{} is set to '{}' but nothing exists at that path.",
                env_name,
                &file_value
            );
        }
        if require_dir {
            if !file_path.is_dir() {
                bail!(
                    "{} is set to '{}' but that path does not point to a directory.",
                    env_name,
                    &file_value
                );
            }
        }
        return Ok(Some(file_path));
    }
    Ok(None)
}

fn looks_like_fuchsia_dir(path: &PathBuf) -> bool {
    for name in [".config", ".jiri_manifest"].iter() {
        let config_path = path.join(name);
        if !config_path.exists() {
            return false;
        }
    }
    true
}

pub fn fuchsia_dir() -> Result<PathBuf, Error> {
    let fuchsia_dir = if let Some(fuchsia_root) = get_path_from_env("FUCHSIA_ROOT", true)? {
        fuchsia_root
    } else if let Some(fuchsia_dir) = get_path_from_env("FUCHSIA_DIR", true)? {
        fuchsia_dir
    } else {
        let mut path = env::current_dir().unwrap();
        loop {
            if looks_like_fuchsia_dir(&path) {
                return Ok(path);
            }
            path = if let Some(path) = path.parent() {
                path.to_path_buf()
            } else {
                bail!(
                    "FUCHSIA_DIR not set and current directory is not in a Fuchsia tree with a \
                     release-x64 build. You must set the environmental variable FUCHSIA_DIR to \
                     point to a Fuchsia tree with .config and .jiri_manifest files."
                )
            }
        }
    };

    Ok(fuchsia_dir)
}

pub fn target_out_dir(config: &FuchsiaConfig) -> Result<PathBuf, Error> {
    let fuchsia_dir = fuchsia_dir()?;
    Ok(fuchsia_dir.join(&config.fuchsia_build_dir))
}

pub fn cargo_out_dir(options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    let fuchsia_dir = fuchsia_dir()?;
    let target_triple = get_target_triple(options);
    Ok(fuchsia_dir
        .join("garnet")
        .join("target")
        .join(target_triple)
        .join("debug"))
}

pub fn strip_tool_path() -> Result<PathBuf, Error> {
    Ok(toolchain_path()?.join("bin/llvm-objcopy"))
}

pub fn sysroot_path(options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    Ok(target_out_dir(&options.config)?
        .join("sdk")
        .join("exported")
        .join("zircon_sysroot")
        .join("arch")
        .join(&options.config.fuchsia_arch)
        .join("sysroot"))
}

pub fn zircon_build_path(options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    let fuchsia_dir = fuchsia_dir()?;
    let build_name = if options.config.fuchsia_arch == X64 {
        "build-x64"
    } else {
        "build-arm64"
    };
    let zircon_build = fuchsia_dir
        .join("out")
        .join("build-zircon")
        .join(build_name);
    Ok(zircon_build)
}

pub fn shared_libraries_path(options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    let shared_name = if options.config.fuchsia_arch == X64 {
        "x64-shared"
    } else {
        "arm64-shared"
    };
    Ok(target_out_dir(&options.config)?.join(shared_name))
}

fn buildtools_path() -> Result<PathBuf, Error> {
    let platform_name = if is_mac() { "mac-x64" } else { "linux-x64" };
    Ok(fuchsia_dir()?.join("buildtools").join(platform_name))
}

pub fn cargo_path() -> Result<PathBuf, Error> {
    if let Some(cargo_path) = get_path_from_env("FARGO_CARGO", false)? {
        Ok(cargo_path)
    } else {
        Ok(buildtools_path()?.join("rust/bin/cargo"))
    }
}

pub fn rustc_path() -> Result<PathBuf, Error> {
    if let Some(rustc_path) = get_path_from_env("FARGO_RUSTC", false)? {
        Ok(rustc_path)
    } else {
        Ok(buildtools_path()?.join("rust/bin/rustc"))
    }
}

pub fn rustdoc_path() -> Result<PathBuf, Error> {
    if let Some(rustdoc_path) = get_path_from_env("FARGO_RUSTDOC", false)? {
        Ok(rustdoc_path)
    } else {
        Ok(buildtools_path()?.join("rust/bin/rustdoc"))
    }
}

pub fn toolchain_path() -> Result<PathBuf, Error> {
    Ok(buildtools_path()?.join("clang"))
}

pub fn clang_linker_path() -> Result<PathBuf, Error> {
    Ok(toolchain_path()?.join("bin").join("clang"))
}

pub fn clang_c_compiler_path() -> Result<PathBuf, Error> {
    Ok(toolchain_path()?.join("bin").join("clang"))
}

pub fn clang_cpp_compiler_path() -> Result<PathBuf, Error> {
    Ok(toolchain_path()?.join("bin").join("clang++"))
}

pub fn clang_archiver_path() -> Result<PathBuf, Error> {
    Ok(toolchain_path()?.join("bin").join("llvm-ar"))
}

pub fn clang_ranlib_path() -> Result<PathBuf, Error> {
    Ok(toolchain_path()?.join("bin").join("llvm-ranlib"))
}

pub fn fx_path() -> Result<PathBuf, Error> {
    let fuchsia_dir = fuchsia_dir()?;
    Ok(fuchsia_dir.join("scripts/fx"))
}

#[derive(Debug, Default)]
pub struct FuchsiaConfig {
    pub fuchsia_build_dir: String,
    pub fuchsia_variant: String,
    pub fuchsia_arch: String,
    pub zircon_project: String,
}

impl FuchsiaConfig {
    pub fn new() -> Result<FuchsiaConfig, Error> {
        let mut config = FuchsiaConfig {
            fuchsia_build_dir: String::from(""),
            fuchsia_variant: String::from(""),
            fuchsia_arch: String::from(""),
            zircon_project: String::from(""),
        };
        let fuchsia_dir = fuchsia_dir()?;
        let config_path = fuchsia_dir.join(".config");
        let mut config_file = File::open(&config_path)?;
        let mut config_file_contents_str = String::new();
        config_file.read_to_string(&mut config_file_contents_str)?;
        for one_line in config_file_contents_str.lines() {
            let parts: Vec<&str> = one_line.split("=").collect();
            if parts.len() == 2 {
                const QUOTE: char = '\'';
                match parts[0] {
                    "FUCHSIA_BUILD_DIR" => {
                        config.fuchsia_build_dir = String::from(parts[1].trim_matches(QUOTE))
                    }
                    "FUCHSIA_VARIANT" => {
                        config.fuchsia_variant = String::from(parts[1].trim_matches(QUOTE))
                    }
                    "FUCHSIA_ARCH" => {
                        config.fuchsia_arch = String::from(parts[1].trim_matches(QUOTE))
                    }
                    "ZIRCON_PROJECT" => {
                        config.zircon_project = String::from(parts[1].trim_matches(QUOTE))
                    }
                    _ => (),
                }
            }
        }
        Ok(config)
    }

    pub fn is_release(&self) -> bool {
        self.fuchsia_variant != "debug"
    }
}
