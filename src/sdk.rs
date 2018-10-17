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
    pub release_os: bool,
    pub target_cpu: &'a str,
    pub target_cpu_linker: &'a str,
    pub device_name: Option<&'b str>,
}

impl<'a, 'b> TargetOptions<'a, 'b> {
    /// Constructs a new `TargetOptions`.
    ///
    /// # Examples
    ///
    /// ```
    /// use fargo::TargetOptions;
    ///
    /// let target_options = TargetOptions::new(true, "x64", Some("ivy-donut-grew-stoop"));
    /// ```

    pub fn new(
        release_os: bool, target_cpu: &'a str, device_name: Option<&'b str>,
    ) -> TargetOptions<'a, 'b> {
        TargetOptions {
            release_os: release_os,
            target_cpu: target_cpu,
            target_cpu_linker: target_cpu,
            device_name: device_name,
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

pub fn fuchsia_dir(options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    let fuchsia_dir = if let Some(fuchsia_root) = get_path_from_env("FUCHSIA_ROOT", true)? {
        fuchsia_root
    } else if let Some(fuchsia_dir) = get_path_from_env("FUCHSIA_DIR", true)? {
        fuchsia_dir
    } else {
        let mut path = env::current_dir().unwrap();
        loop {
            if possible_target_out_dir(&path, options).is_ok() {
                return Ok(path);
            }
            path = if let Some(path) = path.parent() {
                path.to_path_buf()
            } else {
                bail!(
                    "FUCHSIA_DIR not set and current directory is not in a Fuchsia tree with a \
                     release-x64 build. You must set the environmental variable FUCHSIA_DIR to \
                     point to a Fuchsia tree with a release-x64 build."
                )
            }
        }
    };

    Ok(fuchsia_dir)
}

pub fn possible_target_out_dir(
    fuchsia_dir: &PathBuf, options: &TargetOptions<'_, '_>,
) -> Result<PathBuf, Error> {
    let out_dir_name_prefix = if options.release_os {
        "release"
    } else {
        "debug"
    };
    let out_dir_name = format!("{}-{}", out_dir_name_prefix, options.target_cpu);
    let target_out_dir = fuchsia_dir.join("out").join(out_dir_name);
    if !target_out_dir.exists() {
        bail!("no target out directory found at  {:?}", target_out_dir);
    }
    Ok(target_out_dir)
}

pub fn target_out_dir(options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    let fuchsia_dir = fuchsia_dir(options)?;
    possible_target_out_dir(&fuchsia_dir, options)
}

pub fn cargo_out_dir(options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    let fuchsia_dir = fuchsia_dir(options)?;
    let target_triple = get_target_triple(options);
    Ok(fuchsia_dir
        .join("garnet")
        .join("target")
        .join(target_triple)
        .join("debug"))
}

pub fn strip_tool_path(target_options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    Ok(toolchain_path(target_options)?.join("bin/llvm-objcopy"))
}

pub fn sysroot_path(options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    Ok(target_out_dir(&options)?
        .join("sdk")
        .join("exported")
        .join("zircon_sysroot")
        .join("arch")
        .join(options.target_cpu)
        .join("sysroot"))
}

pub fn zircon_build_path(options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    let fuchsia_dir = fuchsia_dir(options)?;
    let build_name = if options.target_cpu == X64 {
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
    let shared_name = if options.target_cpu == X64 {
        "x64-shared"
    } else {
        "arm64-shared"
    };
    Ok(target_out_dir(&options)?.join(shared_name))
}

fn buildtools_path(target_options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    let platform_name = if is_mac() { "mac-x64" } else { "linux-x64" };
    Ok(fuchsia_dir(target_options)?
        .join("buildtools")
        .join(platform_name))
}

pub fn cargo_path(target_options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    if let Some(cargo_path) = get_path_from_env("FARGO_CARGO", false)? {
        Ok(cargo_path)
    } else {
        Ok(buildtools_path(target_options)?.join("rust/bin/cargo"))
    }
}

pub fn rustc_path(target_options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    if let Some(rustc_path) = get_path_from_env("FARGO_RUSTC", false)? {
        Ok(rustc_path)
    } else {
        Ok(buildtools_path(target_options)?.join("rust/bin/rustc"))
    }
}

pub fn rustdoc_path(target_options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    if let Some(rustdoc_path) = get_path_from_env("FARGO_RUSTDOC", false)? {
        Ok(rustdoc_path)
    } else {
        Ok(buildtools_path(target_options)?.join("rust/bin/rustdoc"))
    }
}

pub fn toolchain_path(target_options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    Ok(buildtools_path(target_options)?.join("clang"))
}

pub fn clang_linker_path(target_options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    Ok(toolchain_path(target_options)?.join("bin").join("clang"))
}

pub fn clang_c_compiler_path(target_options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    Ok(toolchain_path(target_options)?.join("bin").join("clang"))
}

pub fn clang_cpp_compiler_path(target_options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    Ok(toolchain_path(target_options)?.join("bin").join("clang++"))
}

pub fn clang_archiver_path(target_options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    Ok(toolchain_path(target_options)?.join("bin").join("llvm-ar"))
}

pub fn clang_ranlib_path(target_options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    Ok(toolchain_path(target_options)?
        .join("bin")
        .join("llvm-ranlib"))
}

pub fn fx_path(target_options: &TargetOptions<'_, '_>) -> Result<PathBuf, Error> {
    let fuchsia_dir = fuchsia_dir(target_options)?;
    Ok(fuchsia_dir.join("scripts/fx"))
}

#[derive(Debug)]
pub struct FuchsiaConfig {
    pub fuchsia_build_dir: String,
    pub fuchsia_variant: String,
    pub fuchsia_arch: String,
    pub zircon_project: String,
}

impl FuchsiaConfig {
    pub fn new(target_options: &TargetOptions<'_, '_>) -> Result<FuchsiaConfig, Error> {
        let mut config = FuchsiaConfig {
            fuchsia_build_dir: String::from(""),
            fuchsia_variant: String::from(""),
            fuchsia_arch: String::from(""),
            zircon_project: String::from(""),
        };
        let fuchsia_dir = fuchsia_dir(target_options)?;
        let config_path = fuchsia_dir.join(".config");
        let mut config_file = File::open(&config_path)?;
        let mut config_file_contents_str = String::new();
        config_file.read_to_string(&mut config_file_contents_str)?;
        for one_line in config_file_contents_str.lines() {
            let parts: Vec<&str> = one_line.split("=").collect();
            if parts.len() == 2 {
                match parts[0] {
                    "FUCHSIA_BUILD_DIR" => {
                        config.fuchsia_build_dir = String::from(parts[1].trim_matches('"'))
                    }
                    "FUCHSIA_VARIANT" => {
                        config.fuchsia_variant = String::from(parts[1].trim_matches('"'))
                    }
                    "FUCHSIA_ARCH" => {
                        config.fuchsia_arch = String::from(parts[1].trim_matches('"'))
                    }
                    "ZIRCON_PROJECT" => {
                        config.zircon_project = String::from(parts[1].trim_matches('"'))
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
