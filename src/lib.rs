// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! While fargo is mainly intended to be a command line tool, this library
//! exposes one function, `run_cargo`, that could be integrated directly into
//! Rust programs that want to cross compile cargo crates on Fuchsia.

#![recursion_limit = "1024"]

extern crate clap;
#[macro_use]
extern crate failure;
extern crate toml;
extern crate uname;

mod cross;
mod device;
mod sdk;
mod utils;

use clap::{App, AppSettings, Arg, SubCommand};
use cross::{pkg_config_path, run_configure, run_pkg_config};
use device::{enable_networking, netaddr, netls, scp_to_device, ssh, start_emulator, stop_emulator,
             StartEmulatorOptions};
use failure::{err_msg, Error, ResultExt};
pub use sdk::TargetOptions;
use sdk::{cargo_out_dir, cargo_path, clang_archiver_path, clang_c_compiler_path,
          clang_cpp_compiler_path, clang_linker_path, clang_ranlib_path, rustc_path, rustdoc_path,
          shared_libraries_path, sysroot_path, zircon_build_path, FuchsiaConfig};
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use utils::strip_binary;

fn copy_to_target(
    source_path: &PathBuf, verbose: bool, target_options: &TargetOptions,
) -> Result<String, Error> {
    let netaddr = netaddr(verbose, target_options)?;
    if verbose {
        println!("netaddr {}", netaddr);
    }
    let destination_path = format!(
        "/tmp/{}",
        source_path.file_name().unwrap().to_string_lossy()
    );
    println!(
        "copying {} to {}",
        source_path.to_string_lossy(),
        destination_path
    );
    scp_to_device(
        verbose,
        target_options,
        &netaddr,
        &source_path,
        &destination_path,
    )?;
    Ok(destination_path)
}

fn run_program_on_target(
    filename: &str, verbose: bool, target_options: &TargetOptions, set_root_view: bool,
    params: &[&str], test_args: Option<&str>,
) -> Result<(), Error> {
    let source_path = PathBuf::from(&filename);
    let stripped_source_path = strip_binary(&source_path, target_options)?;
    let destination_path = copy_to_target(&stripped_source_path, verbose, target_options)?;
    let mut command_string = (if set_root_view { "set_root_view " } else { "" }).to_string();
    command_string.push_str(&destination_path);
    for param in params {
        command_string.push(' ');
        command_string.push_str(param);
    }

    if let Some(test_args_str) = test_args {
        command_string.push_str(" -- ");
        command_string.push_str(test_args_str);
    }

    if verbose {
        println!("running {}", command_string);
    }

    if set_root_view {
        ssh(verbose, target_options, "killall scene_manager").unwrap_or(());
        ssh(verbose, target_options, "killall set_root_view").unwrap_or(());
    }

    ssh(verbose, target_options, &command_string)?;
    Ok(())
}

extern crate notify;

use notify::{RecommendedWatcher, RecursiveMode, Watcher};
use std::sync::mpsc::channel;
use std::time::Duration;

fn autotest(
    run_cargo_options: RunCargoOptions, target_options: &TargetOptions,
) -> Result<(), Error> {
    let (tx, rx) = channel();
    let mut watcher: RecommendedWatcher =
        Watcher::new(tx, Duration::from_secs(1)).context("autotest: watcher creation failed")?;

    let cwd = std::fs::canonicalize(std::env::current_dir()?)
        .context("autotest: canonicalize working directory")?;
    let tgt = cwd.join("target");
    let git = cwd.join(".git");

    watcher
        .watch(&cwd, RecursiveMode::Recursive)
        .context("autotest: watch failed")?;

    println!("autotest: started");
    loop {
        let event = rx.recv().context("autotest: watch recv failed")?;
        match event {
            notify::DebouncedEvent::Create(path)
            | notify::DebouncedEvent::Write(path)
            | notify::DebouncedEvent::Chmod(path)
            | notify::DebouncedEvent::Remove(path)
            | notify::DebouncedEvent::Rename(path, _) => {
                // TODO(raggi): provide a fuller ignore flag/pattern match solution here.
                if !path.starts_with(&tgt) && !path.starts_with(&git) {
                    println!("autotest: running tests because {:?}", path);
                    run_tests(run_cargo_options, false, target_options, "", &[], None).ok();
                }
            }
            _ => {}
        }
    }
}

fn build_tests(
    run_cargo_options: RunCargoOptions, target_options: &TargetOptions, test_target: &str,
) -> Result<bool, Error> {
    run_tests(
        run_cargo_options,
        true,
        target_options,
        test_target,
        &[],
        None,
    )?;
    Ok(true)
}

fn run_tests(
    run_cargo_options: RunCargoOptions, no_run: bool, target_options: &TargetOptions,
    test_target: &str, params: &[&str], target_params: Option<&str>,
) -> Result<(), Error> {
    let mut args = vec![];

    if !test_target.is_empty() {
        args.push("--test");
        args.push(test_target);
    }

    if no_run {
        args.push("--no-run");
    }

    for param in params {
        args.push(param);
    }

    if target_params.is_some() {
        let formatted_target_params = format!("--args={}", target_params.unwrap());
        run_cargo(
            run_cargo_options,
            "test",
            &args,
            target_options,
            None,
            Some(&formatted_target_params),
        )?;
    } else {
        run_cargo(run_cargo_options, "test", &args, target_options, None, None)?;
    }

    Ok(())
}

fn build_binary(
    run_cargo_options: RunCargoOptions, target_options: &TargetOptions, params: &[&str],
) -> Result<(), Error> {
    run_cargo(
        run_cargo_options,
        "build",
        params,
        target_options,
        None,
        None,
    )
}

fn check_binary(
    run_cargo_options: RunCargoOptions, target_options: &TargetOptions, params: &[&str],
) -> Result<(), Error> {
    run_cargo(
        run_cargo_options,
        "check",
        params,
        target_options,
        None,
        None,
    )
}

fn run_binary(
    run_cargo_options: RunCargoOptions, target_options: &TargetOptions, params: &[&str],
) -> Result<(), Error> {
    run_cargo(run_cargo_options, "run", params, target_options, None, None)?;
    Ok(())
}

fn build_doc(
    run_cargo_options: RunCargoOptions, target_options: &TargetOptions, no_deps: bool, open: bool,
) -> Result<(), Error> {
    let mut args = vec![];
    if no_deps {
        args.push("--no-deps");
    }
    if open {
        args.push("--open");
    }
    run_cargo(run_cargo_options, DOC, &args, &target_options, None, None)
}

fn load_driver(
    run_cargo_options: RunCargoOptions, target_options: &TargetOptions,
) -> Result<(), Error> {
    let args = vec![];
    run_cargo(
        run_cargo_options,
        "build",
        &args,
        target_options,
        None,
        None,
    )?;
    let cwd = std::env::current_dir()?;
    let package = cwd
        .file_name()
        .ok_or(err_msg("No current directory"))?
        .to_str()
        .ok_or(err_msg("Invalid current directory"))?;
    let filename = cargo_out_dir(target_options)?.join(format!("lib{}.so", package));
    let destination_path = copy_to_target(&filename, run_cargo_options.verbose, target_options)?;
    let command_string = format!("dm add-driver:{}", destination_path);
    if run_cargo_options.verbose {
        println!("running {}", command_string);
    }
    ssh(run_cargo_options.verbose, target_options, &command_string)?;
    Ok(())
}

#[derive(Debug, Copy, Clone)]
pub struct RunCargoOptions {
    pub verbose: bool,
    pub release: bool,
    pub set_root_view: bool,
    pub disable_cross: bool,
}

impl RunCargoOptions {
    pub fn new(verbose: bool, release: bool) -> RunCargoOptions {
        RunCargoOptions {
            verbose,
            release,
            set_root_view: false,
            disable_cross: false,
        }
    }

    pub fn disable_cross(&self, disable_cross: bool) -> RunCargoOptions {
        RunCargoOptions {
            verbose: self.verbose,
            release: self.release,
            set_root_view: self.set_root_view,
            disable_cross,
        }
    }

    pub fn release(&self, release: bool) -> RunCargoOptions {
        RunCargoOptions {
            verbose: self.verbose,
            release: release,
            set_root_view: self.set_root_view,
            disable_cross: self.disable_cross,
        }
    }

    pub fn set_root_view(&self, set_root_view: bool) -> RunCargoOptions {
        RunCargoOptions {
            verbose: self.verbose,
            release: self.release,
            set_root_view: set_root_view,
            disable_cross: self.disable_cross,
        }
    }
}

/// Runs the cargo tool configured to target Fuchsia. When used as a library,
/// the runner options must contain the path to fargo or some other program
/// that implements the `run-on-target` subcommand in a way compatible with
/// fargo.
///
/// # Examples
///
/// ```
/// use fargo::{run_cargo, RunCargoOptions, TargetOptions};
///
/// let target_options = TargetOptions::new(true, "x64", None);
/// run_cargo(
///     RunCargoOptions {
///         verbose: false,
///         release: true,
///         set_root_view: false,
///         disable_cross: false,
///     },
///     "help",
///     &[],
///     &target_options,
///     None,
///     None,
/// );
/// ```
pub fn run_cargo(
    options: RunCargoOptions, subcommand: &str, args: &[&str], target_options: &TargetOptions,
    runner: Option<PathBuf>, additional_target_args: Option<&str>,
) -> Result<(), Error> {
    if options.verbose {
        println!("target_options = {:?}", target_options);
    }

    let set_root_view_arg = format!("--{}", SET_ROOT_VIEW);

    let triple_cpu = if target_options.target_cpu == X64 {
        "x86_64"
    } else {
        "aarch64"
    };
    let target_triple = format!("{}-unknown-fuchsia", triple_cpu);
    let mut target_args = vec!["--target", &target_triple];

    if options.release {
        target_args.push("--release");
    }

    if options.verbose {
        println!(
            "target_options.target_cpu = {:?}",
            target_options.target_cpu
        );
        println!("triple_cpu = {:?}", triple_cpu);
        println!("target_triple = {:?}", target_triple);
        println!("target_args = {:?}", target_args);
    }

    let target_triple_uc = format!("{}_unknown_fuchsia", triple_cpu).to_uppercase();

    let fargo_path = if runner.is_some() {
        runner.unwrap()
    } else {
        fs::canonicalize(std::env::current_exe()?)?
    };

    let mut runner_args = vec![
        fargo_path
            .to_str()
            .ok_or_else(|| err_msg("unable to convert path to utf8 encoding"))?,
    ];

    if options.verbose {
        runner_args.push("-v");
        target_args.push("-v");
    }

    if let Some(device_name) = target_options.device_name {
        runner_args.push("--device-name");
        runner_args.push(device_name);
    }

    runner_args.push("run-on-target");

    if options.set_root_view {
        runner_args.push(&set_root_view_arg);
    }

    if let Some(args_for_target) = additional_target_args {
        runner_args.push(&args_for_target);
    }

    let fargo_command = runner_args.join(" ");

    if options.verbose {
        println!("fargo_command: {:?}", fargo_command);
    }

    let pkg_path = pkg_config_path(target_options)?;
    let mut cmd = Command::new(cargo_path(target_options)?);
    let sysroot_as_path = sysroot_path(target_options)?;
    let sysroot_as_str = sysroot_as_path.to_str().unwrap();

    let args: Vec<&str> = args
        .iter()
        .map(|a| if *a == "++" { "--" } else { *a })
        .collect();

    let runner_env_name = format!("CARGO_TARGET_{}_RUNNER", target_triple_uc);
    let rustflags_env_name = format!("CARGO_TARGET_{}_RUSTFLAGS", target_triple_uc);
    let linker_env_name = format!("CARGO_TARGET_{}_LINKER", target_triple_uc);

    if options.verbose {
        println!("runner_env_name: {:?}", runner_env_name);
        println!("rustflags_env_name: {:?}", rustflags_env_name);
        println!("linker_env_name: {:?}", linker_env_name);
        println!(
            "rustc_path: {:?}",
            rustc_path(target_options)?.to_str().unwrap()
        );
        println!(
            "cargo_path: {:?}",
            cargo_path(target_options)?.to_str().unwrap()
        );
    }

    cmd.env(runner_env_name, fargo_command)
        .env(
            rustflags_env_name,
            format!(
                "-C link-arg=--target={}-unknown-fuchsia -C link-arg=--sysroot={} -Lnative={}",
                triple_cpu,
                sysroot_as_str,
                shared_libraries_path(target_options)?.to_str().unwrap(),
            ),
        )
        .env(
            linker_env_name,
            clang_linker_path(target_options)?.to_str().unwrap(),
        )
        .env("RUSTC", rustc_path(target_options)?.to_str().unwrap())
        .env("RUSTDOC", rustdoc_path(target_options)?.to_str().unwrap())
        .env(
            "FUCHSIA_SHARED_ROOT",
            shared_libraries_path(target_options)?,
        )
        .env("ZIRCON_BUILD_ROOT", zircon_build_path(target_options)?)
        .arg(subcommand)
        .args(target_args)
        .args(args);

    if !options.disable_cross {
        let cc_env_name = format!("CC_{}", target_triple_uc);
        let cxx_env_name = format!("CXX_{}", target_triple_uc);
        let cflags_env_name = format!("CFLAGS_{}", target_triple_uc);
        let ar_env_name = format!("AR_{}", target_triple_uc);
        cmd.env(
            cc_env_name,
            clang_c_compiler_path(target_options)?.to_str().unwrap(),
        ).env(
                cxx_env_name,
                clang_cpp_compiler_path(target_options)?.to_str().unwrap(),
            )
            .env(cflags_env_name, format!("--sysroot={}", sysroot_as_str))
            .env(
                ar_env_name,
                clang_archiver_path(target_options)?.to_str().unwrap(),
            )
            .env(
                "RANLIB",
                clang_ranlib_path(target_options)?.to_str().unwrap(),
            )
            .env("PKG_CONFIG_ALL_STATIC", "1")
            .env("PKG_CONFIG_ALLOW_CROSS", "1")
            .env("PKG_CONFIG_PATH", "")
            .env("PKG_CONFIG_LIBDIR", pkg_path);
    }

    if options.verbose {
        println!("cargo cmd: {:?}", cmd);
    }

    let cargo_status = cmd.status()?;
    if !cargo_status.success() {
        bail!("cargo exited with status {:?}", cargo_status,);
    }

    Ok(())
}

static SET_ROOT_VIEW: &str = "set-root-view";

static CHECK: &str = "check";
static RELEASE: &str = "release";
static EXAMPLE: &str = "example";
static EXAMPLES: &str = "examples";

static DOC: &str = "doc";
static DOC_OPEN: &str = "open";
static DOC_NO_DEPS: &str = "no-deps";

static TARGET_CPU: &str = "target-cpu";
static X64: &str = "x64";
static ARM64: &str = "arm64";

static SUBCOMMAND: &str = "subcommand";

static DISABLE_CROSS_ENV: &str = "disable-cross-env";

static NO_NET: &str = "no-net";
static FX_RUN_PARAMS: &str = "fx-run-params";

static RELEASE_HELP: &str = "Build artifacts in release mode, with optimizations";

static START: &str = "start";
static RESTART: &str = "restart";
static GRAPHICS: &str = "graphics";
static DISABLE_VIRTCON: &str = "disable-virtcon";

#[doc(hidden)]
pub fn run() -> Result<(), Error> {
    let matches =
        App::new("fargo")
            .version("v0.2.0")
            .setting(AppSettings::GlobalVersion)
            .about("Fargo is a prototype Fuchsia-specific wrapper around Cargo")
            .arg(
                Arg::with_name("verbose")
                    .long("verbose")
                    .short("v")
                    .help("Print verbose output while performing commands"),
            )
            .arg(
                Arg::with_name("debug-os")
                    .long("debug-os")
                    .help("Use debug user.bootfs and ssh keys"),
            )
            .arg(
                Arg::with_name(DISABLE_CROSS_ENV)
                    .long(DISABLE_CROSS_ENV)
                    .help("Disable the setting of CC, AR and such environmental variables."),
            )
            .arg(
                Arg::with_name(TARGET_CPU)
                    .long(TARGET_CPU)
                    .short("T")
                    .value_name(TARGET_CPU)
                    .default_value(X64)
                    .possible_values(&[X64, ARM64])
                    .help("Architecture of target device"),
            )
            .arg(
                Arg::with_name("device-name")
                    .long("device-name")
                    .short("N")
                    .value_name("device-name")
                    .help(
                        "Name of device to target, needed if there are multiple devices visible \
                         on the network",
                    ),
            )
            .subcommand(
                SubCommand::with_name("autotest")
                    .about("Auto build and test in Fuchsia device or emulator")
                    .arg(Arg::with_name(RELEASE).long(RELEASE).help("Build release")),
            )
            .subcommand(
                SubCommand::with_name("build-tests")
                    .about("Build tests for Fuchsia device or emulator")
                    .arg(
                        Arg::with_name("test")
                            .long("test")
                            .value_name("test")
                            .help("Test only the specified test target"),
                    )
                    .arg(Arg::with_name(RELEASE).long(RELEASE).help("Build release")),
            )
            .subcommand(
                SubCommand::with_name("test")
                    .about("Run unit tests on Fuchsia device or emulator")
                    .arg(Arg::with_name(RELEASE).long(RELEASE).help(RELEASE_HELP))
                    .arg(
                        Arg::with_name("test")
                            .long("test")
                            .value_name("test")
                            .help("Test only the specified test target"),
                    )
                    .arg(
                        Arg::with_name("test_args")
                            .long("args")
                            .value_name("args")
                            .help("arguments to pass to the test runner"),
                    )
                    .arg(Arg::with_name("test_params").index(1).multiple(true)),
            )
            .subcommand(
                SubCommand::with_name("build")
                    .about("Build binary targeting Fuchsia device or emulator")
                    .arg(Arg::with_name(RELEASE).long(RELEASE).help(RELEASE_HELP))
                    .arg(
                        Arg::with_name("example")
                            .long("example")
                            .takes_value(true)
                            .help("Build a specific example from the examples/ dir."),
                    )
                    .arg(
                        Arg::with_name("examples")
                            .long("examples")
                            .help("Build all examples in the examples/ dir."),
                    ),
            )
            .subcommand(
                SubCommand::with_name(CHECK)
                    .about("Check binary targeting Fuchsia device or emulator")
                    .arg(Arg::with_name(RELEASE).long(RELEASE).help(RELEASE_HELP))
                    .arg(
                        Arg::with_name(EXAMPLE)
                            .long(EXAMPLE)
                            .takes_value(true)
                            .help("Check a specific example from the examples/ dir."),
                    )
                    .arg(
                        Arg::with_name(EXAMPLES)
                            .long(EXAMPLES)
                            .help("Check all examples in the examples/ dir."),
                    ),
            )
            .subcommand(
                SubCommand::with_name(DOC)
                    .about("Build a package's documentation")
                    .arg(Arg::with_name(RELEASE).long(RELEASE).help(RELEASE_HELP))
                    .arg(
                        Arg::with_name(DOC_NO_DEPS)
                            .long(DOC_NO_DEPS)
                            .help("Don't build documentation for dependencies"),
                    )
                    .arg(
                        Arg::with_name(DOC_OPEN)
                            .long(DOC_OPEN)
                            .help("Opens the docs in a browser after the operation"),
                    ),
            )
            .subcommand(
                SubCommand::with_name("run")
                    .about("Run binary on Fuchsia device or emulator")
                    .arg(Arg::with_name(RELEASE).long(RELEASE).help(RELEASE_HELP))
                    .arg(
                        Arg::with_name(SET_ROOT_VIEW)
                            .long(SET_ROOT_VIEW)
                            .help("Use set_root_view to run binary."),
                    )
                    .arg(
                        Arg::with_name("example")
                            .long("example")
                            .value_name("example")
                            .help("Run a specific example from the examples/ dir."),
                    ),
            )
            .subcommand(
                SubCommand::with_name("load-driver")
                    .about("Build driver and load it on Fuchsia device or emulator.")
                    .arg(Arg::with_name(RELEASE).long(RELEASE).help("Build release")),
            )
            .subcommand(SubCommand::with_name("list-devices").about("List visible Fuchsia devices"))
            .subcommand(
                SubCommand::with_name(START)
                    .about("Start a Fuchsia emulator")
                    .arg(
                        Arg::with_name(GRAPHICS)
                            .short("g")
                            .help("Start a simulator with graphics enabled"),
                    )
                    .arg(Arg::with_name(DISABLE_VIRTCON).long(DISABLE_VIRTCON).help(
                        "Do not launch the virtual console service if this option is present",
                    ))
                    .arg(
                        Arg::with_name(NO_NET)
                            .long(NO_NET)
                            .help("Don't set up networking."),
                    )
                    .arg(Arg::with_name(FX_RUN_PARAMS).index(1).multiple(true)),
            )
            .subcommand(SubCommand::with_name("stop").about("Stop all Fuchsia emulators"))
            .subcommand(
                SubCommand::with_name("enable-networking")
                    .about("Enable networking for a running emulator"),
            )
            .subcommand(
                SubCommand::with_name(RESTART)
                    .about("Stop all Fuchsia emulators and start a new one")
                    .arg(
                        Arg::with_name(GRAPHICS)
                            .short("g")
                            .help("Start a simulator with graphics enabled"),
                    )
                    .arg(Arg::with_name(DISABLE_VIRTCON).long(DISABLE_VIRTCON).help(
                        "Do not launch the virtual console service if this option is present",
                    ))
                    .arg(
                        Arg::with_name(NO_NET)
                            .long(NO_NET)
                            .help("Don't set up networking."),
                    )
                    .arg(Arg::with_name(FX_RUN_PARAMS).index(1).multiple(true)),
            )
            .subcommand(
                SubCommand::with_name("ssh").about("Open a shell on Fuchsia device or emulator"),
            )
            .subcommand(
                SubCommand::with_name("cargo")
                    .about(
                        "Run a cargo command for Fuchsia. Use -- to indicate that all following \
                         arguments should be passed to cargo.",
                    )
                    .arg(Arg::with_name(SUBCOMMAND).required(true))
                    .arg(Arg::with_name("cargo_params").index(2).multiple(true)),
            )
            .subcommand(
                SubCommand::with_name("run-on-target")
                    .about("Act as a test runner for cargo")
                    .arg(
                        Arg::with_name("test_args")
                            .long("args")
                            .value_name("args")
                            .help("arguments to pass to the test runner"),
                    )
                    .arg(
                        Arg::with_name(SET_ROOT_VIEW)
                            .long(SET_ROOT_VIEW)
                            .help("Use set_root_view to run binary."),
                    )
                    .arg(
                        Arg::with_name("run_on_target_params")
                            .index(1)
                            .multiple(true),
                    )
                    .setting(AppSettings::Hidden),
            )
            .subcommand(
                SubCommand::with_name("pkg-config")
                    .about("Run pkg-config for the cross compilation environment")
                    .arg(Arg::with_name("pkgconfig_param").index(1).multiple(true)),
            )
            .subcommand(
                SubCommand::with_name("configure")
                    .about("Run a configure script for the cross compilation environment")
                    .arg(Arg::with_name("configure_param").index(1).multiple(true))
                    .arg(
                        Arg::with_name("no-host")
                            .long("no-host")
                            .help("Don't pass --host to configure"),
                    ),
            )
            .get_matches();

    let verbose = matches.is_present("verbose");
    let disable_cross = matches.is_present(DISABLE_CROSS_ENV);
    let release = !matches.is_present("debug-os");
    let target_options = TargetOptions::new(
        release,
        matches.value_of(TARGET_CPU).unwrap(),
        matches.value_of("device-name"),
    );

    let run_cargo_options = RunCargoOptions {
        verbose,
        release: false,
        set_root_view: false,
        disable_cross,
    };

    if verbose {
        println!("target_options = {:#?}", target_options);
    }

    let fuchsia_config = FuchsiaConfig::new(&target_options)?;
    if verbose {
        println!("fuchsia_config = {:#?}", fuchsia_config);
    }

    if let Some(autotest_matches) = matches.subcommand_matches("autotest") {
        return autotest(
            run_cargo_options.release(autotest_matches.is_present(RELEASE)),
            &target_options,
        );
    }

    if let Some(test_matches) = matches.subcommand_matches("test") {
        let test_params = test_matches
            .values_of("test_params")
            .map(|x| x.collect())
            .unwrap_or_else(|| vec![]);
        let test_target = test_matches.value_of("test").unwrap_or("");
        let test_args = test_matches.value_of("test_args");
        return run_tests(
            run_cargo_options.release(test_matches.is_present(RELEASE)),
            false,
            &target_options,
            test_target,
            &test_params,
            test_args,
        );
    }

    if let Some(build_matches) = matches.subcommand_matches("build") {
        let mut params = vec![];
        if let Some(example) = build_matches.value_of("example") {
            params.push("--example");
            params.push(example);
        }

        if build_matches.is_present("examples") {
            params.push("--examples");
        }

        build_binary(
            run_cargo_options.release(build_matches.is_present(RELEASE)),
            &target_options,
            &params,
        )?;
        return Ok(());
    }

    if let Some(check_matches) = matches.subcommand_matches(CHECK) {
        let mut params = vec![];
        if let Some(example) = check_matches.value_of(EXAMPLE) {
            params.push("--example");
            params.push(example);
        }

        if check_matches.is_present(EXAMPLES) {
            params.push("--examples");
        }

        check_binary(
            run_cargo_options.release(check_matches.is_present(RELEASE)),
            &target_options,
            &params,
        )?;
        return Ok(());
    }

    if let Some(run_matches) = matches.subcommand_matches("run") {
        let mut params = vec![];
        if let Some(example) = run_matches.value_of("example") {
            params.push("--example");
            params.push(example);
        }

        return run_binary(
            run_cargo_options
                .release(run_matches.is_present(RELEASE))
                .set_root_view(run_matches.is_present(SET_ROOT_VIEW)),
            &target_options,
            &params,
        );
    }

    if let Some(load_driver_matches) = matches.subcommand_matches("load-driver") {
        return load_driver(
            run_cargo_options.release(load_driver_matches.is_present(RELEASE)),
            &target_options,
        );
    }

    if let Some(build_test_matches) = matches.subcommand_matches("build-tests") {
        let test_target = build_test_matches.value_of("test").unwrap_or("");
        build_tests(
            run_cargo_options.release(build_test_matches.is_present(RELEASE)),
            &target_options,
            test_target,
        )?;
        return Ok(());
    }

    if let Some(doc_matches) = matches.subcommand_matches(DOC) {
        return build_doc(
            run_cargo_options.release(doc_matches.is_present(RELEASE)),
            &target_options,
            doc_matches.is_present(DOC_NO_DEPS),
            doc_matches.is_present(DOC_OPEN),
        );
    }

    if matches.subcommand_matches("list-devices").is_some() {
        return netls(verbose, &target_options);
    }

    if let Some(start_matches) = matches.subcommand_matches(START) {
        if fuchsia_config.is_release() != target_options.release_os {
            bail!(
                "Variant '{}' from .config would override the fargo command line flag.",
                fuchsia_config.fuchsia_variant
            );
        }

        let fx_run_params = start_matches
            .values_of(FX_RUN_PARAMS)
            .map(|x| x.collect())
            .unwrap_or_else(|| vec![]);

        return start_emulator(
            &StartEmulatorOptions {
                verbose: verbose,
                with_graphics: start_matches.is_present(GRAPHICS),
                with_networking: !start_matches.is_present(NO_NET),
                disable_virtcon: start_matches.is_present(DISABLE_VIRTCON),
            },
            &fx_run_params,
            &target_options,
        );
    }

    if matches.subcommand_matches("stop").is_some() {
        return stop_emulator();
    }

    if matches.subcommand_matches("enable-networking").is_some() {
        return enable_networking();
    }

    if let Some(restart_matches) = matches.subcommand_matches(RESTART) {
        stop_emulator()?;

        let fx_run_params = restart_matches
            .values_of(FX_RUN_PARAMS)
            .map(|x| x.collect())
            .unwrap_or_else(|| vec![]);

        return start_emulator(
            &StartEmulatorOptions {
                verbose: verbose,
                with_graphics: restart_matches.is_present(GRAPHICS),
                with_networking: !restart_matches.is_present(NO_NET),
                disable_virtcon: restart_matches.is_present(DISABLE_VIRTCON),
            },
            &fx_run_params,
            &target_options,
        );
    }

    if matches.subcommand_matches("ssh").is_some() {
        return ssh(verbose, &target_options, "");
    }

    if let Some(cargo_matches) = matches.subcommand_matches("cargo") {
        let subcommand = cargo_matches.value_of(SUBCOMMAND).unwrap();
        let cargo_params = cargo_matches
            .values_of("cargo_params")
            .map(|x| x.collect())
            .unwrap_or_else(|| vec![]);
        return run_cargo(
            RunCargoOptions {
                verbose,
                release: false,
                set_root_view: false,
                disable_cross: disable_cross,
            },
            subcommand,
            &cargo_params,
            &target_options,
            None,
            None,
        );
    }

    if let Some(run_on_target_matches) = matches.subcommand_matches("run-on-target") {
        let run_params = run_on_target_matches
            .values_of("run_on_target_params")
            .map(|x| x.collect())
            .unwrap_or_else(|| vec![]);
        let test_args = run_on_target_matches.value_of("test_args");
        let (program, args) = run_params.split_first().unwrap();
        return run_program_on_target(
            program,
            verbose,
            &target_options,
            run_on_target_matches.is_present(SET_ROOT_VIEW),
            args,
            test_args,
        );
    }

    if let Some(pkg_matches) = matches.subcommand_matches("pkg-config") {
        let pkg_params = pkg_matches
            .values_of("pkgconfig_param")
            .map(|x| x.collect())
            .unwrap_or_else(|| vec![]);
        let exit_code = run_pkg_config(verbose, &pkg_params, &target_options)?;
        if exit_code != 0 {
            ::std::process::exit(exit_code);
        }
        return Ok(());
    }

    if let Some(configure_matches) = matches.subcommand_matches("configure") {
        let configure_params = configure_matches
            .values_of("configure_param")
            .map(|x| x.collect())
            .unwrap_or_else(|| vec![]);
        run_configure(
            verbose,
            !configure_matches.is_present("no-host"),
            &configure_params,
            &target_options,
        )?;
        return Ok(());
    }

    Ok(())
}
