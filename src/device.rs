// Copyright 2017 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

use crate::sdk::{fuchsia_dir, fx_path, target_out_dir, FuchsiaConfig, TargetOptions};
use crate::utils::is_mac;
use failure::{bail, err_msg, Error, ResultExt};
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::{str, thread, time};

pub fn netaddr(verbose: bool, target_options: &TargetOptions<'_, '_>) -> Result<String, Error> {
    let fuchsia_dir = fuchsia_dir()?;
    let netaddr_binary = fuchsia_dir.join("out/build-zircon/tools/netaddr");
    let mut args = vec!["--fuchsia"];
    if let Some(device_name) = target_options.device_name {
        args.push(device_name);
    }
    let netaddr_result = Command::new(netaddr_binary).args(args).output()?;
    let result = str::from_utf8(&netaddr_result.stdout)
        .unwrap()
        .trim()
        .to_string();
    if verbose {
        println!(
            "netaddr status = {}, result = {}",
            netaddr_result.status, result
        );
    }
    if !netaddr_result.status.success() {
        let err_str = str::from_utf8(&netaddr_result.stderr)
            .unwrap()
            .trim()
            .to_string();
        bail!(
            "netaddr failed with status {:?}: {}",
            netaddr_result.status,
            err_str
        );
    }
    Ok(result)
}

pub fn netls(verbose: bool) -> Result<(), Error> {
    let fuchsia_dir = fuchsia_dir()?;
    let netls_binary = fuchsia_dir.join("out/build-zircon/tools/netls");
    let mut netls_command = Command::new(netls_binary);
    netls_command.arg("--nowait").arg("--timeout=500");
    if verbose {
        println!("{:?}", netls_command);
    }
    let netls_status = netls_command.status()?;
    if !netls_status.success() {
        bail!("netlst failed with error {:?}", netls_status);
    }
    Ok(())
}

static SSH_OPTIONS: &'static [&str] = &[
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "ConnectTimeout=20",
];

pub fn scp_to_device(
    verbose: bool, config: &FuchsiaConfig, netaddr: &str, source_path: &PathBuf,
    destination_path: &str,
) -> Result<(), Error> {
    let destination_with_address = format!("[{}]:{}", netaddr, destination_path);
    let ssh_config = target_out_dir(config)?.join("ssh-keys/ssh_config");
    if !ssh_config.exists() {
        bail!("ssh config not found at {:?}", ssh_config);
    }
    if verbose {
        println!("destination_with_address = {}", destination_with_address);
        println!("ssh_config = {:?}", ssh_config);
    }

    let mut scp_command = Command::new("scp");

    scp_command
        .env_remove("SSH_AUTH_SOCK")
        .arg(if verbose { "-v" } else { "-q" })
        .arg("-F")
        .arg(ssh_config)
        .args(SSH_OPTIONS)
        .arg(source_path)
        .arg(destination_with_address);

    if verbose {
        println!("{:?}", scp_command);
    }

    let scp_result = scp_command.status().context("unable to run scp")?;

    if !scp_result.success() {
        bail!("scp failed with error {:?}", scp_result);
    }

    Ok(())
}

pub fn ssh(
    verbose: bool, config: &FuchsiaConfig, target_options: &TargetOptions<'_, '_>, command: &str,
) -> Result<(), Error> {
    let netaddr = netaddr(verbose, target_options)?;
    let ssh_config = target_out_dir(config)?.join("ssh-keys/ssh_config");
    if !ssh_config.exists() {
        bail!("ssh config not found at {:?}", ssh_config);
    }
    let ssh_result = Command::new("ssh")
        .env_remove("SSH_AUTH_SOCK")
        .arg("-q")
        .arg("-F")
        .arg(ssh_config)
        .args(SSH_OPTIONS)
        .arg(netaddr)
        .arg(command)
        .status()
        .context("unable to run ssh")?;

    if !ssh_result.success() {
        bail!("ssh failed: {}", ssh_result);
    }

    Ok(())
}

pub fn setup_network_mac(user: &str) -> Result<(), Error> {
    println!("Calling sudo ifconfig to bring up tap0 interface; password may be required.");

    let chown_status = Command::new("sudo")
        .arg("chown")
        .arg(user)
        .arg("/dev/tap0")
        .status()
        .context("couldn't run chown")?;

    if !chown_status.success() {
        bail!("chown failed: {}", chown_status);
    }

    let mut loop_count = 0;
    loop {
        let ifconfig_status = Command::new("sudo")
            .arg("ifconfig")
            .arg("tap0")
            .arg("inet6")
            .arg("fc00::/7")
            .arg("up")
            .status()
            .context("couldn't run ifconfig")?;

        if !ifconfig_status.success() {
            if loop_count > 10 {
                bail!("ifconfig failed: {}", ifconfig_status);
            }
            loop_count += 1;
            thread::sleep(time::Duration::from_millis(100));
        } else {
            break;
        }
    }

    println!("tap0 enabled");

    Ok(())
}

#[cfg_attr(rustfmt, rustfmt_skip)]
static TUNCTL_NOT_FOUND_ERROR: &'static str =
"tunctl command not found. Please install uml-utilities.
For help see https://fuchsia.googlesource.com/zircon/+/
master/docs/qemu.md#Enabling-Networking-under-QEMU-x86_64-only";

pub fn setup_network_linux(user: &str) -> Result<(), Error> {
    // Create the tap network device if it doesn't exist.
    if !Path::new("/sys/class/net/qemu").exists() {
        println!(
            "Qemu tap device not found. Using sudo and tunctl to create tap network device; \
             password may be required."
        );
        let tunctl_status = Command::new("sudo")
            .args(&["tunctl", "-b", "-u", user, "-t", "qemu"])
            .stdout(Stdio::null())
            .status()
            .map_err(|e| {
                if e.kind() == ::std::io::ErrorKind::NotFound {
                    err_msg(TUNCTL_NOT_FOUND_ERROR)
                } else {
                    err_msg("tunctl failed to create a new tap network device")
                }
            })?;

        if !tunctl_status.success() {
            bail!("tunctl failed to create tap network device.");
        }
    }

    let ifconfig_status = Command::new("sudo")
        .arg("ifconfig")
        .arg("qemu")
        .arg("up")
        .status()
        .context("couldn't run ifconfig")?;

    if !ifconfig_status.success() {
        bail!("ifconfig failed");
    }

    Ok(())
}

pub fn setup_network() -> Result<(), Error> {
    let user = env::var("USER").context("No $USER env var found.")?;
    if is_mac() {
        setup_network_mac(&user)?;
    } else {
        setup_network_linux(&user)?;
    }
    Command::new("stty")
        .arg("sane")
        .status()
        .context("couldn't run stty")?;
    Ok(())
}

pub struct StartEmulatorOptions {
    pub verbose: bool,
    pub with_graphics: bool,
    pub with_networking: bool,
    pub disable_virtcon: bool,
}

pub fn start_emulator(options: &StartEmulatorOptions, params: &[&str]) -> Result<(), Error> {
    let fuchsia_dir = fuchsia_dir()?;
    let fx_script = fx_path()?;
    if !fx_script.exists() {
        bail!("fx script not found at {:?}", fx_script);
    }
    let mut args = vec!["run", "-N"];
    if options.with_graphics {
        args.push("-g");
    }

    if options.disable_virtcon {
        args.push("-c");
        args.push("virtcon.disable");
    }

    if options.verbose {
        println!("fx_script = {:?}", fx_script);
        println!("args = {:?}", args);
        println!("params = {:?}", params);
    }

    let child = Command::new(fx_script)
        .args(&args)
        .args(params)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir(&fuchsia_dir)
        .spawn()
        .context("unable to run qemu")?;

    println!("emulator started with process ID {}", child.id());

    if options.with_networking {
        setup_network()
    } else {
        Ok(())
    }
}

pub fn stop_emulator() -> Result<(), Error> {
    Command::new("killall").arg("qemu-system-x86_64").status()?;
    Ok(())
}

pub fn enable_networking() -> Result<(), Error> {
    setup_network()
}
