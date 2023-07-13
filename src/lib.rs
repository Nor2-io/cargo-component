//! Cargo support for WebAssembly components.

#![deny(missing_docs)]

use crate::config::Config;
use anyhow::{anyhow, bail, Context as _, Result};
use bindings::BindingsEncoder;
use bytes::Bytes;
use cargo::{
    core::{compiler::Compilation, Workspace},
    ops::{
        self, CompileOptions, DocOptions, ExportInfo, OutputMetadataOptions, Packages,
        UpdateOptions,
    },
    util::Filesystem,
};
use futures::TryStreamExt;
use metadata::Target;
use registry::{
    LockFile, LockFileResolver, LockedPackage, LockedPackageVersion, PackageDependencyResolution,
    PackageResolutionMap,
};
use semver::Version;
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
    time::{Duration, SystemTime},
};
use termcolor::Color;
use tokio::io::BufReader;
use tokio_util::io::ReaderStream;
use warg_client::storage::{ContentStorage, PublishEntry, PublishInfo};
use warg_crypto::signing::PrivateKey;
use warg_protocol::registry::PackageId;
use wit_component::ComponentEncoder;

pub mod bindings;
pub mod commands;
pub mod config;
mod generator;
pub mod metadata;
pub mod registry;
mod signing;
mod target;

fn last_modified_time(path: impl AsRef<Path>) -> Result<SystemTime> {
    let path = path.as_ref();
    path.metadata()
        .with_context(|| {
            format!(
                "failed to read file metadata for `{path}`",
                path = path.display()
            )
        })?
        .modified()
        .with_context(|| {
            format!(
                "failed to retrieve last modified time for `{path}`",
                path = path.display()
            )
        })
}

fn bindings_dir(workspace: &Workspace) -> Filesystem {
    workspace.target_dir().join("bindings")
}

async fn create_resolution_map(
    config: &Config,
    workspace: &Workspace<'_>,
    lock_file: Option<&LockFile>,
) -> Result<PackageResolutionMap> {
    let mut map = PackageResolutionMap::default();
    let resolver = lock_file.map(|l| LockFileResolver::new(workspace, l));

    for package in workspace.members() {
        match PackageDependencyResolution::new(config, package, resolver).await? {
            Some(resolution) => {
                let prev = map.insert(package.package_id(), resolution);
                assert!(prev.is_none());
            }
            None => continue,
        }
    }
    Ok(map)
}

async fn resolve_dependencies(
    config: &Config,
    workspace: &Workspace<'_>,
) -> Result<PackageResolutionMap> {
    let lock_file = LockFile::open(config, workspace)?.unwrap_or_default();
    let map = create_resolution_map(config, workspace, Some(&lock_file)).await?;
    let new_lock_file = LockFile::from_resolution_map(&map);
    new_lock_file.update(config, workspace, &lock_file)?;

    Ok(map)
}

async fn encode_workspace_bindings(
    config: &Config,
    workspace: &Workspace<'_>,
    force_generation: bool,
) -> Result<PackageResolutionMap> {
    let map = resolve_dependencies(config, workspace).await?;
    let bindings_dir = bindings_dir(workspace);
    let _lock = bindings_dir.open_rw(".lock", config.cargo(), "bindings cache")?;

    for package in workspace.members() {
        let resolution = match map.get(&package.package_id()) {
            Some(resolution) => resolution,
            None => continue,
        };

        encode_package_bindings(
            config,
            resolution,
            bindings_dir.as_path_unlocked(),
            force_generation,
        )
        .await?;
    }

    Ok(map)
}

async fn encode_package_bindings(
    config: &Config,
    resolution: &PackageDependencyResolution,
    bindings_dir: &Path,
    force: bool,
) -> Result<()> {
    let output = bindings_dir
        .join(&resolution.metadata.name)
        .join("bindings.wasm");

    let last_modified_output = output
        .is_file()
        .then(|| last_modified_time(&output))
        .transpose()?
        .unwrap_or(SystemTime::UNIX_EPOCH);

    let encoder = BindingsEncoder::new(resolution)?;

    match encoder.reason(last_modified_output, force)? {
        Some(reason) => {
            ::log::debug!(
                "encoding bindings for package `{name}` at `{path}` because {reason}",
                name = resolution.metadata.name,
                path = output.display(),
            );

            config.shell().status(
                "Encoding",
                format!(
                    "bindings for {name} ({path})",
                    name = resolution.metadata.name,
                    path = output.display()
                ),
            )?;

            let encoded = encoder.encode(None)?;

            if let Some(parent) = output.parent() {
                fs::create_dir_all(parent).with_context(|| {
                    format!(
                        "failed to create output directory `{path}`",
                        path = parent.display()
                    )
                })?;
            }

            fs::write(&output, encoded).with_context(|| {
                format!(
                    "failed to write bindings information to `{path}`",
                    path = output.display()
                )
            })?;
        }
        None => {
            ::log::debug!(
                "encoded bindings for package `{name}` at `{path}` is up-to-date",
                name = resolution.metadata.name,
                path = output.display(),
            );
        }
    }

    Ok(())
}

fn is_wasm_module(path: impl AsRef<Path>) -> Result<bool> {
    let path = path.as_ref();

    let mut file = File::open(path)
        .with_context(|| format!("failed to open `{path}` for read", path = path.display()))?;

    let mut bytes = [0u8; 8];
    file.read(&mut bytes).with_context(|| {
        format!(
            "failed to read file header for `{path}`",
            path = path.display()
        )
    })?;

    if bytes[0..4] != [0x0, b'a', b's', b'm'] {
        bail!(
            "expected `{path}` to be a WebAssembly module",
            path = path.display()
        );
    }

    // Check for the module header version
    Ok(bytes[4..] == [0x01, 0x00, 0x00, 0x00])
}

fn create_component(config: &Config, path: &Path, binary: bool) -> Result<()> {
    // If the compilation output is not a WebAssembly module, then do nothing
    // Note: due to the way cargo currently works on macOS, it will overwrite
    // a previously generated component on an up-to-date build.
    //
    // As a result, users on macOS will see a "creating component" message
    // even if the build is up-to-date.
    //
    // See: https://github.com/rust-lang/cargo/blob/99ad42deb4b0be0cdb062d333d5e63460a94c33c/crates/cargo-util/src/paths.rs#L542-L550
    if !is_wasm_module(path)? {
        ::log::debug!(
            "output file `{path}` is already a WebAssembly component",
            path = path.display()
        );
        return Ok(());
    }

    ::log::debug!(
        "componentizing WebAssembly module `{path}`",
        path = path.display()
    );

    let module = fs::read(path).with_context(|| {
        anyhow!(
            "failed to read output module `{path}`",
            path = path.display()
        )
    })?;

    config.shell().status(
        "Creating",
        format!("component {path}", path = path.display()),
    )?;

    let encoder = ComponentEncoder::default()
        .adapter(
            "wasi_snapshot_preview1",
            if binary {
                include_bytes!(concat!(
                    "../adapters/",
                    env!("WASI_ADAPTER_VERSION"),
                    "/wasi_snapshot_preview1.command.wasm"
                ))
            } else {
                include_bytes!(concat!(
                    "../adapters/",
                    env!("WASI_ADAPTER_VERSION"),
                    "/wasi_snapshot_preview1.reactor.wasm"
                ))
            },
        )?
        .module(&module)?
        .validate(true);

    let mut producers = wasm_metadata::Producers::empty();
    producers.add(
        "processed-by",
        env!("CARGO_PKG_NAME"),
        option_env!("CARGO_VERSION_INFO").unwrap_or(env!("CARGO_PKG_VERSION")),
    );

    let component = producers.add_to_wasm(&encoder.encode()?).with_context(|| {
        anyhow!(
            "failed to add metadata to output component `{path}`",
            path = path.display()
        )
    })?;

    fs::write(path, component).with_context(|| {
        anyhow!(
            "failed to write output component `{path}`",
            path = path.display()
        )
    })
}

/// Compile a component for the given workspace and compile options.
///
/// It is expected that the current package contains a `package.metadata.component` section.
pub async fn compile<'a>(
    config: &Config,
    workspace: Workspace<'a>,
    options: &CompileOptions,
    force_generation: bool,
) -> Result<Compilation<'a>> {
    let map = encode_workspace_bindings(config, &workspace, force_generation).await?;
    let compilation = ops::compile(&workspace, options)?;

    for (binary, output) in compilation
        .binaries
        .iter()
        .map(|o| (true, o))
        .chain(compilation.cdylibs.iter().map(|o| (false, o)))
        .filter(|(_, o)| map.keys().any(|k| k == &o.unit.pkg.package_id()))
    {
        create_component(config, &output.path, binary)?;
    }

    Ok(compilation)
}

/// Represents options for a publish WIT operation.
pub struct PublishWitOptions<'a> {
    /// The name of the cargo package to publish for.
    pub cargo_package: Option<&'a str>,
    /// The id of the registry package to publish.
    pub id: &'a PackageId,
    /// The version of the registry package to publish.
    pub version: &'a Version,
    /// The url of the registry to publish to.
    pub url: &'a str,
    /// The private signing key to use for the publish.
    pub signing_key: PrivateKey,
    /// Whether or not to initialize the package before publishing.
    pub init: bool,
    /// Whether or not to perform a dry run.
    ///
    /// A dry run skips communicating with the registry.
    pub dry_run: bool,
}

/// Publish the target WIT for a project to a component registry.
pub async fn publish_wit(
    config: &Config,
    workspace: Workspace<'_>,
    options: &PublishWitOptions<'_>,
) -> Result<()> {
    let package = if let Some(ref inner) = options.cargo_package {
        let pkg = Packages::from_flags(false, vec![], vec![inner.to_string()])?;
        pkg.get_packages(&workspace)?[0]
    } else {
        workspace.current()?
    };

    let map = resolve_dependencies(config, &workspace).await?;
    let resolution = match map.get(&package.package_id()) {
        Some(resolution) => resolution,
        None => bail!(
            "manifest `{path}` is not a WebAssembly component package",
            path = package.manifest_path().display(),
        ),
    };

    let bytes = match &resolution.metadata.section.target {
        Some(Target::Local { .. }) => {
            let encoder = BindingsEncoder::new(resolution)?;
            encoder.encode(Some(options.version)).with_context(|| {
                anyhow!(
                    "failed to encode target WIT for package `{package}`",
                    package = package.name()
                )
            })?
        }
        _ => {
            bail!("a WIT package may only be published from a project using a local target");
        }
    };

    let mut producers = wasm_metadata::Producers::empty();
    producers.add(
        "processed-by",
        env!("CARGO_PKG_NAME"),
        option_env!("CARGO_VERSION_INFO").unwrap_or(env!("CARGO_PKG_VERSION")),
    );

    let bytes = producers
        .add_to_wasm(&bytes)
        .context("failed to add producers metadata to output WIT package")?;

    if options.dry_run {
        config
            .shell()
            .warn("not publishing WIT package to the registry due to the --dry-run option")?;
        return Ok(());
    }

    let client = registry::create_client(config, options.url)?;

    let content = client
        .content()
        .store_content(
            Box::pin(futures::stream::once(async { Ok(Bytes::from(bytes)) })),
            None,
        )
        .await?;

    config
        .shell()
        .status("Publishing", format!("target WIT package ({content})"))?;

    let mut info = PublishInfo {
        id: options.id.clone(),
        head: None,
        entries: Default::default(),
    };

    if options.init {
        info.entries.push(PublishEntry::Init);
    }

    info.entries.push(PublishEntry::Release {
        version: options.version.clone(),
        content,
    });

    let record_id = client.publish_with_info(&options.signing_key, info).await?;
    client
        .wait_for_publish(options.id, &record_id, Duration::from_secs(1))
        .await?;

    config.shell().status(
        "Published",
        format!(
            "package `{id}` v{version}",
            id = options.id,
            version = options.version
        ),
    )?;

    Ok(())
}

/// Represents options for a publish operation.
pub struct PublishOptions<'a> {
    /// Force generation of bindings for the build.
    pub force_generation: bool,
    /// The compile options to use for the build.
    pub compile_options: CompileOptions,
    /// The id of the component to publish.
    pub id: &'a PackageId,
    /// The version of the component to publish.
    pub version: &'a Version,
    /// The url of the registry to publish to.
    pub url: &'a str,
    /// The private signing key to use for the publish.
    pub signing_key: PrivateKey,
    /// Whether or not to initialize the package before publishing.
    pub init: bool,
    /// Whether or not to perform a dry run.
    ///
    /// A dry run skips communicating with the registry.
    pub dry_run: bool,
}

/// Publish a component for the given workspace and publish options.
pub async fn publish(
    config: &Config,
    workspace: Workspace<'_>,
    options: &PublishOptions<'_>,
) -> Result<()> {
    let compilation = compile(
        config,
        workspace,
        &options.compile_options,
        options.force_generation,
    )
    .await?;

    let outputs: Vec<_> = compilation
        .binaries
        .iter()
        .map(|o| (true, o))
        .chain(compilation.cdylibs.iter().map(|o| (false, o)))
        .collect();

    let output = match outputs.len() {
        0 => bail!("no compilation outputs to publish"),
        1 => &outputs[0].1,
        2 => {
            // One output must be a lib and the other a bin
            if outputs[0].0 == outputs[1].0 {
                bail!("cannot publish multiple compilation outputs");
            }

            // Publish the bin in this case
            if outputs[0].0 {
                assert!(!outputs[1].0);
                &outputs[0].1
            } else {
                assert!(outputs[1].0);
                &outputs[1].1
            }
        }
        _ => bail!("cannot publish multiple compilation outputs"),
    };

    if options.dry_run {
        config
            .shell()
            .warn("not publishing component to the registry due to the --dry-run option")?;
        return Ok(());
    }

    let client = registry::create_client(config, options.url)?;

    let content = client
        .content()
        .store_content(
            Box::pin(
                ReaderStream::new(BufReader::new(
                    tokio::fs::File::open(&output.path).await.with_context(|| {
                        format!("failed to open `{path}`", path = output.path.display())
                    })?,
                ))
                .map_err(|e| anyhow!(e)),
            ),
            None,
        )
        .await?;

    config.shell().status(
        "Publishing",
        format!("component {path} ({content})", path = output.path.display()),
    )?;

    let mut info = PublishInfo {
        id: options.id.clone(),
        head: None,
        entries: Default::default(),
    };

    if options.init {
        info.entries.push(PublishEntry::Init);
    }

    info.entries.push(PublishEntry::Release {
        version: options.version.clone(),
        content,
    });

    let record_id = client.publish_with_info(&options.signing_key, info).await?;
    client
        .wait_for_publish(options.id, &record_id, Duration::from_secs(1))
        .await?;

    config.shell().status(
        "Published",
        format!(
            "package `{id}` v{version}",
            id = options.id,
            version = options.version
        ),
    )?;

    Ok(())
}

/// Generate API documentation for the given workspace and compile options.
///
/// It is expected that the current package contains a `package.metadata.component` section.
pub async fn doc(
    config: &Config,
    workspace: Workspace<'_>,
    options: &DocOptions,
    force_generation: bool,
) -> Result<()> {
    encode_workspace_bindings(config, &workspace, force_generation).await?;
    ops::doc(&workspace, options)?;
    Ok(())
}

/// Retrieves workspace metadata for the given workspace and metadata options.
///
/// The returned metadata contains information about generated dependencies.
pub async fn metadata(
    config: &Config,
    workspace: Workspace<'_>,
    options: &OutputMetadataOptions,
) -> Result<ExportInfo> {
    encode_workspace_bindings(config, &workspace, false).await?;
    ops::output_metadata(&workspace, options)
}

/// Check a component for errors with the given workspace and compile options.
pub async fn check(
    config: &Config,
    workspace: Workspace<'_>,
    options: &CompileOptions,
    force_generation: bool,
) -> Result<()> {
    encode_workspace_bindings(config, &workspace, force_generation).await?;
    ops::compile(&workspace, options)?;
    Ok(())
}

/// Update the dependencies in the local lock files.
///
/// This updates both `Cargo.lock` and `Cargo-component.lock`.
pub async fn update_lockfile(
    config: &Config,
    workspace: &Workspace<'_>,
    options: &UpdateOptions<'_>,
) -> Result<()> {
    // First update `Cargo.lock`
    ops::update_lockfile(workspace, options)?;

    // Next read the current lock file and generate a new one
    let map = create_resolution_map(config, workspace, None).await?;
    let orig_lock_file = LockFile::open(config, workspace)?.unwrap_or_default();
    let new_lock_file = LockFile::from_resolution_map(&map);

    // Unlike `cargo`, the lock file doesn't have transitive dependencies
    // So we expect the entries (and the version requirements) to be the same
    // Thus, only "updating" messages get printed for the packages that changed
    for old_pkg in &orig_lock_file.packages {
        let new_pkg_index = new_lock_file
            .packages
            .binary_search_by_key(&old_pkg.key(), LockedPackage::key)
            .expect("locked packages should remain the same");

        let new_pkg = &new_lock_file.packages[new_pkg_index];
        for old_ver in &old_pkg.versions {
            let new_ver_index = new_pkg
                .versions
                .binary_search_by_key(&old_ver.key(), LockedPackageVersion::key)
                .expect("version requirements should remain the same");

            let new_ver = &new_pkg.versions[new_ver_index];
            if old_ver.version != new_ver.version {
                config.shell().status_with_color(
                    "Updating",
                    format!(
                        "component registry package `{id}` v{old} -> v{new}",
                        id = old_pkg.id,
                        old = old_ver.version,
                        new = new_ver.version
                    ),
                    Color::Green,
                )?;
            }
        }
    }

    if options.dry_run {
        options
            .config
            .shell()
            .warn("not updating component lock file due to --dry-run option")?;
    } else {
        new_lock_file.update(config, workspace, &orig_lock_file)?;
    }

    Ok(())
}
