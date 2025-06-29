mod build;
mod build_ebpf;
mod proto_gen;
mod run;
mod tarball;
mod test;

use std::process::exit;

use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    BuildEbpf(build_ebpf::Options),
    Build(build::Options),
    ProtoGen(proto_gen::Options),
    Run(run::Options),
    Test(test::Options),
    Tarball(tarball::Options),
}

fn main() {
    let opts = Options::parse();

    use Command::*;
    let ret = match opts.command {
        BuildEbpf(opts) => build_ebpf::build_ebpf(opts),
        ProtoGen(opts) => proto_gen::proto_gen(opts),
        Run(opts) => run::run(opts),
        Build(opts) => build::build(opts),
        Test(opts) => test::test(opts),
        Tarball(opts) => tarball::tarball(opts),
    };

    if let Err(e) = ret {
        eprintln!("{e:#}");
        exit(1);
    }
}
