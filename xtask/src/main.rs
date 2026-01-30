mod build;
mod build_ebpf;
mod docs_gen;
mod proto_gen;
mod rule_parser_gen;
mod run;
mod tarball;
mod test;
mod vmlinux_gen;

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
    VmlinuxGen(vmlinux_gen::Options),
    DocsGen(docs_gen::Options),
    RuleParserGen(rule_parser_gen::Options),
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
        VmlinuxGen(opts) => vmlinux_gen::vmlinux_gen(opts),
        DocsGen(opts) => docs_gen::docs_gen(opts),
        RuleParserGen(opts) => rule_parser_gen::rule_parser_gen(opts),
    };

    if let Err(e) = ret {
        eprintln!("{e:#}");
        exit(1);
    }
}
