use std::{
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
};
use tgc_demo::{
    Result, audit, ensure,
    protocol::{Discovery, RecipientPolicy, Topology},
    scenario::{self, Composition, Config, Report},
    store::Host,
};

fn help() {
    println!(
        "TGC flat Rust demo\n\n  tgc-demo run [--out runs/demo] [--topology constitutive|control]\n               [--composition fork|reuse] [--downstream indeterminate|honour|refuse]\n               [--newcomer-seed arbitrary-value] [--json]\n  tgc-demo matrix [--out runs/matrix]\n  tgc-demo verify RUN\n  tgc-demo inspect RUN [HASH | stub:INDEX | queue | --interactive]\n  tgc-demo replay RUN BEAT [--out NEW_RUN]\n  tgc-demo recover RUN\n\nBeats: constitution, 1a, 2a, 2b, 3a, 3b, 3c, close.\nRuns locally with simulated Proof of Honesty and JSON records."
    );
}
fn flag(args: &[String], key: &str) -> Result<Option<String>> {
    if let Some(i) = args.iter().position(|a| a == key) {
        Ok(Some(
            args.get(i + 1)
                .filter(|s| !s.starts_with("--"))
                .ok_or_else(|| format!("{key} requires a value"))?
                .clone(),
        ))
    } else {
        Ok(None)
    }
}
fn read_events(root: &Path, name: &str) -> Result<Vec<audit::Event>> {
    fs::read_to_string(root.join(name))?
        .lines()
        .map(|s| Ok(serde_json::from_str(s)?))
        .collect()
}
fn verify(root: &Path) -> Result<()> {
    tgc_demo::local_audit::verify_run(root)?;
    println!(
        "Verified local decisions, receipts, evidence, records, queues, mock effects, report metrics and semantic export. PoH assurance remains supplied by its verification boundary."
    );
    Ok(())
}

fn inspect(root: &Path, query: &str) -> Result<()> {
    if query == "queue" {
        for name in ["primary", "peer"] {
            println!(
                "{name}: {}",
                serde_json::to_string_pretty(
                    &Host::open_existing(root.join(name))?.state()?.queue
                )?
            );
        }
        return Ok(());
    }
    let discovery: Discovery = serde_json::from_slice(&fs::read(root.join("discovery.json"))?)?;
    if let Some(index) = query.strip_prefix("stub:") {
        let stub = discovery
            .stubs
            .get(index.parse::<usize>()?)
            .ok_or("stub index out of range")?;
        println!(
            "{}",
            serde_json::to_string_pretty(
                &serde_json::json!({"stub":stub,"governance_hash":stub.governance_hash(),"seat":discovery.seats.get(&stub.commitment_ref),"commitment":discovery.inspect(stub)?,"interpretation":discovery.resolve(&stub.rulebook_id,&stub.rule_interpretation_hash)?,"moderators":discovery.moderators,"revocation_epoch":discovery.revocation_epoch})
            )?
        );
    } else if query.is_empty() || query == "stubs" {
        println!("{}", serde_json::to_string_pretty(&discovery)?);
    } else {
        for name in ["primary", "peer"] {
            let state = Host::open_existing(root.join(name))?.state()?;
            if let Some(value) = state.objects.get(query) {
                println!("{}", serde_json::to_string_pretty(value)?);
                return Ok(());
            }
            if let Some(record) = state.records.get(query) {
                println!("{}", serde_json::to_string_pretty(record)?);
                return Ok(());
            }
        }
        return Err("unknown hash or proposal ID".into());
    }
    Ok(())
}
fn summary(report: &Report, out: &Path) {
    println!(
        "Settlement demo — {:?} / {:?} / {:?}\n",
        report.config.topology, report.config.composition, report.config.downstream
    );
    println!("I   Parties choose and constitute a path. Ordinary settlement: Permitted.");
    println!(
        "II  The optimal venue shortcut is Prevented. The exception requires approval,
    then proceeds under its proof producer's explicit accountability."
    );
    println!(
        "III A newcomer reads public stubs, obtains a qualifying credential and acts.
    Composition: {:?}. Independent recipient: {:?}.",
        report.config.composition, report.config.downstream
    );
    println!(
        "\nAll four outcomes exercised: {}. Unresolved queue items: {}.\nArtifacts: {}\n\n{}",
        report.all_four_outcomes,
        report.pending_queue_items,
        out.display(),
        report.finale
    );
}
fn main() {
    if let Err(error) = execute() {
        eprintln!("Error: {error}");
        std::process::exit(1);
    }
}
fn execute() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(command) = args.first().map(String::as_str) else {
        help();
        return Ok(());
    };
    match command {
        "help" | "--help" | "-h" => help(),
        "run" => {
            let mut config = Config::default();
            if let Some(v) = flag(&args, "--topology")? {
                config.topology = match v.as_str() {
                    "control" => Topology::Control,
                    "constitutive" => Topology::Constitutive,
                    _ => return Err("unknown topology".into()),
                };
            }
            if let Some(v) = flag(&args, "--composition")? {
                config.composition = match v.as_str() {
                    "reuse" => Composition::Reuse,
                    "fork" => Composition::Fork,
                    _ => return Err("unknown composition".into()),
                };
            }
            if let Some(v) = flag(&args, "--downstream")? {
                config.downstream = match v.as_str() {
                    "refuse" => RecipientPolicy::Refuse,
                    "honour" => RecipientPolicy::Honour,
                    "indeterminate" => RecipientPolicy::Unresolved,
                    _ => return Err("unknown downstream policy".into()),
                };
            }
            if let Some(v) = flag(&args, "--newcomer-seed")? {
                config.newcomer_seed = v;
            }
            let out = PathBuf::from(flag(&args, "--out")?.unwrap_or("runs/demo".into()));
            let report = scenario::run(&out, config)?;
            if args.iter().any(|a| a == "--json") {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                summary(&report, &out);
            }
        }
        "matrix" => {
            let out = PathBuf::from(flag(&args, "--out")?.unwrap_or("runs/matrix".into()));
            let mut reports = Vec::new();
            for topology in [Topology::Control, Topology::Constitutive] {
                for composition in [Composition::Reuse, Composition::Fork] {
                    for downstream in [
                        RecipientPolicy::Refuse,
                        RecipientPolicy::Honour,
                        RecipientPolicy::Unresolved,
                    ] {
                        let name =
                            format!("{topology:?}-{composition:?}-{downstream:?}").to_lowercase();
                        let report = scenario::run(
                            &out.join(&name),
                            Config {
                                topology,
                                composition,
                                downstream,
                                ..Config::default()
                            },
                        )?;
                        println!("{name}: complete");
                        reports.push(report);
                    }
                }
            }
            fs::write(
                out.join("comparison.json"),
                serde_json::to_vec_pretty(&reports)?,
            )?;
            println!(
                "All 12 combinations completed. Comparison: {}",
                out.join("comparison.json").display()
            );
        }
        "verify" => verify(Path::new(
            args.get(1).ok_or("verify requires run directory")?,
        ))?,
        "inspect" => {
            let root = Path::new(args.get(1).ok_or("inspect requires run directory")?);
            if args.iter().any(|a| a == "--interactive") {
                println!("Inspect: stubs | stub:INDEX | HASH | PROPOSAL_ID | queue | quit");
                loop {
                    print!("> ");
                    io::stdout().flush()?;
                    let mut line = String::new();
                    if io::stdin().read_line(&mut line)? == 0 || line.trim() == "quit" {
                        break;
                    }
                    if let Err(e) = inspect(root, line.trim()) {
                        println!("{e}");
                    }
                }
            } else {
                inspect(root, args.get(2).map(String::as_str).unwrap_or(""))?;
            }
        }
        "replay" => {
            let root = Path::new(args.get(1).ok_or("replay requires run directory")?);
            let beat = args.get(2).ok_or("replay requires beat")?;
            ensure(
                ["constitution", "1a", "2a", "2b", "3a", "3b", "3c", "close"]
                    .contains(&beat.as_str()),
                "unknown beat",
            )?;
            let report: Report = serde_json::from_slice(&fs::read(root.join("report.json"))?)?;
            let out = flag(&args, "--out")?
                .map(PathBuf::from)
                .unwrap_or_else(|| root.join(format!("replay-{beat}")));
            tgc_demo::local_audit::verify_run(root)?;
            scenario::run(&out, report.config)?;
            tgc_demo::local_audit::verify_run(&out)?;
            let original = serde_json::from_slice(&fs::read(root.join("semantic.json"))?)?;
            let repeated = serde_json::from_slice(&fs::read(out.join("semantic.json"))?)?;
            ensure(
                audit::replay_semantics(original) == audit::replay_semantics(repeated),
                "replayed decisions/events differ",
            )?;
            for file in ["events.jsonl", "peer-events.jsonl"] {
                for event in read_events(&out, file)? {
                    if event.beat == *beat {
                        println!("{}", serde_json::to_string(&event)?);
                    }
                }
            }
        }
        "recover" => {
            let root = Path::new(args.get(1).ok_or("recover requires run directory")?);
            ensure(root.join("primary").is_dir(), "missing primary store")?;
            for name in ["primary", "peer"] {
                // A crash can precede creation of the independent peer. Skip an
                // absent peer directory, but never recreate a partial store.
                if name == "peer" && !root.join(name).exists() {
                    continue;
                }
                let host = Host::open_existing(root.join(name))?;
                println!(
                    "{name}: {} attempts recovered using original replay IDs",
                    if host.state()?.field_bootstrap.is_some() {
                        tgc_demo::protocol::Field::recover_host(&host)?.len()
                    } else {
                        host.recover()?.len()
                    }
                );
                if host.state()?.field_bootstrap.is_some() {
                    tgc_demo::protocol::Field::reopen(&root.join(name))?;
                }
                scenario::export_events(
                    &root.join(if name == "primary" {
                        "events.jsonl"
                    } else {
                        "peer-events.jsonl"
                    }),
                    &host.state()?.events,
                )?;
            }
        }
        _ => return Err("unknown command; use --help".into()),
    }
    Ok(())
}
