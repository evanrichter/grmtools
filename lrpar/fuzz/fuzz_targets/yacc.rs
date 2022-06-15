#![no_main]
use libfuzzer_sys::fuzz_target;

use std::fs::File;
use std::io::{Seek, SeekFrom, Write};
use std::os::unix::io::AsRawFd;

use cfgrammar::yacc::{YaccKind, YaccOriginalActionKind};
use lrlex::CTLexerBuilder;
use lrpar::RecoveryKind;

fuzz_target!(|data: (&str, &str, u8)| {
    if data.0.len() < 4 && data.1.len() < 4 {
        return;
    }

    let (_file, grammar_path) = match create_in_memory_file(data.0.as_bytes()) {
        Ok(x) => x,
        Err(_) => return,
    };

    let (_file, lexer_path) = match create_in_memory_file(data.1.as_bytes()) {
        Ok(x) => x,
        Err(_) => return,
    };

    let yacckind = match data.2 & 0b11 {
        0 => YaccKind::Original(YaccOriginalActionKind::NoAction),
        1 => YaccKind::Original(YaccOriginalActionKind::UserAction),
        2 => YaccKind::Original(YaccOriginalActionKind::GenericParseTree),
        _ => YaccKind::Grmtools,
    };

    let recoverykind = match (data.2 >> 2) & 1 {
        0 => RecoveryKind::CPCTPlus,
        _ => RecoveryKind::None,
    };

    let _ = CTLexerBuilder::new()
        .lrpar_config(move |ctp| {
            ctp.yacckind(yacckind)
                .grammar_path(grammar_path.as_str())
                .output_path("/dev/null")
                .recoverer(recoverykind)
        })
        .lexer_path(lexer_path)
        .output_path("/dev/null")
        .allow_missing_terms_in_lexer(true)
        .allow_missing_tokens_in_parser(true)
        .build();
});

fn create_in_memory_file(contents: &[u8]) -> Result<(File, String), ()> {
    let mfd = memfd::MemfdOptions::default()
        .create("fuzz-file")
        .map_err(|_| ())?;

    let fd = mfd.as_raw_fd();
    let filepath = format!("/proc/self/fd/{fd}");

    let mut file = mfd.into_file();
    if file.write_all(contents).is_err() {
        println!("could not write to memfd file!");
        return Err(());
    }

    if file.seek(SeekFrom::Start(0)).is_err() {
        println!("failed to seek!");
        return Err(());
    }

    Ok((file, filepath))
}
