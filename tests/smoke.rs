use yak::{CreateOptions, EntryType, OpenMode, YakDefault};
use std::fs;

#[test]
fn roundtrip() {
    let path = "test_roundtrip.yak";
    let _ = fs::remove_file(path);

    // Create
    println!("Creating {path}...");
    let yak = YakDefault::create(path, CreateOptions::default()).expect("create failed");

    // Write a stream
    println!("Creating stream hello.txt...");
    let handle = yak.create_stream("hello.txt", false).expect("create_stream failed");
    let written = yak.write(&handle, b"Hello, World!").expect("write failed");
    println!("Wrote {written} bytes");
    yak.close_stream(handle).expect("close_stream failed");

    // Create a directory and a stream inside it
    println!("Creating directory subdir...");
    yak.mkdir("subdir").expect("mkdir failed");
    let handle = yak.create_stream("subdir/nested.txt", false).expect("create nested stream failed");
    yak.write(&handle, b"nested content").expect("write nested failed");
    yak.close_stream(handle).expect("close nested stream failed");

    yak.close().expect("close failed");
    println!("Closed.");

    // Reopen and list
    println!("Reopening...");
    let yak = YakDefault::open(path, OpenMode::Read).expect("open failed");

    println!("Listing root...");
    let entries = yak.list("").expect("list root failed");
    println!("Root entries: {entries:?}");
    for e in &entries {
        println!("  name={:?} type={:?}", e.name, e.entry_type);
        match e.entry_type {
            EntryType::Stream => {
                let h = yak.open_stream(&e.name, OpenMode::Read).expect("open stream");
                let len = yak.stream_length(&h).expect("stream_length");
                println!("    size={len}");
                let mut buf = vec![0u8; len as usize];
                let n = yak.read(&h, &mut buf).expect("read");
                println!("    content={:?}", String::from_utf8_lossy(&buf[..n]));
                yak.close_stream(h).expect("close stream");
            }
            EntryType::Directory => {
                let sub = yak.list(&e.name).expect("list subdir");
                println!("    subdir entries: {sub:?}");
                for se in &sub {
                    let full = format!("{}/{}", e.name, se.name);
                    println!("    sub name={:?} type={:?}", se.name, se.entry_type);
                    if matches!(se.entry_type, EntryType::Stream) {
                        let h = yak.open_stream(&full, OpenMode::Read).expect("open nested");
                        let len = yak.stream_length(&h).expect("nested len");
                        let mut buf = vec![0u8; len as usize];
                        let n = yak.read(&h, &mut buf).expect("read nested");
                        println!("      size={len} content={:?}", String::from_utf8_lossy(&buf[..n]));
                        yak.close_stream(h).expect("close nested");
                    }
                }
            }
        }
    }

    yak.close().expect("close read");
    let _ = fs::remove_file(path);
    println!("All OK!");
}
