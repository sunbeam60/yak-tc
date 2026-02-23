use yak::{OpenMode, YakDefault};

#[test]
fn open_testfile() {
    let path = r"C:\Users\bjorn\Code\testfile.yak";
    println!("Opening {path}...");
    let yak = YakDefault::open(path, OpenMode::Read).expect("open failed");

    println!("Listing root...");
    let entries = yak.list("").expect("list root failed");
    println!("Found {} root entries", entries.len());
    for (i, e) in entries.iter().enumerate().take(20) {
        println!("  [{i}] name={:?} type={:?}", e.name, e.entry_type);
    }
    if entries.len() > 20 {
        println!("  ... and {} more", entries.len() - 20);
    }

    yak.close().expect("close");
    println!("OK");
}
