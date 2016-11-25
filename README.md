# Commit Log

Commit log library for rust. It is intended to be used in various higher-level distributed abstractions on top
of a distributed log.

```rust
extern crate commitlog;

use commitlog::*;

fn main() {
    let opts = LogOptions::new("log");
    let mut log = CommitLog::new(opts).unwrap();

    // append to the log
    log.append(b"hello world").unwrap(); // offset 0
    log.append(b"second message").unwrap(); // offset 1

    // read the messages
    let messages = log.read(ReadPosition::Beginning, ReadLimit::Messages(2)).unwrap();
    for msg in messages {
        println!("{} - {}", msg.offset(), String::from_utf8_lossy(msg.payload()));
    }

    // prints:
    //    0 - hello world
    //    1 - second message
}

```

## Prior Art
* [Apache Kafka](https://kafka.apache.org/)
* [Jocko](https://github.com/travisjeffery/jocko) + [EXCELLENT Blog Post](https://medium.com/the-hoard/how-kafkas-storage-internals-work-3a29b02e026)
