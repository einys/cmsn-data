# umami-analyzer

## install (rust)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

## route analyze
- note: this analysis targets the file named `umami_raw_backup.sql`
1. run `cargo run --bin route`
2. check the result `output/route`

## mouse entropy analyze
- note: this analysis targets the file named `umami_raw_backup.sql`
1. run `cargo run --bin entropy`
2. check the result `output/entropy`

## ip analyze
1. prepare `../udgardb_v3.dat` file. This is a sqllite database file from udgerdb, contains known crawler ips, etc.
2. run `cargo run --bin udger`
3. check the result `output/udger`



## repository architecture
```
.
├── bot_scenarios.csv
├── Cargo.lock
├── Cargo.toml
├── output                  # analysis results
├── README.md
├── src
│   └── bin                 # analysis core logic
├── target
└── umami_raw_backup.sql    # analysis target data
```
