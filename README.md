# umami-analyzer

## install (rust)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh


## route analyze
cargo run --bin route

## mouse entropy analyze
cargo run --bin entropy

# ip check
## 1. build (tag: sqlite-viewer)
docker build -t sqlite-viewer .

## 2. run (prepare ../udgardb_v3.dat first)
docker run --rm -d \
  -p 8080:8080 \
  -v $(pwd)/../udgardb_v3.dat:/data/udgardb_v3.dat \
  --name my-sqlite-viewer \
  sqlite-viewer

## search
cargo run --bin udger -- 8.8.8.8

