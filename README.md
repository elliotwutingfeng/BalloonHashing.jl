# BalloonHashing.jl

[![Julia](https://img.shields.io/badge/Julia-9558B2?style=for-the-badge&logo=julia&logoColor=white)](https://julialang.org)
[![Coveralls](https://img.shields.io/coverallsCoverage/github/elliotwutingfeng/BalloonHashing.jl?logo=coveralls&style=for-the-badge)](https://coveralls.io/github/elliotwutingfeng/BalloonHashing.jl?branch=main)

[![GitHub license](https://img.shields.io/badge/LICENSE-BSD--3--CLAUSE-GREEN?style=for-the-badge)](LICENSE)

Balloon Hashing implemented in Julia. All credit to Dan Boneh, Henry Corrigan-Gibbs, and Stuart Schechter. For more information see
the [research paper](https://eprint.iacr.org/2016/027.pdf) or their [website](https://crypto.stanford.edu/balloon/) for this project.

This is a direct port of the Python [implementation](https://github.com/nachonavarro/balloon-hashing) by [nachonavarro](https://github.com/nachonavarro).

**Warning:** Please DO NOT use this code in production! It has not been tested rigorously for security vulnerabilities.

## Background

Balloon Hashing is a new hashing function that, according to the paper, is:

* **Built from Standard Primitives:** Builds on top of other common hashing functions.
* **Has Proven Memory-Hardness Properties:** See paper.
* **Resistant to Cache Attacks:** The idea is that an adversary who can observe the memory access patterns of the buffer in the algorithm (for example through cached side-channels) still can't figure out the password being cached.
* **Practical:** Is as good as the best hashing functions used in production today.

## Algorithm

The algorithm consists of three main parts, as explained in the paper.

The first step is the expansion, in which the system fills up a buffer with pseudorandom bytes derived from the password and salt by computing repeatedly the hash function on a combination
of the password and the previous hash.

The second step is mixing, in which the system mixes time_cost number of times the pseudorandom
bytes in the buffer. At each step in the for loop, it updates the nth block to be the hash of the n-1th block, the nth block,
and delta other blocks chosen at random from the buffer.

In the last step, the extraction, the system outputs as the hash the last element in the buffer.

## Usage

```julia
include("src/BalloonHashing.jl")

password = "buildmeupbuttercup"
salt = "JqMcHqUcjinFhQKJ"
BalloonHashing.balloon_hash(password, salt)
# OUTPUT: 2ec8d833db5f88e584ab793950ecfb21657a3816edea8d9e73ea23c13ba2b740

delta = 5
time_cost = 18
space_cost = 24
bytes2hex(BalloonHashing.balloon(password, salt, space_cost, time_cost, delta))
# OUTPUT: 69f86890cef40a7ec5f70daff1ce8e2cde233a15bffa785e7efdb5143af51bfb
```

## Testing

In Julia REPL

```julia
using Pkg
Pkg.activate(".")
Pkg.test("BalloonHashing")
```

## Formatting

In Julia REPL

```julia
using JuliaFormatter
format(".")
```

## References

* [Dart implementation](https://github.com/elliotwutingfeng/balloon_hashing)
* [Kotlin implementation](https://github.com/elliotwutingfeng/balloon-hashing-kotlin)
* [Python implementation](https://github.com/nachonavarro/balloon-hashing)
* [Ruby implementation](https://github.com/elliotwutingfeng/balloon-hashing)
* [Rust implementation](https://crates.io/crates/balloon-hash)
