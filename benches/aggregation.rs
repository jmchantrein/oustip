//! Benchmarks for CIDR aggregation performance.

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use ipnet::IpNet;
use std::hint::black_box;
use std::str::FromStr;

/// Generate random-ish IPv4 addresses for benchmarking
fn generate_ips(count: usize) -> Vec<IpNet> {
    (0..count)
        .map(|i| {
            let a = (i % 256) as u8;
            let b = ((i / 256) % 256) as u8;
            let c = ((i / 65536) % 256) as u8;
            let d = ((i / 16777216) % 256) as u8;
            IpNet::from_str(&format!("{}.{}.{}.{}/32", a, b, c, d)).unwrap()
        })
        .collect()
}

/// Generate CIDRs of varying sizes
fn generate_cidrs(count: usize) -> Vec<IpNet> {
    (0..count)
        .map(|i| {
            let a = (i % 256) as u8;
            let b = ((i / 256) % 256) as u8;
            let prefix = 16 + (i % 17) as u8; // Prefix lengths 16-32
            IpNet::from_str(&format!("{}.{}.0.0/{}", a, b, prefix)).unwrap()
        })
        .collect()
}

fn bench_aggregate(c: &mut Criterion) {
    let mut group = c.benchmark_group("aggregate");

    for size in [100, 1000, 10000, 50000] {
        let ips = generate_ips(size);
        group.bench_with_input(BenchmarkId::new("single_ips", size), &ips, |b, ips| {
            b.iter(|| {
                let v4_nets: Vec<ipnet::Ipv4Net> = ips
                    .iter()
                    .filter_map(|n| match n {
                        IpNet::V4(v4) => Some(*v4),
                        _ => None,
                    })
                    .collect();
                black_box(ipnet::Ipv4Net::aggregate(&v4_nets))
            });
        });

        let cidrs = generate_cidrs(size);
        group.bench_with_input(BenchmarkId::new("mixed_cidrs", size), &cidrs, |b, cidrs| {
            b.iter(|| {
                let v4_nets: Vec<ipnet::Ipv4Net> = cidrs
                    .iter()
                    .filter_map(|n| match n {
                        IpNet::V4(v4) => Some(*v4),
                        _ => None,
                    })
                    .collect();
                black_box(ipnet::Ipv4Net::aggregate(&v4_nets))
            });
        });
    }

    group.finish();
}

fn bench_deduplicate(c: &mut Criterion) {
    let mut group = c.benchmark_group("deduplicate");

    for size in [100, 1000, 10000] {
        // Create list with duplicates
        let mut ips = generate_ips(size);
        ips.extend(ips.clone()); // Double with duplicates

        group.bench_with_input(
            BenchmarkId::new("with_duplicates", size * 2),
            &ips,
            |b, ips| {
                b.iter(|| {
                    let set: std::collections::HashSet<_> = ips.iter().cloned().collect();
                    black_box(set.into_iter().collect::<Vec<_>>())
                });
            },
        );
    }

    group.finish();
}

fn bench_parse_blocklist(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_blocklist");

    // Generate sample blocklist content
    let small_content = (0..100)
        .map(|i| format!("192.168.{}.{}/24\n", i % 256, i / 256))
        .collect::<String>();

    let medium_content = (0..1000)
        .map(|i| {
            format!(
                "{}.{}.{}.{}\n",
                i % 256,
                (i / 256) % 256,
                (i / 65536) % 256,
                0
            )
        })
        .collect::<String>();

    let large_content = (0..10000)
        .map(|i| format!("{}.{}.0.0/16\n", i % 256, (i / 256) % 256))
        .collect::<String>();

    group.bench_function("small_100", |b| {
        b.iter(|| {
            black_box(
                small_content
                    .lines()
                    .filter(|line| !line.starts_with('#') && !line.is_empty())
                    .filter_map(|line| line.trim().parse::<IpNet>().ok())
                    .collect::<Vec<_>>(),
            )
        });
    });

    group.bench_function("medium_1000", |b| {
        b.iter(|| {
            black_box(
                medium_content
                    .lines()
                    .filter(|line| !line.starts_with('#') && !line.is_empty())
                    .filter_map(|line| {
                        let trimmed = line.trim();
                        if trimmed.contains('/') {
                            trimmed.parse::<IpNet>().ok()
                        } else {
                            trimmed.parse::<std::net::IpAddr>().ok().map(IpNet::from)
                        }
                    })
                    .collect::<Vec<_>>(),
            )
        });
    });

    group.bench_function("large_10000", |b| {
        b.iter(|| {
            black_box(
                large_content
                    .lines()
                    .filter(|line| !line.starts_with('#') && !line.is_empty())
                    .filter_map(|line| line.trim().parse::<IpNet>().ok())
                    .collect::<Vec<_>>(),
            )
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_aggregate,
    bench_deduplicate,
    bench_parse_blocklist
);
criterion_main!(benches);
