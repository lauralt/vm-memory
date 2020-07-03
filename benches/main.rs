// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//#![cfg(feature = "backend-mmap")]

extern crate criterion;
extern crate vm_memory;
extern crate vmm_sys_util;

use std::fs::File;
use std::io::Cursor;
use std::path::Path;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[cfg(feature = "backend-mmap")]
use vm_memory::GuestMemoryMmap;
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryError};
use vmm_sys_util::tempfile::TempFile;

const REGION_SIZE: u64 = 0x8000_0000;
const REGIONS_COUNT: u64 = 8;
const ACCESS_SIZE: usize = 0x200;

/// Result of guest memory operations.
pub type Result<T> = std::result::Result<T, GuestMemoryError>;

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct SmallDummy {
    a: u32,
    b: u32,
}
unsafe impl ByteValued for SmallDummy {}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct BigDummy {
    elements: [u64; 8],
}

unsafe impl ByteValued for BigDummy {}

#[cfg(feature = "backend-mmap")]
fn make_image(size: usize) -> Vec<u8> {
    let mut image: Vec<u8> = Vec::with_capacity(size as usize);
    for i in 0..size {
        // We just want some different numbers here, so the conversion is OK.
        image.push(i as u8);
    }
    image
}

pub fn criterion_benchmark(c: &mut Criterion) {
    #[cfg(feature = "backend-mmap")]
    {
        let mut regions: Vec<(GuestAddress, usize)> = Vec::with_capacity(REGIONS_COUNT as usize);
        for i in 0..REGIONS_COUNT {
            regions.push((GuestAddress(i * REGION_SIZE), REGION_SIZE as usize));
        }
        assert_eq!(regions.len() as u64, REGIONS_COUNT);

        let memory = GuestMemoryMmap::from_ranges(regions.as_slice()).unwrap();
        assert_eq!(
            memory.last_addr(),
            GuestAddress(REGION_SIZE * REGIONS_COUNT - 0x01)
        );

        let mut image = make_image(ACCESS_SIZE);
        let offsets = [
            GuestAddress(ACCESS_SIZE as u64 / 2),
            // offset that will involve reading/writing from the first 2 regions.
            GuestAddress(REGION_SIZE - ACCESS_SIZE as u64 / 2),
            // offset that will involve reading/writing from the last 2 regions.
            GuestAddress(REGION_SIZE * (REGIONS_COUNT - 1) - ACCESS_SIZE as u64 / 2),
        ];
        let buf = &mut [0u8; ACCESS_SIZE];
        let mut file = File::open(Path::new("/dev/urandom")).unwrap();
        let temp = TempFile::new().unwrap();
        let mut file_to_write = temp.as_file();

        // Here comes an ugly loop :).
        for offset in offsets.iter() {
            // Read stuff.
            c.bench_function(format!("read_from_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| {
                    black_box(
                        memory
                            .read_from(*offset, &mut Cursor::new(&image), ACCESS_SIZE)
                            .unwrap(),
                    )
                })
            });
            c.bench_function(format!("read_from_file_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| black_box(memory.read_from(*offset, &mut file, ACCESS_SIZE).unwrap()))
            });
            c.bench_function(format!("read_exact_from_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| {
                    black_box(
                        memory
                            .read_exact_from(*offset, &mut Cursor::new(&mut image), ACCESS_SIZE)
                            .unwrap(),
                    )
                })
            });
            c.bench_function(
                format!("read_entire_slice_from_{:#0x}", offset.0).as_str(),
                |b| b.iter(|| black_box(memory.read_slice(buf, *offset).unwrap())),
            );
            c.bench_function(format!("read_slice_from_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| black_box(memory.read(buf, *offset).unwrap()))
            });

            // Write stuff.
            c.bench_function(format!("write_to_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| {
                    black_box(
                        memory
                            .write_to(*offset, &mut Cursor::new(&mut image), ACCESS_SIZE)
                            .unwrap(),
                    )
                })
            });
            c.bench_function(format!("write_to_file_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| {
                    black_box(
                        memory
                            .write_to(*offset, &mut file_to_write, ACCESS_SIZE)
                            .unwrap(),
                    )
                })
            });
            c.bench_function(format!("write_exact_to_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| {
                    black_box(
                        memory
                            .write_all_to(*offset, &mut Cursor::new(&mut image), ACCESS_SIZE)
                            .unwrap(),
                    )
                })
            });
            c.bench_function(
                format!("write_entire_slice_to_{:#0x}", offset.0).as_str(),
                |b| b.iter(|| black_box(memory.write_slice(buf, *offset).unwrap())),
            );
            c.bench_function(format!("write_slice_to_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| black_box(memory.write(buf, *offset).unwrap()))
            });
        }
    }
}

pub fn criterion_benchmark_2(c: &mut Criterion) {
    #[cfg(feature = "backend-mmap")]
    {
        let mut regions: Vec<(GuestAddress, usize)> = Vec::with_capacity(REGIONS_COUNT as usize);
        for i in 0..REGIONS_COUNT {
            regions.push((GuestAddress(i * REGION_SIZE), REGION_SIZE as usize));
        }
        assert_eq!(regions.len() as u64, REGIONS_COUNT);

        let memory = GuestMemoryMmap::from_ranges(regions.as_slice()).unwrap();
        assert_eq!(
            memory.last_addr(),
            GuestAddress(REGION_SIZE * REGIONS_COUNT - 0x01)
        );

        // Here comes some duplicate code but it got weird when I tried to switch to a loop.
        // Will return to it.
        let small_size = std::mem::size_of::<SmallDummy>();

        let some_small_dummy = SmallDummy {
            a: 0x1111_2222,
            b: 0x3333_4444,
        };

        let mut offsets_for_obj = [
            GuestAddress(ACCESS_SIZE as u64 / 2),
            // offset that will involve reading/writing from the first 2 regions.
            GuestAddress(REGION_SIZE - small_size as u64 / 2),
            // offset that will involve reading/writing from the last 2 regions.
            GuestAddress(REGION_SIZE * (REGIONS_COUNT - 1) - small_size as u64 / 2),
        ];

        for offset in offsets_for_obj.iter() {
            c.bench_function(format!("read_obj_from_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| black_box(memory.read_obj::<SmallDummy>(*offset).unwrap()))
            });
            c.bench_function(format!("write_obj_to_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| {
                    black_box(
                        memory
                            .write_obj::<SmallDummy>(some_small_dummy, *offset)
                            .unwrap(),
                    )
                })
            });
        }

        let big_size = std::mem::size_of::<BigDummy>();

        let some_big_dummy = BigDummy {
            elements: [0x1111_2222_3333_4444; 8],
        };

        offsets_for_obj = [
            GuestAddress(ACCESS_SIZE as u64 / 2),
            // offset that will involve reading/writing from the first 2 regions.
            GuestAddress(REGION_SIZE - big_size as u64 / 2),
            // offset that will involve reading/writing from the last 2 regions.
            GuestAddress(REGION_SIZE * (REGIONS_COUNT - 1) - big_size as u64 / 2),
        ];

        for offset in offsets_for_obj.iter() {
            c.bench_function(format!("read_obj_from_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| black_box(memory.read_obj::<BigDummy>(*offset).unwrap()))
            });
            c.bench_function(format!("write_obj_to_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| {
                    black_box(
                        memory
                            .write_obj::<BigDummy>(some_big_dummy, *offset)
                            .unwrap(),
                    )
                })
            });
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(200).measurement_time(std::time::Duration::from_secs(5));
    targets = criterion_benchmark, criterion_benchmark_2
}

criterion_main! {
    benches,
}
