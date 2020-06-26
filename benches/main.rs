// Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE-BSD-3-Clause file.
//
// SPDX-License-Identifier: Apache-2.0 AND BSD-3-Clause
//#![cfg(feature = "backend-mmap")]

extern crate criterion;
extern crate vm_memory;

use std::fs::File;
use std::io::Cursor;
use std::path::Path;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[cfg(feature = "backend-mmap")]
use vm_memory::GuestMemoryMmap;
use vm_memory::{ByteValued, Bytes, GuestAddress, GuestMemory, GuestMemoryError};

/// Result of guest memory operations.
pub type Result<T> = std::result::Result<T, GuestMemoryError>;

#[cfg(feature = "backend-mmap")]
fn make_image(size: usize) -> Vec<u8> {
    let mut image: Vec<u8> = Vec::with_capacity(size as usize);
    for i in 0..size {
        // We just want some different numbers here, so the conversion is OK.
        image.push(i as u8);
    }
    image
}

#[cfg(feature = "backend-mmap")]
/// Reads up to `count` bytes.
fn read_bytes_from<M: GuestMemory>(
    memory: &M,
    offset: GuestAddress,
    image: &Vec<u8>,
    count: usize,
) -> Result<usize> {
    memory.read_from(offset, &mut Cursor::new(&image), count)
}

#[cfg(feature = "backend-mmap")]
/// Reads up to `count` bytes from a file.
fn read_bytes_from_file<M: GuestMemory>(
    memory: &M,
    offset: GuestAddress,
    image: &mut File,
    count: usize,
) -> Result<usize> {
    memory.read_from(offset, image, count)
}

#[cfg(feature = "backend-mmap")]
/// Reads exact `count` bytes.
fn read_exact_bytes_from<M: GuestMemory>(
    memory: &M,
    offset: GuestAddress,
    image: &Vec<u8>,
    count: usize,
) -> Result<()> {
    memory.read_exact_from(offset, &mut Cursor::new(&image), count)
}

#[cfg(feature = "backend-mmap")]
/// Reads a slice. Returns error if there isn't enough data to fill the whole buffer.
fn read_slice_from<M: GuestMemory>(
    memory: &M,
    offset: GuestAddress,
    slice: &mut [u8],
) -> Result<()> {
    memory.read_slice(slice, offset)
}

#[cfg(feature = "backend-mmap")]
/// Reads some <T> obj.
fn read_obj<M: GuestMemory, T: ByteValued>(memory: &M, offset: GuestAddress) -> Result<T> {
    memory.read_obj::<T>(offset)
}

#[cfg(feature = "backend-mmap")]
/// Reads data into a slice.
fn read<M: GuestMemory>(memory: &M, offset: GuestAddress, slice: &mut [u8]) -> Result<usize> {
    memory.read(slice, offset)
}

#[cfg(feature = "backend-mmap")]
/// Writes up to `count` bytes.
fn write_bytes_to<M: GuestMemory>(
    memory: &M,
    offset: GuestAddress,
    image: &mut Vec<u8>,
    count: usize,
) -> Result<usize> {
    memory.write_to(offset, &mut Cursor::new(image), count)
}

#[cfg(feature = "backend-mmap")]
/// Writes up to `count` bytes from a file.
fn write_bytes_to_file<M: GuestMemory>(
    memory: &M,
    offset: GuestAddress,
    image: &mut File,
    count: usize,
) -> Result<usize> {
    memory.write_to(offset, image, count)
}

#[cfg(feature = "backend-mmap")]
/// Writes exact `count` bytes.
fn write_exact_bytes_to<M: GuestMemory>(
    memory: &M,
    offset: GuestAddress,
    image: &mut Vec<u8>,
    count: usize,
) -> Result<()> {
    memory.write_all_to(offset, &mut Cursor::new(image), count)
}

#[cfg(feature = "backend-mmap")]
/// Writes a slice. Returns error if there isn't enough data to fill the whole buffer.
fn write_slice_to<M: GuestMemory>(
    memory: &M,
    offset: GuestAddress,
    slice: &mut [u8],
) -> Result<()> {
    memory.write_slice(slice, offset)
}

#[cfg(feature = "backend-mmap")]
/// Writes some <T> obj.
fn write_obj<M: GuestMemory, T: ByteValued>(
    memory: &M,
    offset: GuestAddress,
    value: T,
) -> Result<()> {
    memory.write_obj::<T>(value, offset)
}

#[cfg(feature = "backend-mmap")]
/// Writes a slice.
fn write<M: GuestMemory>(memory: &M, offset: GuestAddress, slice: &mut [u8]) -> Result<usize> {
    memory.write(slice, offset)
}

pub fn criterion_benchmark(c: &mut Criterion) {
    #[cfg(feature = "backend-mmap")]
    {
        let start_addr1 = GuestAddress(0x0);
        let start_addr2 = GuestAddress(0x1000);
        let start_addr3 = GuestAddress(0x2100);
        let start_addr4 = GuestAddress(0x3100);
        let mem = GuestMemoryMmap::from_ranges(&[
            (start_addr1, 0x1000 as usize),
            (start_addr2, 0x1000 as usize),
            (start_addr3, 0x1000 as usize),
            (start_addr4, 0x1000 as usize),
        ])
        .unwrap();
        assert_eq!(mem.last_addr(), GuestAddress(0x3FFF));

        let mut image = make_image(0x200);
        let mut offsets = vec![
            GuestAddress(0x100),
            // offset that will involve reading/writing from 2 regions.
            GuestAddress(0xF00),
            // offset that will involve (trying) reading/writing from 2 regions
            // (with a hole between them).
            GuestAddress(0x1F00),
        ];
        let count: usize = 0x200;
        let buf = &mut [0u8; 0x200 as usize];
        let mut file = File::open(Path::new("/dev/urandom")).unwrap();
        let mut file_to_write = File::create("foo.txt").unwrap();

        // Here comes an ugly loop :).
        for offset in offsets.iter() {
            // Read stuff.
            c.bench_function(format!("read_from_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| black_box(read_bytes_from(&mem, *offset, &image, count).unwrap()))
            });
            c.bench_function(format!("read_from_file_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| black_box(read_bytes_from_file(&mem, *offset, &mut file, count).unwrap()))
            });

            // It would probably make sense to measure this for other data types too.
            c.bench_function(format!("read_obj_from_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| black_box(read_obj::<_, u8>(&mem, *offset).unwrap()))
            });

            c.bench_function(format!("read_slice_from_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| black_box(read(&mem, *offset, buf).unwrap()))
            });

            // Write stuff.
            c.bench_function(format!("write_to_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| black_box(write_bytes_to(&mem, *offset, &mut image, count).unwrap()))
            });
            c.bench_function(format!("write_to_file_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| {
                    black_box(
                        write_bytes_to_file(&mem, *offset, &mut file_to_write, count).unwrap(),
                    )
                })
            });

            c.bench_function(format!("write_obj_to_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| black_box(write_obj::<_, u8>(&mem, *offset, 0x11).unwrap()))
            });

            c.bench_function(format!("write_slice_to_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| black_box(write(&mem, *offset, buf).unwrap()))
            });
        }

        // Remove the last offset because the functions in the next loop panic if they can't fill
        // the entire buffer.
        offsets.pop();

        // Here comes another ugly loop, but this time a shorter one.
        for offset in offsets.iter() {
            c.bench_function(format!("read_exact_from_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| black_box(read_exact_bytes_from(&mem, *offset, &image, count).unwrap()))
            });

            c.bench_function(
                format!("read_entire_slice_from_{:#0x}", offset.0).as_str(),
                |b| b.iter(|| black_box(read_slice_from(&mem, *offset, buf).unwrap())),
            );

            c.bench_function(format!("write_exact_to_{:#0x}", offset.0).as_str(), |b| {
                b.iter(|| {
                    black_box(write_exact_bytes_to(&mem, *offset, &mut image, count).unwrap())
                })
            });

            c.bench_function(
                format!("write_entire_slice_to_{:#0x}", offset.0).as_str(),
                |b| b.iter(|| black_box(write_slice_to(&mem, *offset, buf).unwrap())),
            );
        }
    }
}

criterion_group! {
    name = benches;
    config = Criterion::default().sample_size(200).measurement_time(std::time::Duration::from_secs(50));
    targets = criterion_benchmark
}

criterion_main! {
    benches,
}
