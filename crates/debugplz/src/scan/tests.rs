use super::{
    live::{LiveScanConfig, MemoryReader, ReaderSpec, VmaRegion, build_segments, scan_regions},
    *,
};
use std::collections::BTreeMap;

fn sample() -> Segment {
    Segment {
        module: "fixture".to_owned(),
        segment: ".data".to_owned(),
        start: 0x1000,
        end: 0x1100,
    }
}

#[test]
fn writes_root_to_target_offsets_and_a_direct_root() -> Result<()> {
    let root = sample();
    let segments = [&root];
    let mut output = Vec::new();
    let results = Results::new(&mut output, 64, &segments)?;
    let start = output_header_length(&root);
    let mut search = Search {
        index: &[
            Pointer {
                address: 0x1010,
                value: 0x2000,
            },
            Pointer {
                address: 0x2020,
                value: 0x3000,
            },
        ],
        segments: &segments,
        limits: &[0x8, 0x20],
        negative: false,
        nearest_first: false,
        started: Instant::now(),
        budget: None,
        results,
    };
    assert!(search.walk(
        0x3008,
        &mut Path {
            target: 0x3008,
            ..Default::default()
        }
    )?);
    assert!(search.walk(
        0x1020,
        &mut Path {
            target: 0x1020,
            ..Default::default()
        }
    )?);
    assert_eq!(search.results.finish(true)?, 2);

    let chain = &output[start..];
    assert_eq!(chain[0], 1);
    assert_eq!(u64::from_le_bytes(chain[1..9].try_into()?), 0x3008);
    assert_eq!(u64::from_le_bytes(chain[13..21].try_into()?), 0x10);
    assert_eq!(u16::from_le_bytes(chain[21..23].try_into()?), 2);
    assert_eq!(i64::from_le_bytes(chain[23..31].try_into()?), 0x20);
    assert_eq!(i64::from_le_bytes(chain[31..39].try_into()?), 0x8);
    let direct = &chain[39..];
    assert_eq!(direct[0], 1);
    assert_eq!(u64::from_le_bytes(direct[13..21].try_into()?), 0x20);
    assert_eq!(u16::from_le_bytes(direct[21..23].try_into()?), 0);
    assert_eq!(&direct[23..], &[0, 1, 2, 0, 0, 0, 0, 0, 0, 0]);
    Ok(())
}

fn output_header_length(segment: &Segment) -> usize {
    12 + 4 + segment.module.len() + 4 + segment.segment.len()
}

#[test]
fn closest_offsets_win_in_both_directions() {
    let values = [0, 98, 99, 100, 101, 102, u64::MAX].map(|value| Pointer {
        address: value,
        value,
    });
    let order = |target, limit, negative| {
        candidates(&values, target, limit, negative, true)
            .map(|record| record.value)
            .collect::<Vec<_>>()
    };
    assert_eq!(order(100, 2, true), [100, 99, 101, 98, 102]);
    assert_eq!(order(100, 2, false), [100, 99, 98]);
    assert_eq!(order(0, 1, true), [0]);
    assert_eq!(order(u64::MAX, 1, true), [u64::MAX]);
}

#[test]
fn exhausted_budget_keeps_results_marked_partial() -> Result<()> {
    let mut output = Vec::new();
    let results = Results::new(&mut output, 32, &[])?;
    let mut search = Search {
        index: &[],
        segments: &[],
        limits: &[],
        negative: false,
        nearest_first: false,
        started: Instant::now(),
        budget: Some(Duration::ZERO),
        results,
    };
    let complete = search.walk(3, &mut Path::default())?;
    assert!(!complete);
    assert_eq!(search.results.finish(complete)?, 0);
    assert_eq!(&output[12..], &[0; 10]);
    Ok(())
}

struct MockReader {
    pages: BTreeMap<u64, Vec<u8>>,
}

impl MemoryReader for MockReader {
    fn read_chunk(&mut self, address: u64, buffer: &mut [u8]) -> Result<usize> {
        let data = self.pages.get(&address).context("unmapped mock page")?;
        let n = buffer.len().min(data.len());
        buffer[..n].copy_from_slice(&data[..n]);
        Ok(n)
    }
}

#[test]
fn live_scan_supports_cross_page_step4_and_restricted_regions() -> Result<()> {
    let maps = "\
00001000-00003000 rw-p 00000000 08:01 10 /data/app/libgame.so
00003000-00004000 rw-p 00000000 00:00 0  [anon:.bss]
00004000-00005000 ---p 00000000 00:00 0  [anon:guard]
00005000-00006000 r--p 00000000 00:00 0  [vdso]
";
    let regions = VmaRegion::parse_maps(maps)?;
    let segments = build_segments(&regions, u64::MAX);
    assert_eq!(
        segments,
        vec![
            Segment {
                module: "libgame.so".to_owned(),
                segment: ".data".to_owned(),
                start: 0x1000,
                end: 0x3000,
            },
            Segment {
                module: "libgame.so".to_owned(),
                segment: ".bss".to_owned(),
                start: 0x3000,
                end: 0x4000,
            },
        ]
    );

    let mut page1 = vec![0_u8; 4096];
    let mut page2 = vec![0_u8; 4096];
    let mut guard_page = vec![0_u8; 4096];
    let cross_ptr = 0x3000_u64.to_le_bytes();
    page1[4092..4096].copy_from_slice(&cross_ptr[..4]);
    page2[0..4].copy_from_slice(&cross_ptr[4..]);
    guard_page[0..8].copy_from_slice(&0x4020_u64.to_le_bytes());

    let mut reader = MockReader {
        pages: BTreeMap::from([
            (0x1000, page1),
            (0x2000, page2),
            (0x3000, vec![0_u8; 4096]),
            (0x4000, guard_page),
        ]),
    };

    let targets = [0x4020_u64];
    let base_cfg = LiveScanConfig {
        pid: 1,
        max_address: u64::MAX,
        width: 8,
        align4: false,
        cross_page_step4: false,
        pagemap: false,
        restricted: false,
        value_margin: 0x100,
        targets: &targets,
    };
    let snap_default = scan_regions(&base_cfg, &regions, &mut reader, None)?;
    assert!(snap_default.pointers.is_empty());

    let step4_cfg = LiveScanConfig {
        cross_page_step4: true,
        restricted: true,
        ..base_cfg
    };
    let snap_adv = scan_regions(&step4_cfg, &regions, &mut reader, None)?;
    assert_eq!(
        snap_adv.pointers,
        vec![
            Pointer {
                address: 0x1ffc,
                value: 0x3000,
            },
            Pointer {
                address: 0x4000,
                value: 0x4020,
            },
        ]
    );
    Ok(())
}

#[test]
fn reader_spec_and_module_range_filters_parse_correctly() -> Result<()> {
    assert_eq!("syscall".parse::<ReaderSpec>()?, ReaderSpec::Syscall);
    assert_eq!("pread".parse::<ReaderSpec>()?, ReaderSpec::Pread);
    assert_eq!(
        "custom:libreader.so".parse::<ReaderSpec>()?,
        ReaderSpec::Custom(PathBuf::from("libreader.so"))
    );
    assert_eq!(
        "/data/local/tmp/libreader.so".parse::<ReaderSpec>()?,
        ReaderSpec::Custom(PathBuf::from("/data/local/tmp/libreader.so"))
    );
    assert!("invalid_reader".parse::<ReaderSpec>().is_err());

    let segs = vec![Segment {
        module: "libgame.so".to_owned(),
        segment: ".data".to_owned(),
        start: 0x1000,
        end: 0x2000,
    }];
    let clipped = Segment::select_roots(
        &segs,
        &[
            "libgame.so:0x1200-0x1800".to_owned(),
            "0x5000-0x6000".to_owned(),
        ],
    )?;
    assert_eq!(clipped.len(), 2);
    assert_eq!((clipped[0].start, clipped[0].end), (0x1200, 0x1800));
    assert_eq!((clipped[1].start, clipped[1].end), (0x5000, 0x6000));
    Ok(())
}
