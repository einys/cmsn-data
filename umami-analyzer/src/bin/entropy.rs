use flate2::read::GzDecoder;
use plotters::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::f64::consts::PI;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};

#[derive(Deserialize, Serialize, Debug, Clone)]
struct Position {
    x: f64,
    y: f64,
    #[serde(rename = "timeOffset")]
    time_offset: i64,
}

#[derive(Deserialize, Debug)]
struct EventData {
    source: Option<i32>,
    positions: Option<Vec<Position>>,
}

#[derive(Deserialize, Debug)]
struct ReplayEvent {
    #[serde(rename = "type")]
    event_type: i32,
    data: EventData,
}

struct VisitGroup {
    positions: Vec<Position>,
}

fn calculate_mouse_entropy(positions: &[Position]) -> f64 {
    if positions.len() < 2 {
        return 0.0;
    }

    let mut bins = [0_usize; 8];
    let mut valid_angles = 0;

    // .windows(2)를 사용하여 Vec 추가 할당 없이 한 번의 순회로 처리
    for window in positions.windows(2) {
        let dx = window[1].x - window[0].x;
        let dy = window[1].y - window[0].y;

        if dx == 0.0 && dy == 0.0 {
            continue;
        }

        let angle = dy.atan2(dx);
        let norm_angle = angle + PI;
        let mut bin_idx = (norm_angle / (PI / 4.0)).floor() as usize;

        if bin_idx >= 8 {
            bin_idx = 7;
        }

        bins[bin_idx] += 1;
        valid_angles += 1;
    }

    if valid_angles == 0 {
        return 0.0;
    }

    let total = valid_angles as f64;

    bins.into_iter()
        .filter(|&count| count > 0)
        .map(|count| {
            let p = count as f64 / total;
            -p * p.log2()
        })
        .sum()
}

fn decompress_umami_replay(raw_str: &str) -> Option<String> {
    let bytes = hex::decode(raw_str).ok()?;
    let mut decoder = GzDecoder::new(&bytes[..]);
    let mut json_string = String::new();

    decoder.read_to_string(&mut json_string).ok()?;
    Some(json_string)
}

// 추출 로직을 별도 함수로 분리하여 main 함수의 가독성 향상
fn extract_hex_payload(line: &str) -> Option<&str> {
    // 현재 라인 전체에서 "1f8b" 또는 "\\x1f8b"의 시작 인덱스 동적 탐색
    let mut target_idx = None;
    if let Some(idx) = line.find("\\x1f8b") {
        target_idx = Some(idx + 2); // \\x 제외한 실제 hex 시작점
    } else if let Some(idx) = line.find("1f8b") {
        // 단, UUID나 해시값의 중간에 우연히 끼어든 1f8b오인 방지를 위해
        // 앞뒤가 공백이거나 탭으로 분리되는 순수 헥사 시작 영역 스캔
        let sub = &line[idx..];
        if sub.len() > 100 {
            // 리플레이 바이너리는 최소 수백 자 이상으로 깁니다
            target_idx = Some(idx);
        }
    }

    let start_pos = target_idx?;

    // 시작점부터 라인 끝까지 자른 후, 뒤쪽에 붙은 시간값이나 메타데이터 컬럼 잘라내기
    let remaining = &line[start_pos..];

    // 리플레이 헥사 문자열 뒤에는 공백이나 탭으로 다음 컬럼(예: '62', '2026-05-23')이 붙어옵니다.
    Some(match remaining.find(|c: char| c.is_whitespace()) {
        Some(end_p) => &remaining[..end_p],
        None => remaining.trim(),
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file = File::open("umami_raw_backup.sql")?;
    let reader = BufReader::new(file);

    println!("=== 🚀 Rust 고성능 마우스 엔트로피 스트림 파서 가동 ===");
    let mut total_processed = 0;
    let mut visit_map: HashMap<String, VisitGroup> = HashMap::new();

    // 분석 결과 저장을 위한 CSV 파일 생성 및 헤더 작성
    let mut csv_file = std::io::BufWriter::new(File::create("mouse_entropy_analysis.csv")?);
    writeln!(
        csv_file,
        "replay_id,session_id,visit_id,move_count,chunk_entropy_score,raw_movements"
    )?;

    for line in reader.lines() {
        let line = line?;

        // 데이터가 없는 스키마 정의/주석 구간 고속 스킵
        if line.starts_with("--")
            || line.starts_with("CREATE")
            || line.starts_with("ALTER")
            || line.starts_with("COPY")
        {
            continue;
        }

        // PostgreSQL Dump의 COPY 포맷은 탭(\t)으로 컬럼을 구분합니다.
        let columns: Vec<&str> = line.split('\t').collect();

        // session_replay 테이블의 컬럼 순서 (0부터 시작):
        // 2: session_id (UUID), 3: visit_id (UUID), 5: events (Hex Payload)
        if columns.len() < 6 {
            continue;
        }

        let replay_id = columns[0];
        let session_id = columns[2];
        let visit_id = columns[3];
        let raw_payload = columns[5];

        // 헥사 페이로드 추출 (\\x 접두어 제거)
        let pure_hex = if let Some(hex) = raw_payload.strip_prefix("\\\\x") {
            hex
        } else if let Some(hex) = raw_payload.strip_prefix("\\x") {
            hex
        } else {
            continue;
        };

        total_processed += 1;

        // 압축 해제 및 엔트로피 연산 가동
        if let Some(json_content) = decompress_umami_replay(pure_hex) {
            if let Ok(events) = serde_json::from_str::<Vec<ReplayEvent>>(&json_content) {
                let mouse_moves: Vec<Position> = events
                    .into_iter()
                    .filter(|e| e.event_type == 3 && e.data.source == Some(1))
                    .filter_map(|e| e.data.positions)
                    .flatten()
                    .collect();

                if !mouse_moves.is_empty() {
                    // 1. CSV 저장을 위한 개별 Row(Chunk) 엔트로피 계산
                    let chunk_entropy = calculate_mouse_entropy(&mouse_moves);

                    // 2. CSV에 즉시 기록 (기존 방식 유지)
                    let raw_moves_json = serde_json::to_string(&mouse_moves)?;
                    let escaped_json = raw_moves_json.replace("\"", "\"\"");

                    writeln!(
                        csv_file,
                        "{},{},{},{},{:.6},\"{}\"",
                        replay_id,
                        session_id,
                        visit_id,
                        mouse_moves.len(),
                        chunk_entropy,
                        escaped_json
                    )?;

                    // 3. 그래프 계산을 위해 visit_id별로 좌표 통합
                    let group = visit_map.entry(visit_id.to_string()).or_insert(VisitGroup {
                        positions: Vec::new(),
                    });
                    group.positions.extend(mouse_moves);
                }
            }
        }
    }
    csv_file.flush()?;
    println!("📁 모든 행의 데이터가 'mouse_entropy_analysis.csv'에 저장되었습니다.");

    println!("🔄 visit_id 그룹별 그래프용 엔트로피 연산 시작...");
    let mut visit_entropy_values = Vec::new();
    for group in visit_map.values() {
        if group.positions.len() >= 5 {
            let total_entropy = calculate_mouse_entropy(&group.positions);
            visit_entropy_values.push(total_entropy);
        }
    }

    println!("\n=== ✨ 분석 완료 ===");
    println!("총 처리된 SQL Row 수: {}", total_processed);
    println!(
        "📈 그래프 생성에 사용된 고유 방문(Visit) 수: {}",
        visit_entropy_values.len()
    );
    println!("📁 분석 데이터가 'mouse_entropy_analysis.csv' 파일에 저장되었습니다.");

    // 오류 처리
    if !visit_entropy_values.is_empty() {
        draw_entropy_histogram(&visit_entropy_values)?;
    }

    Ok(())
}

fn draw_entropy_histogram(data: &[f64]) -> Result<(), Box<dyn std::error::Error>> {
    // 1. 도화지 세팅 (800x600 픽셀 크기의 PNG 파일 생성)
    let root = BitMapBackend::new("mouse_entropy_distribution.png", (800, 600)).into_drawing_area();
    root.fill(&WHITE)?;

    // 1.5 데이터를 0.2 단위의 버킷(Bin)으로 쪼개서 히스토그램 데이터 생성
    let mut bins = vec![0; 20];
    for &val in data {
        let idx = (val / 0.2).floor() as usize;
        if idx < bins.len() {
            bins[idx] += 1;
        }
    }
    let max_count = *bins.iter().max().unwrap_or(&10);

    // 2. 챠트의 영역 및 축 범위 설정 (X축: 엔트로피 0.0 ~ 4.0, Y축: 세션 수에 맞춰 동적 할당)
    let mut chart = ChartBuilder::on(&root)
        .caption(
            "Mouse Entropy Distribution (Min 5 Points)",
            ("sans-serif", 30).into_font(),
        )
        .margin(10)
        .x_label_area_size(40)
        .y_label_area_size(40)
        .build_cartesian_2d(0.0..4.0, 0..max_count + (max_count / 10).max(1))?;

    chart
        .configure_mesh()
        .x_desc("Shannon Entropy Score")
        .y_desc("Number of Sessions")
        .draw()?;

    // 4. 히스토그램 막대 그래프 그리기
    chart.draw_series(bins.iter().enumerate().map(|(idx, &count)| {
        let x0 = idx as f64 * 0.2;
        let x1 = x0 + 0.2;
        Rectangle::new([(x0, 0), (x1, count)], BLUE.filled())
    }))?;

    root.present()?;
    println!("📊 [시각화 완료] 'mouse_entropy_distribution.png' 파일이 저장되었습니다.");

    Ok(())
}
