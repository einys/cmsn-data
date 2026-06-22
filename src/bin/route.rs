use chrono::DateTime;
use plotters::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};

const OUT_DIR: &str = "output/route";
const MIN_EVENTS: usize = 30; // 통계 신뢰를 위한 최소 이벤트 수

// ==========================================
// 1. 데이터 구조체
// ==========================================
#[derive(Debug, Clone)]
struct WebEvent {
    url_path: String,
    created_at: i64,
}

#[derive(Debug, Clone)]
struct SessionFeatures {
    visit_id: String,
    step_count: usize,
    std_dwell: f64,
    cv_dwell: f64,
    entropy_dwell: f64,
    repeat_ratio: f64,
    autocorr_lag1: f64, // 체류시간 자기상관 (lag-1)
}

struct AnalysisResult {
    transitions: HashMap<(String, String), usize>,
    all_states: HashSet<String>,
    session_count: usize,
    skipped_count: usize, // MIN_EVENTS 미만으로 스킵된 세션 수
    session_features: Vec<SessionFeatures>,
}

// ==========================================
// 마르코프 모델 학습 결과 저장용 구조체
// ==========================================
#[derive(Serialize, Deserialize, Debug)]
pub struct MarkovDetector {
    // (From_State, To_State) -> Probability(확률) 구조의 전이 확률 지도
    pub tpm: HashMap<(String, String), f64>,
    // 학습 데이터에 없는 돌발/스캔 경로 진입 시 부여할 라플라스 패널티 스무딩 계수
    pub state_alpha: f64,
}

impl MarkovDetector {
    // 기존에 누적된 전이 빈도수(Transitions)를 기반으로 정규화된 확률 지도 생성
    pub fn train(transitions: &HashMap<(String, String), usize>) -> Self {
        let mut row_sums: HashMap<String, usize> = HashMap::new();
        for ((from, _), &cnt) in transitions {
            *row_sums.entry(from.clone()).or_insert(0) += cnt;
        }

        let mut tpm = HashMap::new();
        for ((from, to), &cnt) in transitions {
            let sum = *row_sums.get(from).unwrap_or(&0);
            if sum > 0 {
                tpm.insert((from.clone(), to.clone()), cnt as f64 / sum as f64);
            }
        }

        // 기본 패널티 스무딩 값을 0.0001로 지정하여 제로데이 경로 차단력 확보
        MarkovDetector {
            tpm,
            state_alpha: 0.0001,
        }
    }
}

// ==========================================
// 2. URL 상태 추상화 모듈
// ==========================================
fn categorize_path(path: &str) -> String {
    let clean_path = path.trim().trim_matches('"').trim_matches('\'');

    if clean_path == "/"
        || clean_path.is_empty()
        || clean_path.contains("/list")
        || clean_path.contains("/t")
    {
        "[List]".to_string()
    } else if clean_path.contains("/search") || clean_path.contains("/category") {
        "[Search]".to_string()
    } else if clean_path.contains("/i/") || clean_path.contains("/post") {
        "[Detail]".to_string()
    } else {
        let parts: Vec<&str> = clean_path.split('/').filter(|s| !s.is_empty()).collect();
        if !parts.is_empty() {
            format!("[{}]", parts[0])
        } else {
            "[Other]".to_string()
        }
    }
}

// ==========================================
// 3. 로그 파싱 모듈
// ==========================================
fn parse_logs(
    file_path: &str,
) -> Result<HashMap<String, Vec<WebEvent>>, Box<dyn std::error::Error>> {
    let file = File::open(file_path)?;
    let reader = BufReader::new(file);
    let mut visit_routes: HashMap<String, Vec<WebEvent>> = HashMap::new();
    let mut raw_count = 0;

    for line in reader.lines() {
        let line = line?;

        if line.starts_with("--")
            || line.starts_with("CREATE")
            || line.starts_with("ALTER")
            || line.starts_with("COPY")
            || line.trim() == "\\."
        {
            continue;
        }

        let columns: Vec<&str> = line.split('\t').collect();

        if columns.len() >= 13 && columns[10].trim() == "1" && columns[12].trim().len() >= 32 {
            let created_at_str = columns[3].trim();
            let url_path = columns[4].trim();
            let visit_id = columns[12].trim();

            let normalized = {
                let len = created_at_str.len();
                let bytes = created_at_str.as_bytes();
                if len >= 3 && (bytes[len - 3] == b'+' || bytes[len - 3] == b'-') {
                    format!("{}00", created_at_str)
                } else if !created_at_str.contains('+') && !created_at_str[10..].contains('-') {
                    format!("{} +0000", created_at_str)
                } else {
                    created_at_str.to_string()
                }
            };

            let timestamp = DateTime::parse_from_str(&normalized, "%Y-%m-%d %H:%M:%S%.f%z")
                .map(|dt| dt.timestamp_millis())
                .unwrap_or_else(|err| {
                    println!(
                        "파싱 실패 원인: {:?}, 원본 데이터: [{}]",
                        err, created_at_str
                    );
                    0
                });

            raw_count += 1;
            visit_routes
                .entry(visit_id.to_string())
                .or_insert_with(Vec::new)
                .push(WebEvent {
                    url_path: url_path.to_string(),
                    created_at: timestamp,
                });
        }
    }

    println!("✅ 총 파싱한 유효 웹 이벤트 수: {}건", raw_count);
    println!(
        "✅ 분류된 고유 방문(visit_id) 수: {}개\n",
        visit_routes.len()
    );

    Ok(visit_routes)
}

// ==========================================
// 4. 특징 계산 헬퍼
// ==========================================
fn calc_std(vals: &[f64]) -> f64 {
    if vals.len() < 2 {
        return 0.0;
    }
    let mean = vals.iter().sum::<f64>() / vals.len() as f64;
    let var = vals.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / vals.len() as f64;
    var.sqrt()
}

// 체류 시간 시퀀스의 불확실성(엔트로피)을 측정
// 연속형 변수인 초(seconds) 단위를 0.5초 혹은 1초 버킷으로 양자화하여 계산합니다.
// 인간은 체류 시간이 다양해서 엔트로피가 높고, 봇은 일정해서 엔트로피가 낮게 나옵니다.
fn calc_dwell_entropy(vals: &[f64]) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<i64, usize> = HashMap::new();
    for &v in vals {
        // 0.5초 단위 버킷으로 범주화 (예: 1.2s -> bucket 2, 1.4s -> bucket 3)
        // 만약 해상도를 더 넓히고 싶다면 (v).round() as i64 (1초 단위)로 변경 가능
        let bucket = (v * 2.0).round() as i64;
        *freq.entry(bucket).or_insert(0) += 1;
    }

    let n = vals.len() as f64;
    freq.values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn calc_repeat_ratio(vals: &[f64]) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }
    // ms 단위 노이즈 고려: 0.5초 이내 같은 값을 동일로 간주
    let mut freq: HashMap<i64, usize> = HashMap::new();
    for &v in vals {
        let bucket = (v * 2.0).round() as i64; // 0.5s 버킷
        *freq.entry(bucket).or_insert(0) += 1;
    }
    let max_repeat = *freq.values().max().unwrap_or(&0);
    max_repeat as f64 / vals.len() as f64
}

// lag-1 자기상관: 체류시간 시퀀스의 주기성 측정
// 봇은 절댓값이 크게 나옴 (양수: 같은 값 반복 / 음수: 교대 반복)
// 인간은 대체로 0에 가까움
fn calc_autocorr_lag1(vals: &[f64]) -> f64 {
    if vals.len() < 3 {
        return 0.0;
    }
    let mean = vals.iter().sum::<f64>() / vals.len() as f64;
    let numerator: f64 = vals.windows(2).map(|w| (w[0] - mean) * (w[1] - mean)).sum();
    let denominator: f64 = vals.iter().map(|v| (v - mean).powi(2)).sum();
    if denominator == 0.0 {
        return 0.0;
    }
    numerator / denominator
}

// ==========================================
// 5. 핵심 분석 모듈
// ==========================================
fn analyze_sessions(
    mut visit_routes: HashMap<String, Vec<WebEvent>>,
    csv_path: &str,
) -> Result<AnalysisResult, Box<dyn std::error::Error>> {
    let mut csv_file = File::create(csv_path)?;
    writeln!(csv_file, "visit_id,path_sequence")?;

    let mut result = AnalysisResult {
        transitions: HashMap::new(),
        all_states: HashSet::new(),
        session_count: 0,
        skipped_count: 0,
        session_features: Vec::new(),
    };

    println!(
        "=== 🔍 세션별 시퀀스 마이닝 (MIN_EVENTS={}) ===",
        MIN_EVENTS
    );

    for (visit_id, events) in visit_routes.iter_mut() {
        // MIN_EVENTS 미만 세션 스킵
        if events.len() < MIN_EVENTS {
            result.skipped_count += 1;
            continue;
        }

        events.sort_by_key(|e| e.created_at);

        let categories: Vec<String> = events
            .iter()
            .map(|e| categorize_path(&e.url_path))
            .collect();

        for cat in &categories {
            result.all_states.insert(cat.clone());
        }

        // 체류시간 계산 (마지막 페이지 제외)
        let dwell_times: Vec<f64> = (0..events.len() - 1)
            .map(|i| (events[i + 1].created_at - events[i].created_at) as f64 / 1000.0)
            .collect();

        // 특징 계산
        let mean_dwell = dwell_times.iter().sum::<f64>() / dwell_times.len() as f64;
        let std_dwell = calc_std(&dwell_times);
        let cv_dwell = if mean_dwell > 0.0 {
            std_dwell / mean_dwell
        } else {
            0.0
        };
        let entropy_dwell = calc_dwell_entropy(&dwell_times);
        let repeat_ratio = calc_repeat_ratio(&dwell_times);
        let autocorr_lag1 = calc_autocorr_lag1(&dwell_times);

        result.session_features.push(SessionFeatures {
            visit_id: visit_id.clone(),
            step_count: categories.len(),
            std_dwell,
            cv_dwell,
            entropy_dwell,
            repeat_ratio,
            autocorr_lag1,
        });

        // 전이 매트릭스 업데이트 및 CSV 기록
        let mut timed_sequence = Vec::new();
        for i in 0..categories.len() - 1 {
            let from = &categories[i];
            let to = &categories[i + 1];
            *result
                .transitions
                .entry((from.clone(), to.clone()))
                .or_insert(0) += 1;
            timed_sequence.push(format!("{}({:.2}s)", from, dwell_times[i]));
        }
        timed_sequence.push(categories.last().unwrap().clone());
        writeln!(csv_file, "{},\"{}\"", visit_id, timed_sequence.join(" ➔ "))?;

        result.session_count += 1;

        if result.session_count <= 5 {
            println!(
                "🎯 {}.. | steps:{} | std:{:.2} | cv:{:.2} | ent:{:.2} | autocorr:{:.3}",
                &visit_id[..visit_id.len().min(8)],
                categories.len(),
                std_dwell,
                cv_dwell,
                entropy_dwell,
                autocorr_lag1,
            );
        }
    }

    Ok(result)
}

// ==========================================
// 6. 시각화: 전이 확률 히트맵
// ==========================================
fn draw_transition_heatmap(
    matrix: &HashMap<(String, String), usize>,
    states: &[String],
    title: &str,
    file_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    if states.is_empty() {
        return Ok(());
    }

    let mut row_sums: HashMap<&str, usize> = HashMap::new();
    for ((from, _), &cnt) in matrix {
        *row_sums.entry(from.as_str()).or_insert(0) += cnt;
    }

    let size = states.len();
    let cell_px = 120usize;
    let margin = 100usize;
    let w = (size * cell_px + margin * 2) as u32;
    let h = (size * cell_px + margin * 2) as u32;

    let root = BitMapBackend::new(file_path, (w, h)).into_drawing_area();
    root.fill(&WHITE)?;

    root.draw(&Text::new(
        title,
        (w as i32 / 2 - 150, 15),
        ("sans-serif", 22).into_font().color(&BLACK),
    ))?;

    for (j, to) in states.iter().enumerate() {
        let x = margin as i32 + j as i32 * cell_px as i32 + cell_px as i32 / 2 - 20;
        root.draw(&Text::new(
            to.trim_matches(|c| c == '[' || c == ']'),
            (x, margin as i32 - 30),
            ("sans-serif", 14).into_font().color(&RGBColor(80, 80, 80)),
        ))?;
    }

    for (i, from) in states.iter().enumerate() {
        let y = margin as i32 + i as i32 * cell_px as i32 + cell_px as i32 / 2 - 8;
        root.draw(&Text::new(
            from.trim_matches(|c| c == '[' || c == ']'),
            (10, y),
            ("sans-serif", 14).into_font().color(&RGBColor(80, 80, 80)),
        ))?;

        for (j, to) in states.iter().enumerate() {
            let count = matrix
                .get(&(from.clone(), to.clone()))
                .copied()
                .unwrap_or(0);
            let row_sum = row_sums.get(from.as_str()).copied().unwrap_or(0);
            let prob = if row_sum > 0 {
                count as f64 / row_sum as f64
            } else {
                0.0
            };

            let x0 = margin as i32 + j as i32 * cell_px as i32;
            let y0 = margin as i32 + i as i32 * cell_px as i32;
            let x1 = x0 + cell_px as i32;
            let y1 = y0 + cell_px as i32;

            let r = (255.0 - prob * 200.0) as u8;
            let g = (255.0 - prob * 150.0) as u8;
            let b = 255u8;

            root.draw(&Rectangle::new(
                [(x0, y0), (x1, y1)],
                RGBColor(r, g, b).filled(),
            ))?;
            root.draw(&Rectangle::new(
                [(x0, y0), (x1, y1)],
                RGBColor(200, 200, 200).stroke_width(1),
            ))?;

            if count > 0 {
                let label = format!("{:.0}%", prob * 100.0);
                let text_color = if prob > 0.5 { &WHITE } else { &BLACK };
                root.draw(&Text::new(
                    label,
                    (x0 + cell_px as i32 / 2 - 15, y0 + cell_px as i32 / 2 - 8),
                    ("sans-serif", 13).into_font().color(text_color),
                ))?;
            }
        }
    }

    root.draw(&Text::new(
        "To →",
        (w as i32 / 2 - 20, margin as i32 - 55),
        ("sans-serif", 13)
            .into_font()
            .color(&RGBColor(120, 120, 120)),
    ))?;
    root.draw(&Text::new(
        "From",
        (10, margin as i32 - 55),
        ("sans-serif", 13)
            .into_font()
            .color(&RGBColor(120, 120, 120)),
    ))?;

    root.present()?;
    println!("✅ 히트맵 저장: {}", file_path);
    Ok(())
}

// ==========================================
// 7. 시각화: 단일 히스토그램
// ==========================================
fn draw_histogram(
    vals: &[f64],
    title: &str,
    x_label: &str,
    file_path: &str,
    bins: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    if vals.is_empty() {
        return Ok(());
    }

    // 자기상관은 음수 포함이므로 x_min을 데이터 기준으로 잡음
    let mut x_min = vals.iter().cloned().fold(f64::INFINITY, f64::min);
    let mut x_max = vals.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    // 안전하게 그래프 여백(Margin) 처리: 양수/음수 상관없이 절대값의 10%를 여백으로 둠
    x_min = if x_min > 0.0 {
        0.0
    } else {
        x_min - x_min.abs() * 0.1
    };
    x_max = x_max + x_max.abs() * 0.1;

    // 만약 데이터가 모두 0.0이거나 같은 값이라서 min == max가 된 경우, 범위를 억지로 벌려줌
    if (x_max - x_min).abs() < f64::EPSILON {
        x_max += 1.0;
        x_min -= if x_min == 0.0 { 0.0 } else { 1.0 };
    }

    let bin_width = (x_max - x_min) / bins as f64;

    let mut counts = vec![0u32; bins];
    for &v in vals {
        // bin_width가 0이 아님이 보장되므로 안전하게 계산
        let i = ((v - x_min) / bin_width).floor() as usize;
        counts[i.min(bins - 1)] += 1;
    }

    let y_max = counts.iter().max().copied().unwrap_or(1);

    let root = BitMapBackend::new(file_path, (900, 500)).into_drawing_area();
    root.fill(&WHITE)?;

    let mut chart = ChartBuilder::on(&root)
        .caption(title, ("sans-serif", 20))
        .margin(40)
        .x_label_area_size(50)
        .y_label_area_size(50)
        .build_cartesian_2d(x_min..x_max, 0u32..(y_max + 2))?;

    chart
        .configure_mesh()
        .x_desc(x_label)
        .y_desc("세션 수")
        .x_labels(10)
        .y_labels(8)
        .draw()?;

    chart.draw_series(counts.iter().enumerate().map(|(i, &cnt)| {
        let x0 = x_min + i as f64 * bin_width;
        let x1 = x0 + bin_width * 0.85;
        Rectangle::new(
            [(x0, 0), (x1, cnt)],
            RGBColor(55, 138, 221).mix(0.75).filled(),
        )
    }))?;

    chart.draw_series(counts.iter().enumerate().map(|(i, &cnt)| {
        let x0 = x_min + i as f64 * bin_width;
        let x1 = x0 + bin_width * 0.85;
        Rectangle::new([(x0, 0), (x1, cnt)], RGBColor(30, 100, 180).stroke_width(1))
    }))?;

    root.present()?;
    println!("✅ 히스토그램 저장: {}", file_path);
    Ok(())
}

// ==========================================
// 8. 특징 CSV 저장
// ==========================================
fn save_features_csv(
    features: &[SessionFeatures],
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "visit_id,steps,std_dwell,cv_dwell,entropy_dwell,repeat_ratio,autocorr_lag1"
    )?;
    for feat in features {
        writeln!(
            f,
            "{},{},{:.4},{:.4},{:.4},{:.4},{:.4}",
            feat.visit_id,
            feat.step_count,
            feat.std_dwell,
            feat.cv_dwell,
            feat.entropy_dwell,
            feat.repeat_ratio,
            feat.autocorr_lag1,
        )?;
    }
    println!("✅ 특징 CSV 저장: {}", path);
    Ok(())
}

// ==========================================
// 9. 메인 실행부
// ==========================================
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== 🚀 Rust 고성능 마르코프 체인 경로 분석기 가동 ===\n");

    // 0. 출력 디렉토리 생성
    fs::create_dir_all(OUT_DIR)?;
    println!("📂 출력 디렉토리: {}/\n", OUT_DIR);

    // 1. 로그 파싱
    let visit_routes = parse_logs("umami_raw_backup.sql")?;

    // 2. 분석 실행
    let result = analyze_sessions(visit_routes, &format!("{}/session_paths.csv", OUT_DIR))?;

    println!("\n=== ✨ Route 분석 완료 ===");
    println!(
        "📈 분석된 세션 수 (events >= {}): {}",
        MIN_EVENTS, result.session_count
    );
    println!(
        "⏭️  스킵된 세션 수 (events < {}):  {}",
        MIN_EVENTS, result.skipped_count
    );

    // 3. 특징 CSV 저장
    save_features_csv(
        &result.session_features,
        &format!("{}/session_features.csv", OUT_DIR),
    )?;

    // 4. 시각화 준비
    let mut sorted_states: Vec<String> = result.all_states.into_iter().collect();
    sorted_states.sort();

    println!("\n🖼️  시각화 생성 중...");

    // 4-1. 전이 확률 히트맵
    draw_transition_heatmap(
        &result.transitions,
        &sorted_states,
        "Transition Probability Matrix",
        &format!("{}/heatmap_transitions.png", OUT_DIR),
    )?;

    // 4-2. 특징 벡터 추출
    let std_vals: Vec<f64> = result
        .session_features
        .iter()
        .map(|f| f.std_dwell)
        .collect();
    let cv_vals: Vec<f64> = result.session_features.iter().map(|f| f.cv_dwell).collect();
    let ent_vals: Vec<f64> = result
        .session_features
        .iter()
        .map(|f| f.entropy_dwell)
        .collect();
    let repeat_vals: Vec<f64> = result
        .session_features
        .iter()
        .map(|f| f.repeat_ratio)
        .collect();
    let autocorr_vals: Vec<f64> = result
        .session_features
        .iter()
        .map(|f| f.autocorr_lag1)
        .collect();

    // 4-3. 히스토그램
    draw_histogram(
        &std_vals,
        "체류시간 Std 분포",
        "Std (seconds)",
        &format!("{}/hist_std.png", OUT_DIR),
        12,
    )?;
    draw_histogram(
        &cv_vals,
        "체류시간 CV 분포",
        "CV (std / mean)",
        &format!("{}/hist_cv.png", OUT_DIR),
        12,
    )?;
    draw_histogram(
        &ent_vals,
        "Entropy dwell 분포",
        "Entropy (bits)",
        &format!("{}/hist_entropy.png", OUT_DIR),
        12,
    )?;
    draw_histogram(
        &repeat_vals,
        "Repeat Ratio 분포",
        "Repeat Ratio",
        &format!("{}/hist_repeat.png", OUT_DIR),
        12,
    )?;
    draw_histogram(
        &autocorr_vals,
        "자기상관 lag-1 분포",
        "Autocorrelation",
        &format!("{}/hist_autocorr.png", OUT_DIR),
        12,
    )?;

    // =====================================================================
    // ⚙️ 학습된 마르코프 지도를 이진 파일로 영구 저장하는 파트
    // =====================================================================
    println!("\n💾 실시간 탐지용 마르코프 정상성 지도 모델 압축 및 저장 중...");
    let detector = MarkovDetector::train(&result.transitions);
    let mut model_file = File::create("normal_markov_model.bin")?;
    let encoded = bincode::serialize(&detector)?;
    model_file.write_all(&encoded)?;
    println!("✅ 모델 파일 생성 완료: normal_markov_model.bin");
    // =====================================================================

    // 5. Matrix Density
    let state_pow2 = sorted_states.len().pow(2) as f64;
    let density = result.transitions.len() as f64 / state_pow2;
    println!("\n=== 📊 Matrix Density ===");
    println!("💡 Transition Matrix Density: {:.4}", density);

    println!("\n=== 📁 생성된 파일 ({OUT_DIR}/) ===");
    println!("  session_paths.csv        — 세션별 경로 시퀀스");
    println!("  session_features.csv     — 세션별 특징 벡터");
    println!("  heatmap_transitions.png  — 전이 확률 히트맵");
    println!("  hist_std.png             — Std 히스토그램");
    println!("  hist_cv.png              — CV 히스토그램");
    println!("  hist_entropy.png         — 체류 시간 엔트로피 히스토그램");
    println!("  hist_repeat.png          — Repeat Ratio 히스토그램");
    println!("  hist_autocorr.png        — 자기상관 히스토그램");

    Ok(())
}
