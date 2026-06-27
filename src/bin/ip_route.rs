use chrono::DateTime;
use plotters::prelude::*;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};

const OUT_DIR: &str = "output/route_nginx";
const MIN_EVENTS: usize = 30; // 통계 신뢰를 위한 최소 이벤트 수
const SESSION_GAP_SECS: i64 = 30 * 60; // 30분 무활동 시 세션(visit) 분리

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
    pub tpm: HashMap<(String, String), f64>,
    pub state_alpha: f64,
}

impl MarkovDetector {
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
    // 쿼리스트링 제거 (nginx URL에는 ?key=value 가 자주 붙음)
    let clean_path = clean_path.split('?').next().unwrap_or(clean_path);

    if clean_path == "/"
        || clean_path.is_empty()
        || clean_path.contains("/api/items")
        || clean_path.contains("/items/list")
        || clean_path.contains("/t")
    {
        "[List]".to_string()
    } else if clean_path.contains("/search") || clean_path.contains("/category") {
        "[Search]".to_string()
    } else if clean_path.contains("/i/") || clean_path.contains("/post") {
        "[Detail]".to_string()
    } else {
        "".to_string()
    }
}

// ==========================================
// 3. Nginx 로그 파싱 모듈
// ==========================================
fn is_static_resource(url_lower: &str) -> bool {
    url_lower.contains(".css")
        || url_lower.contains(".js")
        || url_lower.contains(".png")
        || url_lower.contains(".jpg")
        || url_lower.contains(".jpeg")
        || url_lower.contains(".ico")
        || url_lower.contains(".svg")
        || url_lower.contains(".woff")
        || url_lower.contains("/api/images")
}

fn is_internal_ip(ip: &str) -> bool {
    ip.starts_with("10.")
        || ip.starts_with("192.168.")
        || (ip.starts_with("172.") && {
            ip.split('.')
                .nth(1)
                .and_then(|s| s.parse::<u8>().ok())
                .map_or(false, |octet| (16..=31).contains(&octet))
        })
}

fn parse_nginx_logs(
    file_path: &str,
) -> Result<HashMap<String, Vec<WebEvent>>, Box<dyn std::error::Error>> {
    let log_regex = Regex::new(
        r#"(?P<ip>\S+) - - \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d+) \d+ "[^"]*" "(?P<ua>[^"]*)" \d+ \S+ \[[^\]]*\] \[\] .* "(?P<host>[^"]*)"#,
    )?;

    let file = File::open(file_path)?;
    let reader = BufReader::new(file);

    // IP별로 (timestamp_ms, url_path) 원본 누적 → 정렬/세션분리는 2단계에서
    let mut by_ip: HashMap<String, Vec<(i64, String)>> = HashMap::new();
    let mut raw_count = 0;
    let mut total_lines = 0;

    for line in reader.lines() {
        let line = line?;
        total_lines += 1;

        let Some(caps) = log_regex.captures(&line) else {
            continue;
        };

        let host_domain = &caps["host"];
        if host_domain != "cmsn.info" && host_domain != "api.cmsn.info" {
            continue;
        }

        let ua = caps["ua"].to_lowercase();
        if ua.contains("uptime-kuma") || ua.contains("googlebot") || ua.contains("bot") {
            continue;
        }

        let ip_str = caps["ip"].to_string();
        if is_internal_ip(&ip_str) {
            continue;
        }

        let status: u32 = caps["status"].parse().unwrap_or(0);
        if status >= 400 {
            continue; // 에러 응답은 실제 페이지 이동 흐름으로 보지 않음
        }

        let url_path = caps["url"].to_string();
        let url_lower = url_path.to_lowercase();
        if is_static_resource(&url_lower) {
            continue; // 정적 리소스는 라우트 시퀀스에서 제외 (umami 페이지뷰와 동등 비교 목적)
        }

        // nginx 기본 시간 형식: 10/Oct/2023:13:55:36 +0000
        let timestamp = DateTime::parse_from_str(&caps["time"], "%d/%b/%Y:%H:%M:%S %z")
            .map(|dt| dt.timestamp_millis())
            .unwrap_or_else(|err| {
                println!("⚠️  시간 파싱 실패: {:?}, 원본: [{}]", err, &caps["time"]);
                0
            });
        if timestamp == 0 {
            continue;
        }

        raw_count += 1;
        by_ip
            .entry(ip_str)
            .or_insert_with(Vec::new)
            .push((timestamp, url_path));
    }

    println!("✅ 총 읽은 로그 라인 수: {}건", total_lines);
    println!("✅ 유효 페이지 요청(정적 제외) 수: {}건", raw_count);

    // 세션 분리: 같은 IP라도 SESSION_GAP_SECS(기본 30분) 이상 공백이 있으면 새 세션으로 간주
    let mut visit_routes: HashMap<String, Vec<WebEvent>> = HashMap::new();
    for (ip, mut events) in by_ip {
        events.sort_by_key(|(ts, _)| *ts);

        let mut session_idx = 0usize;
        let mut last_ts: Option<i64> = None;

        for (ts, url) in events {
            if let Some(prev) = last_ts {
                if ts - prev > SESSION_GAP_SECS * 1000 {
                    session_idx += 1;
                }
            }
            last_ts = Some(ts);

            let visit_id = format!("{}#{}", ip, session_idx);
            visit_routes
                .entry(visit_id)
                .or_insert_with(Vec::new)
                .push(WebEvent {
                    url_path: url,
                    created_at: ts,
                });
        }
    }

    println!(
        "✅ IP+시간창 기준 분리된 세션(visit) 수: {}개\n",
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

fn calc_dwell_entropy(vals: &[f64]) -> f64 {
    if vals.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<i64, usize> = HashMap::new();
    for &v in vals {
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
    let mut freq: HashMap<i64, usize> = HashMap::new();
    for &v in vals {
        let bucket = (v * 2.0).round() as i64;
        *freq.entry(bucket).or_insert(0) += 1;
    }
    let max_repeat = *freq.values().max().unwrap_or(&0);
    max_repeat as f64 / vals.len() as f64
}

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
        "=== 🔍 Nginx 세션별 시퀀스 마이닝 (MIN_EVENTS={}) ===",
        MIN_EVENTS
    );

    for (visit_id, events) in visit_routes.iter_mut() {
        if events.len() < MIN_EVENTS {
            result.skipped_count += 1;
            continue;
        }

        events.sort_by_key(|e| e.created_at);

        // 3가지 상태([List], [Search], [Detail])만 필터링하여 수집
        let categories: Vec<String> = events
            .iter()
            .map(|e| categorize_path(&e.url_path))
            .filter(|cat| !cat.is_empty()) // 빈 문자열("") 제거
            .collect();

        // 필터링 후 남은 이벤트 수가 분석에 너무 적다면 세션 스킵 처리 고려 가능
        if categories.len() < 2 {
            result.skipped_count += 1;
            continue;
        }

        for cat in &categories {
            result.all_states.insert(cat.clone());
        }

        let dwell_times: Vec<f64> = (0..events.len() - 1)
            .map(|i| (events[i + 1].created_at - events[i].created_at) as f64 / 1000.0)
            .collect();

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
                &visit_id[..visit_id.len().min(20)],
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

    let mut x_min = vals.iter().cloned().fold(f64::INFINITY, f64::min);
    let mut x_max = vals.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    x_min = if x_min > 0.0 {
        0.0
    } else {
        x_min - x_min.abs() * 0.1
    };
    x_max = x_max + x_max.abs() * 0.1;

    if (x_max - x_min).abs() < f64::EPSILON {
        x_max += 1.0;
        x_min -= if x_min == 0.0 { 0.0 } else { 1.0 };
    }

    let bin_width = (x_max - x_min) / bins as f64;

    let mut counts = vec![0u32; bins];
    for &v in vals {
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
    println!("=== 🚀 Nginx 기반 라우트 마르코프 체인 분석기 가동 ===\n");

    fs::create_dir_all(OUT_DIR)?;
    println!("📂 출력 디렉토리: {}/\n", OUT_DIR);

    // 1. nginx 로그 파싱 (정적 리소스 제외 + IP 기준 세션 분리)
    let visit_routes = parse_nginx_logs("../ingress_nginx.log")?;

    // 2. 분석 실행 (umami 버전과 동일한 로직)
    let result = analyze_sessions(visit_routes, &format!("{}/session_paths.csv", OUT_DIR))?;

    println!("\n=== ✨ Nginx Route 분석 완료 ===");
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

    draw_transition_heatmap(
        &result.transitions,
        &sorted_states,
        "Transition Probability Matrix (Nginx)",
        &format!("{}/heatmap_transitions.png", OUT_DIR),
    )?;

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

    draw_histogram(
        &std_vals,
        "체류시간 Std 분포 (Nginx)",
        "Std (seconds)",
        &format!("{}/hist_std.png", OUT_DIR),
        12,
    )?;
    draw_histogram(
        &cv_vals,
        "체류시간 CV 분포 (Nginx)",
        "CV (std / mean)",
        &format!("{}/hist_cv.png", OUT_DIR),
        12,
    )?;
    draw_histogram(
        &ent_vals,
        "Entropy dwell 분포 (Nginx)",
        "Entropy (bits)",
        &format!("{}/hist_entropy.png", OUT_DIR),
        12,
    )?;
    draw_histogram(
        &repeat_vals,
        "Repeat Ratio 분포 (Nginx)",
        "Repeat Ratio",
        &format!("{}/hist_repeat.png", OUT_DIR),
        12,
    )?;
    draw_histogram(
        &autocorr_vals,
        "자기상관 lag-1 분포 (Nginx)",
        "Autocorrelation",
        &format!("{}/hist_autocorr.png", OUT_DIR),
        12,
    )?;

    // 마르코프 정상성 지도 저장 (umami 모델과 별도 파일명)
    println!("\n💾 Nginx 기반 마르코프 정상성 지도 모델 압축 및 저장 중...");
    let detector = MarkovDetector::train(&result.transitions);
    let mut model_file = File::create("normal_markov_model_nginx.bin")?;
    let encoded = bincode::serialize(&detector)?;
    model_file.write_all(&encoded)?;
    println!("✅ 모델 파일 생성 완료: normal_markov_model_nginx.bin");

    // 5. Matrix Density
    let state_pow2 = sorted_states.len().pow(2) as f64;
    let density = result.transitions.len() as f64 / state_pow2;
    println!("\n=== 📊 Matrix Density (Nginx) ===");
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
