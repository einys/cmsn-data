use chrono::DateTime;
use plotters::prelude::*;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};

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
    is_bot: bool,
    std_dwell: f64,
    cv_dwell: f64,
    entropy_seq: f64,
    trans_entropy: f64,
    repeat_ratio: f64,
    anomaly_score: f64,
    step_count: usize,
}

struct AnalysisResult {
    human_transitions: HashMap<(String, String), usize>,
    bot_transitions: HashMap<(String, String), usize>,
    all_states: HashSet<String>,
    human_count: usize,
    bot_count: usize,
    session_features: Vec<SessionFeatures>,
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

fn calc_shannon_entropy(items: &[String]) -> f64 {
    if items.is_empty() {
        return 0.0;
    }
    let mut freq: HashMap<&str, usize> = HashMap::new();
    for s in items {
        *freq.entry(s.as_str()).or_insert(0) += 1;
    }
    let n = items.len() as f64;
    freq.values()
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn calc_transition_entropy(pages: &[String]) -> f64 {
    if pages.len() < 2 {
        return 0.0;
    }
    let mut freq: HashMap<(&str, &str), usize> = HashMap::new();
    for w in pages.windows(2) {
        *freq.entry((w[0].as_str(), w[1].as_str())).or_insert(0) += 1;
    }
    let total = (pages.len() - 1) as f64;
    freq.values()
        .map(|&c| {
            let p = c as f64 / total;
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

// anomaly score: 높을수록 봇 가능성 높음
// CV 낮음, 엔트로피 낮음, 전이엔트로피 낮음, 반복비율 높음 → 봇
fn calc_anomaly_score(cv: f64, entropy: f64, trans_entropy: f64, repeat_ratio: f64) -> f64 {
    // 각 피처를 [0,1]로 클리핑 후 가중 합산
    // CV: 낮을수록 봇 → (1 - min(cv/3, 1)) * weight
    // entropy: 낮을수록 봇 → (1 - min(entropy/2, 1)) * weight
    // trans_entropy: 낮을수록 봇 → (1 - min(trans_entropy/2, 1)) * weight
    // repeat_ratio: 높을수록 봇 → repeat_ratio * weight
    let cv_score = (1.0 - (cv / 3.0).min(1.0)) * 0.30;
    let ent_score = (1.0 - (entropy / 2.0).min(1.0)) * 0.25;
    let trans_score = (1.0 - (trans_entropy / 2.0).min(1.0)) * 0.25;
    let rep_score = repeat_ratio.min(1.0) * 0.20;
    cv_score + ent_score + trans_score + rep_score
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
        human_transitions: HashMap::new(),
        bot_transitions: HashMap::new(),
        all_states: HashSet::new(),
        human_count: 0,
        bot_count: 0,
        session_features: Vec::new(),
    };

    println!("=== 🔍 세션별 시퀀스 마이닝 및 봇 시나리오 매칭 ===");

    for (visit_id, events) in visit_routes.iter_mut() {
        if events.len() < 3 {
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

        // 봇 판별 (기존 로직 유지)
        let mut loop_count = 0;
        for window in categories.windows(2) {
            if (window[0] == "[List]" && window[1] == "[Detail]")
                || (window[0] == "[Detail]" && window[1] == "[List]")
            {
                loop_count += 1;
            }
        }
        let loop_ratio = loop_count as f64 / (categories.len() - 1) as f64;
        let is_bot = loop_ratio > 0.8 && categories.len() >= 6;

        // 특징 계산
        let mean_dwell = if dwell_times.is_empty() {
            0.0
        } else {
            dwell_times.iter().sum::<f64>() / dwell_times.len() as f64
        };
        let std_dwell = calc_std(&dwell_times);
        let cv_dwell = if mean_dwell > 0.0 {
            std_dwell / mean_dwell
        } else {
            0.0
        };
        let entropy_seq = calc_shannon_entropy(&categories);
        let trans_entropy = calc_transition_entropy(&categories);
        let repeat_ratio = calc_repeat_ratio(&dwell_times);
        let anomaly_score = calc_anomaly_score(cv_dwell, entropy_seq, trans_entropy, repeat_ratio);

        result.session_features.push(SessionFeatures {
            visit_id: visit_id.clone(),
            is_bot,
            std_dwell,
            cv_dwell,
            entropy_seq,
            trans_entropy,
            repeat_ratio,
            anomaly_score,
            step_count: categories.len(),
        });

        let target_matrix = if is_bot {
            result.bot_count += 1;
            &mut result.bot_transitions
        } else {
            result.human_count += 1;
            &mut result.human_transitions
        };

        // 전이 매트릭스 업데이트
        let mut timed_sequence = Vec::new();
        for i in 0..categories.len() - 1 {
            let from = &categories[i];
            let to = &categories[i + 1];
            *target_matrix.entry((from.clone(), to.clone())).or_insert(0) += 1;
            let dwell_secs = (events[i + 1].created_at - events[i].created_at) as f64 / 1000.0;
            timed_sequence.push(format!("{}({:.2}s)", from, dwell_secs));
        }
        timed_sequence.push(categories.last().unwrap().clone());
        writeln!(csv_file, "{},\"{}\"", visit_id, timed_sequence.join(" ➔ "))?;

        let short_id = &visit_id[..visit_id.len().min(8)];
        if is_bot {
            println!(
                "🚨 [BOT] {}.. | 이동: {} | 매칭률: {:.1}% | CV: {:.2} | Entropy: {:.2}",
                short_id,
                events.len(),
                loop_ratio * 100.0,
                cv_dwell,
                entropy_seq
            );
        } else if result.human_count <= 5 {
            println!(
                "🎯 [HUMAN] {}.. | 이동: {} | CV: {:.2} | Entropy: {:.2}",
                short_id,
                events.len(),
                cv_dwell,
                entropy_seq
            );
        }
    }

    Ok(result)
}

// ==========================================
// 6. 시각화: 전이 확률 히트맵 (정규화)
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

    // 행별 합계로 확률 정규화
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

    // 타이틀
    root.draw(&Text::new(
        title,
        (w as i32 / 2 - 150, 15),
        ("sans-serif", 22).into_font().color(&BLACK),
    ))?;

    // 컬럼 헤더 (to)
    for (j, to) in states.iter().enumerate() {
        let x = margin as i32 + j as i32 * cell_px as i32 + cell_px as i32 / 2 - 20;
        root.draw(&Text::new(
            to.trim_matches(|c| c == '[' || c == ']'),
            (x, margin as i32 - 30),
            ("sans-serif", 14).into_font().color(&RGBColor(80, 80, 80)),
        ))?;
    }

    // 행 헤더 (from) + 셀
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

            // 파란색 계열 그라디언트: 0 → 흰색, 1 → 진파랑
            let r = (255.0 - prob * 200.0) as u8;
            let g = (255.0 - prob * 150.0) as u8;
            let b = 255u8;
            let fill_color = RGBColor(r, g, b).filled();
            let border_color = RGBColor(200, 200, 200).stroke_width(1);

            root.draw(&Rectangle::new([(x0, y0), (x1, y1)], fill_color))?;
            root.draw(&Rectangle::new([(x0, y0), (x1, y1)], border_color))?;

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

    // 축 레이블
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
// 7. 시각화: 히스토그램 (인간 vs 봇 오버레이)
// ==========================================
fn draw_histogram_overlay(
    human_vals: &[f64],
    bot_vals: &[f64],
    title: &str,
    x_label: &str,
    file_path: &str,
    bins: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let all_vals: Vec<f64> = human_vals.iter().chain(bot_vals.iter()).cloned().collect();
    if all_vals.is_empty() {
        return Ok(());
    }

    let x_min = 0.0f64;
    let x_max = all_vals.iter().cloned().fold(f64::NEG_INFINITY, f64::max) * 1.1;
    let bin_width = (x_max - x_min) / bins as f64;

    let count_bins = |vals: &[f64]| -> Vec<u32> {
        let mut counts = vec![0u32; bins];
        for &v in vals {
            let i = ((v - x_min) / bin_width).floor() as usize;
            let i = i.min(bins - 1);
            counts[i] += 1;
        }
        counts
    };

    let human_counts = count_bins(human_vals);
    let bot_counts = count_bins(bot_vals);
    let y_max = human_counts
        .iter()
        .chain(bot_counts.iter())
        .max()
        .copied()
        .unwrap_or(1);

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

    // 인간: 파란색 반투명
    chart
        .draw_series(human_counts.iter().enumerate().map(|(i, &cnt)| {
            let x0 = x_min + i as f64 * bin_width;
            let x1 = x0 + bin_width * 0.45; // 나란히 표시
            Rectangle::new(
                [(x0, 0), (x1, cnt)],
                RGBColor(55, 138, 221).mix(0.7).filled(),
            )
        }))?
        .label("Human")
        .legend(|(x, y)| {
            Rectangle::new(
                [(x, y - 6), (x + 16, y + 6)],
                RGBColor(55, 138, 221).filled(),
            )
        });

    // 봇: 주황색 반투명
    chart
        .draw_series(bot_counts.iter().enumerate().map(|(i, &cnt)| {
            let x0 = x_min + i as f64 * bin_width + bin_width * 0.5; // 오프셋
            let x1 = x0 + bin_width * 0.45;
            Rectangle::new(
                [(x0, 0), (x1, cnt)],
                RGBColor(216, 90, 48).mix(0.75).filled(),
            )
        }))?
        .label("Bot")
        .legend(|(x, y)| {
            Rectangle::new(
                [(x, y - 6), (x + 16, y + 6)],
                RGBColor(216, 90, 48).filled(),
            )
        });

    chart
        .configure_series_labels()
        .background_style(WHITE.mix(0.8))
        .border_style(RGBColor(200, 200, 200))
        .draw()?;

    root.present()?;
    println!("✅ 히스토그램 저장: {}", file_path);
    Ok(())
}

// ==========================================
// 8. 시각화: 산점도 (엔트로피 vs anomaly score)
// ==========================================
fn draw_scatter(
    features: &[SessionFeatures],
    file_path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = BitMapBackend::new(file_path, (900, 600)).into_drawing_area();
    root.fill(&WHITE)?;

    let x_max = features
        .iter()
        .map(|f| f.entropy_seq)
        .fold(0.0f64, f64::max)
        * 1.1
        + 0.1;

    let mut chart = ChartBuilder::on(&root)
        .caption("Entropy vs Anomaly Score", ("sans-serif", 20))
        .margin(40)
        .x_label_area_size(50)
        .y_label_area_size(55)
        .build_cartesian_2d(0.0f64..x_max, 0.0f64..1.05f64)?;

    chart
        .configure_mesh()
        .x_desc("Shannon Entropy (bits)")
        .y_desc("Anomaly Score (높을수록 봇 의심)")
        .x_labels(8)
        .y_labels(8)
        .draw()?;

    // 판별 경계선 힌트 (anomaly score 0.5 기준)
    chart.draw_series(LineSeries::new(
        vec![(0.0, 0.5), (x_max, 0.5)],
        RGBColor(220, 220, 220).stroke_width(1),
    ))?;

    // 인간 세션
    let human_pts: Vec<(f64, f64)> = features
        .iter()
        .filter(|f| !f.is_bot)
        .map(|f| (f.entropy_seq, f.anomaly_score))
        .collect();
    chart
        .draw_series(
            human_pts
                .iter()
                .map(|&(x, y)| Circle::new((x, y), 6, RGBColor(55, 138, 221).mix(0.7).filled())),
        )?
        .label("Human")
        .legend(|(x, y)| Circle::new((x + 8, y), 6, RGBColor(55, 138, 221).filled()));

    // 봇 세션
    let bot_pts: Vec<(f64, f64)> = features
        .iter()
        .filter(|f| f.is_bot)
        .map(|f| (f.entropy_seq, f.anomaly_score))
        .collect();
    chart
        .draw_series(bot_pts.iter().map(|&(x, y)| {
            // 봇은 삼각형 모양 흉내 (작은 십자)
            EmptyElement::at((x, y)) + Cross::new((0, 0), 7, RGBColor(216, 90, 48).stroke_width(2))
        }))?
        .label("Bot")
        .legend(|(x, y)| Cross::new((x + 8, y), 6, RGBColor(216, 90, 48).stroke_width(2)));

    chart
        .configure_series_labels()
        .background_style(WHITE.mix(0.8))
        .border_style(RGBColor(200, 200, 200))
        .draw()?;

    root.present()?;
    println!("✅ 산점도 저장: {}", file_path);
    Ok(())
}

// ==========================================
// 9. 특징 CSV 저장
// ==========================================
fn save_features_csv(
    features: &[SessionFeatures],
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut f = File::create(path)?;
    writeln!(
        f,
        "visit_id,is_bot,steps,std_dwell,cv_dwell,entropy_seq,trans_entropy,repeat_ratio,anomaly_score"
    )?;
    for feat in features {
        writeln!(
            f,
            "{},{},{},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4}",
            feat.visit_id,
            feat.is_bot as u8,
            feat.step_count,
            feat.std_dwell,
            feat.cv_dwell,
            feat.entropy_seq,
            feat.trans_entropy,
            feat.repeat_ratio,
            feat.anomaly_score,
        )?;
    }
    println!("✅ 특징 CSV 저장: {}", path);
    Ok(())
}

// ==========================================
// 10. 메인 실행부
// ==========================================
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== 🚀 Rust 고성능 마르코프 체인 경로 분석기 가동 ===\n");

    // 1. 로그 파싱
    let visit_routes = parse_logs("umami_raw_backup.sql")?;

    // 2. 분석 실행
    let result = analyze_sessions(visit_routes, "session_paths.csv")?;

    println!("\n=== ✨ Route 분석 완료 ===");
    println!("📈 Human-like 세션: {}", result.human_count);
    println!("🤖 Bot-suspect 세션: {}", result.bot_count);

    // 3. 특징 CSV 저장
    save_features_csv(&result.session_features, "session_features.csv")?;

    // 4. 시각화 준비
    let mut sorted_states: Vec<String> = result.all_states.into_iter().collect();
    sorted_states.sort();

    println!("\n🖼️  시각화 생성 중...");

    // 4-1. 전이 확률 히트맵 (확률 정규화)
    draw_transition_heatmap(
        &result.human_transitions,
        &sorted_states,
        "Human — Transition Probability Matrix",
        "heatmap_human.png",
    )?;
    draw_transition_heatmap(
        &result.bot_transitions,
        &sorted_states,
        "Bot — Transition Probability Matrix",
        "heatmap_bot.png",
    )?;

    // 4-2. 특징 분리
    let human_feats: Vec<&SessionFeatures> = result
        .session_features
        .iter()
        .filter(|f| !f.is_bot)
        .collect();
    let bot_feats: Vec<&SessionFeatures> = result
        .session_features
        .iter()
        .filter(|f| f.is_bot)
        .collect();

    let human_cv: Vec<f64> = human_feats.iter().map(|f| f.cv_dwell).collect();
    let bot_cv: Vec<f64> = bot_feats.iter().map(|f| f.cv_dwell).collect();
    let human_ent: Vec<f64> = human_feats.iter().map(|f| f.entropy_seq).collect();
    let bot_ent: Vec<f64> = bot_feats.iter().map(|f| f.entropy_seq).collect();
    let human_anom: Vec<f64> = human_feats.iter().map(|f| f.anomaly_score).collect();
    let bot_anom: Vec<f64> = bot_feats.iter().map(|f| f.anomaly_score).collect();

    // 4-3. 히스토그램
    draw_histogram_overlay(
        &human_cv,
        &bot_cv,
        "체류시간 CV 분포 — Human vs Bot",
        "CV (std / mean)",
        "hist_cv.png",
        12,
    )?;
    draw_histogram_overlay(
        &human_ent,
        &bot_ent,
        "Shannon Entropy 분포 — Human vs Bot",
        "Entropy (bits)",
        "hist_entropy.png",
        12,
    )?;
    draw_histogram_overlay(
        &human_anom,
        &bot_anom,
        "Anomaly Score 분포 — Human vs Bot",
        "Anomaly Score",
        "hist_anomaly.png",
        12,
    )?;

    // 4-4. 산점도
    draw_scatter(&result.session_features, "scatter_entropy_anomaly.png")?;

    // 5. 희소성 분석
    let state_pow2 = sorted_states.len().pow(2) as f64;
    let human_density = result.human_transitions.len() as f64 / state_pow2;
    let bot_density = result.bot_transitions.len() as f64 / state_pow2;

    println!("\n=== 📊 Matrix Density 분석 ===");
    println!("💡 Human Matrix Density: {:.4}", human_density);
    println!(
        "🤖 Bot Matrix Density:   {:.4} (낮을수록 특정 경로만 반복)",
        bot_density
    );

    println!("\n=== 📁 생성된 파일 ===");
    println!("  session_paths.csv       — 세션별 경로 시퀀스");
    println!("  session_features.csv    — 세션별 특징 벡터");
    println!("  heatmap_human.png       — 인간 전이 확률 히트맵");
    println!("  heatmap_bot.png         — 봇 전이 확률 히트맵");
    println!("  hist_cv.png             — CV 히스토그램");
    println!("  hist_entropy.png        — 엔트로피 히스토그램");
    println!("  hist_anomaly.png        — Anomaly Score 히스토그램");
    println!("  scatter_entropy_anomaly.png — 산점도");

    Ok(())
}
