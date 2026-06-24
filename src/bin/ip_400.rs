use indicatif::{ProgressBar, ProgressStyle};
use plotters::prelude::*;
use regex::Regex;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

// 메모리 오버헤드를 최소화한 실시간 세션 구조체
#[derive(Default)]
struct LiveSession {
    total_requests: u64,
    bad_status_count: u64,          // 💡 400 이상의 상태 코드를 카운트
    is_detected: bool, // 💡 [신규] 이미 봇으로 확정되어 터미널에 출력되었는지 여부 플래그
    detection_type: Option<String>, // 💡 [신규] 봇 탐지 유형 저장
}

impl LiveSession {
    // 400+ 상태 코드 비율 계산 (0.0 ~ 1.0)
    fn bad_status_ratio(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            self.bad_status_count as f64 / self.total_requests as f64
        }
    }
}

const OUTPUT_FILE_NAME: &str = "output/ip/detected_vulnerability_scanners.csv";
const OUTPUT_TEXT_FILE_NAME: &str = "output/ip/detected_vulnerability_scanners.txt";
const VISITOR_RATIO_CSV_FILE_NAME: &str = "output/ip/visitor_ip_ratios_400.csv";
const BAD_STATUS_RATIO_CHART_FILE_NAME: &str = "output/ip/bad_status_ratio_distribution.png";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🛡️ 경량화된 실시간 400+ 에러 취약점 스캐너 봇 탐지 엔진 가동...");

    let mut memory_sessions: HashMap<String, LiveSession> = HashMap::new();

    let log_regex = Regex::new(
        r#"(?P<ip>\S+) - - \[[^\]]+\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d+) \d+ "[^"]*" "(?P<ua>[^"]*)" \d+ \S+ \[[^\]]*\] \[\] .* "(?P<host>[^"]*)"#,
    )?;

    let file = File::open("../ingress_nginx.log")?;
    let metadata = file.metadata()?;
    let pb = ProgressBar::new(metadata.len());
    pb.set_style(ProgressStyle::default_bar().template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} | 고속 스캔 중...")?);

    let reader = BufReader::new(file);
    let mut total_lines = 0;
    let mut cmsn_lines = 0;
    let mut unique_bot_ips_count = 0;

    for line in reader.lines().filter_map(Result::ok) {
        pb.inc(line.len() as u64 + 1);
        total_lines += 1;

        if let Some(caps) = log_regex.captures(&line) {
            let host_domain = &caps["host"];
            let url_path = &caps["url"];
            let url_lower = url_path.to_lowercase();
            let ua = caps["ua"].to_lowercase();
            let ip_str = caps["ip"].to_string();

            if host_domain != "cmsn.info" && host_domain != "api.cmsn.info" {
                continue;
            }

            if ua.contains("uptime-kuma") || ua.contains("googlebot") || ua.contains("twitterbot") {
                continue;
            }

            let is_internal_network = ip_str.starts_with("10.")
                || ip_str.starts_with("192.168.")
                || (ip_str.starts_with("172.") && {
                    ip_str
                        .split('.')
                        .nth(1)
                        .and_then(|s| s.parse::<u8>().ok())
                        .map_or(false, |octet| (16..=31).contains(&octet))
                });

            if is_internal_network {
                continue;
            }
            cmsn_lines += 1;

            let status_code: i32 = caps["status"].parse().unwrap_or(0);
            let session = memory_sessions.entry(ip_str.clone()).or_default();

            if session.is_detected {
                session.total_requests += 1;
                if status_code == 400
                    || status_code == 401
                    || status_code == 403
                    || status_code == 404
                {
                    session.bad_status_count += 1;
                }
                continue;
            }

            session.total_requests += 1;

            // URL 경로 자체에 프론트엔드 빌드 배포 파일인 /_app/immutable/이나 /public/build/가 포함되어 있다면
            // 롤링 업데이트 시 정상 유저 요청도 404 오류가 날 수 있기 때문에,
            // 400+ 에러로 카운트하지 않습니다.
            let safe_api_paths =
                url_lower.contains("/_app/immutable/") || url_lower.contains("/public/build/");

            if !safe_api_paths
                && (status_code == 400
                    || status_code == 401
                    || status_code == 403
                    || status_code == 404)
            {
                session.bad_status_count += 1;
            }

            // 복합 행동 실시간 판정 (IP당 최소 요청 15회 이상 쌓였을 때)
            if session.total_requests >= 15 {
                let bad_status_ratio = session.bad_status_ratio();

                // 판정 필터 A: 민감 정보만 찌르고 다니는 404 악성 스캐너 (Advin 같은 봇)
                let is_vulnerability_scanner = bad_status_ratio > 0.80;

                if is_vulnerability_scanner {
                    if ua.contains("googlebot")
                        || ua.contains("bingbot")
                        || ua.contains("twitterbot")
                        || ua.contains("applebot")
                        || ua.contains("yandexbot")
                    {
                        continue;
                    }

                    session.is_detected = true;
                    session.detection_type = Some("Vulnerability Scanner".to_string());
                    unique_bot_ips_count += 1;

                    if unique_bot_ips_count <= 20 {
                        pb.suspend(|| {
                            println!(
                                "🚨 [봇 검출] IP: {} | 타입: {} | 400+비율: {:.0}%",
                                ip_str,
                                session.detection_type.as_ref().unwrap(),
                                bad_status_ratio * 100.0
                            );
                        });
                    }
                }
            }
        }
    }

    pb.finish_with_message("검사 완료");

    // 봇으로 검출된 IP들을 정렬 및 파일 저장
    let mut bot_details: Vec<(&String, &LiveSession)> = memory_sessions
        .iter()
        .filter(|(_, session)| session.is_detected)
        .collect();
    bot_details.sort_by_key(|(ip, _)| *ip);

    if let Some(parent) = Path::new(OUTPUT_FILE_NAME).parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = Path::new(OUTPUT_TEXT_FILE_NAME).parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = File::create(OUTPUT_FILE_NAME)?;
    let mut text_file = File::create(OUTPUT_TEXT_FILE_NAME)?;

    writeln!(file, "IP,DetectionType,BadStatusRatio")?;

    for (ip, session) in &bot_details {
        let bad_status_ratio = session.bad_status_ratio();
        writeln!(
            file,
            "{},{},{:.2}",
            ip,
            session
                .detection_type
                .as_ref()
                .unwrap_or(&"Unknown".to_string()),
            bad_status_ratio * 100.0
        )?;
        writeln!(
            text_file,
            "🚨 [BOT] IP: {} | Type: {} | 400+ ratio: {:.0}%",
            ip,
            session
                .detection_type
                .as_ref()
                .unwrap_or(&"Unknown".to_string()),
            bad_status_ratio * 100.0
        )?;
    }

    let visitor_stats = save_visitor_ratio_stats(&memory_sessions)?;

    let bad_status_data: Vec<f64> = visitor_stats
        .iter()
        .map(|stat| stat.bad_status_ratio * 100.0)
        .collect();
    draw_bad_status_histogram(
        BAD_STATUS_RATIO_CHART_FILE_NAME,
        "400+ Status Ratio Distribution by Unique Visitor IP",
        "400+ status ratio (%)",
        &bad_status_data,
    )?;

    println!("\n=== 📊 CMSN 400+ 에러 탐지 보고서 ===");
    println!("- 인그레스 총 로그 라인 : {} 건", total_lines);
    println!(
        "- CMSN 본진 선별 로그   : {} 건 (전체의 {:.1}%)",
        cmsn_lines,
        (cmsn_lines as f64 / total_lines as f64) * 100.0
    );
    println!(
        "- 격리된 고유 취약점 스캐너 봇 : {} 개 IP",
        bot_details.len()
    );
    println!("- 봇 탐지 CSV 저장 경로 : {}", OUTPUT_FILE_NAME);
    println!(
        "- 400+ 비율 분포 그래프 : {}",
        BAD_STATUS_RATIO_CHART_FILE_NAME
    );

    Ok(())
}

struct VisitorRatioStat {
    ip: String,
    bad_status_ratio: f64,
}

fn save_visitor_ratio_stats(
    sessions: &HashMap<String, LiveSession>,
) -> Result<Vec<VisitorRatioStat>, Box<dyn std::error::Error>> {
    if let Some(parent) = Path::new(VISITOR_RATIO_CSV_FILE_NAME).parent() {
        fs::create_dir_all(parent)?;
    }

    let mut stats: Vec<VisitorRatioStat> = sessions
        .iter()
        .map(|(ip, session)| VisitorRatioStat {
            ip: ip.to_string(),
            bad_status_ratio: session.bad_status_ratio(),
        })
        .collect();

    stats.sort_by(|a, b| {
        b.bad_status_ratio
            .partial_cmp(&a.bad_status_ratio)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut file = File::create(VISITOR_RATIO_CSV_FILE_NAME)?;
    writeln!(file, "IP,BadStatusRatioPercent")?;

    for stat in &stats {
        writeln!(file, "{},{:.2}", stat.ip, stat.bad_status_ratio * 100.0)?;
    }

    Ok(stats)
}

fn draw_bad_status_histogram(
    file_name: &str,
    title: &str,
    x_desc: &str,
    data: &[f64],
) -> Result<(), Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Ok(());
    }

    let mut bins = vec![0_u32; 20];
    for &ratio in data {
        let clamped_ratio = ratio.clamp(0.0, 100.0);
        let mut idx = ((clamped_ratio / 100.0) * bins.len() as f64).floor() as usize;
        if idx >= bins.len() {
            idx = bins.len() - 1;
        }
        bins[idx] += 1;
    }

    let max_count = *bins.iter().max().unwrap_or(&1);
    let y_max = max_count + (max_count / 10).max(1);

    let root = BitMapBackend::new(file_name, (900, 600)).into_drawing_area();
    root.fill(&WHITE)?;

    let mut chart = ChartBuilder::on(&root)
        .caption(title, ("sans-serif", 26).into_font())
        .margin(16)
        .x_label_area_size(45)
        .y_label_area_size(55)
        .build_cartesian_2d(0.0..100.0, 0_u32..y_max)?;

    chart
        .configure_mesh()
        .x_desc(x_desc)
        .y_desc("Unique visitor IP count")
        .draw()?;

    chart.draw_series(bins.iter().enumerate().map(|(idx, &count)| {
        let x0 = idx as f64 * 5.0;
        let x1 = x0 + 5.0;
        Rectangle::new([(x0, 0), (x1, count)], RGBColor(42, 74, 106).filled())
    }))?;

    root.present()?;
    Ok(())
}
