use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

// =========================================================================
// ⚙️ [전역 상수 설정 구역] 논문 실험 및 탐지 임계값 관리
// =========================================================================
const MIN_REQUESTS_FOR_DETECTION: u64 = 15; // 최소 요청 수 (15회 이상일 때만 판정)
const THRESHOLD_STATIC_RATIO: f64 = 0.30; // 정적 자원 비율 임계값 (30% 미만이면 봇으로 간주)

// 📂 출력 파일 경로 설정
const OUTPUT_FILE_NAME: &str = "output/ip/detected_stealth_scrapers.csv";
const OUTPUT_TEXT_FILE_NAME: &str = "output/ip/detected_stealth_scrapers.txt";
const TOTAL_VISITOR_RATIO_CSV_FILE_NAME: &str = "output/ip/total_ip_static_resource_ratios.csv";
const STATIC_RATIO_TABLE_FILE_NAME: &str = "output/ip/static_resource_ratio_distribution.txt";
// =========================================================================

// 오직 전체 누적 카운트만 남긴 정직한 구조체
#[derive(Default)]
struct LiveSession {
    total_requests: u64,
    dynamic_count: u64,
    static_count: u64,
}

impl LiveSession {
    // 전체 로그가 다 돌고 난 후 최종 비율 계산
    fn static_odds_ratio(&self) -> f64 {
        if self.dynamic_count == 0 {
            if self.static_count > 0 {
                100.0 // 동적 요청이 0개이고 정적 요청만 있는 경우
            } else {
                0.0
            }
        } else {
            self.static_count as f64 / self.dynamic_count as f64
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("📊 배치(Batch) 기반 전체 히스토리 스텔스 스크래퍼 분석 엔진 가동...");

    let mut memory_sessions: HashMap<String, LiveSession> = HashMap::new();

    let log_regex = Regex::new(
        r#"(?P<ip>\S+) - - \[[^\]]+\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d+) \d+ "[^"]*" "(?P<ua>[^"]*)" \d+ \S+ \[[^\]]*\] \[\] .* "(?P<host>[^"]*)"#,
    )?;

    let file = File::open("../ingress_nginx.log")?;
    let metadata = file.metadata()?;
    let pb = ProgressBar::new(metadata.len());
    pb.set_style(ProgressStyle::default_bar().template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} | 전체 데이터 수집 중...")?);

    let reader = BufReader::new(file);
    let mut total_lines = 0;
    let mut cmsn_lines = 0;

    // 1단계: 중간 판정 없이 전체 로그를 돌며 IP별로 카운트만 순수하게 누적
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

            let session = memory_sessions.entry(ip_str).or_default();
            session.total_requests += 1;

            let is_static_file = url_lower.contains(".css")
                || url_lower.contains(".js")
                || url_lower.contains(".png")
                || url_lower.contains(".jpg")
                || url_lower.contains(".jpeg")
                || url_lower.contains(".ico")
                || url_lower.contains(".svg")
                || url_lower.contains(".woff")
                || url_lower.contains("/api/images");

            if is_static_file {
                session.static_count += 1;
            } else {
                session.dynamic_count += 1;
            }
        }
    }

    pb.finish_with_message("1단계: 로그 수집 완료");
    println!("📝 2단계: 전체 히스토리 기반 봇 판정 및 파일 저장 중...");

    // 2단계: 수집이 끝난 '전체 히스토리'를 기반으로 상수의 기준미만인 봇들을 필터링
    let mut bot_details: Vec<(&String, &LiveSession)> = memory_sessions
        .iter()
        .filter(|(_, session)| {
            // 💡 상단에 정의한 전역 상수를 적용하여 필터링
            session.total_requests >= MIN_REQUESTS_FOR_DETECTION
                && session.static_odds_ratio() < THRESHOLD_STATIC_RATIO
        })
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

    writeln!(file, "IP,DetectionType,StaticResourceRatio")?;

    for (ip, session) in &bot_details {
        let static_ratio = session.static_odds_ratio();
        writeln!(file, "{},Stealth Scraper,{:.2}", ip, static_ratio)?;
        writeln!(
            text_file,
            "🚨 [BOT] IP: {} | Type: Stealth Scraper | Total Requests: {} | Final ratio: {:.2}",
            ip, session.total_requests, static_ratio
        )?;
    }

    let visitor_stats = save_visitor_ratio_stats(&memory_sessions)?;

    let static_ratio_data: Vec<f64> = visitor_stats
        .iter()
        .map(|stat| stat.static_resource_ratio)
        .collect();
    save_static_odds_table(
        STATIC_RATIO_TABLE_FILE_NAME,
        "전체 히스토리 정적 자원 / 동적 자원 비율 분포 보고서",
        &static_ratio_data,
    )?;

    println!("\n=== 📊 CMSN 전체 통계 분포 보고서 ===");
    println!("- 인그레스 총 로그 라인 : {} 건", total_lines);
    println!("- CMSN 본진 선별 로그   : {} 건", cmsn_lines);
    println!(
        "- 탐지된 고유 스텔스 스크래퍼 : {} 개 IP",
        bot_details.len()
    );
    println!("- 봇 탐지 CSV 저장 경로 : {}", OUTPUT_FILE_NAME);
    println!("- 정적자원 비율 통계 표 : {}", STATIC_RATIO_TABLE_FILE_NAME);

    Ok(())
}

struct VisitorRatioStat {
    ip: String,
    static_resource_ratio: f64,
}

fn save_visitor_ratio_stats(
    sessions: &HashMap<String, LiveSession>,
) -> Result<Vec<VisitorRatioStat>, Box<dyn std::error::Error>> {
    if let Some(parent) = Path::new(TOTAL_VISITOR_RATIO_CSV_FILE_NAME).parent() {
        fs::create_dir_all(parent)?;
    }

    let mut stats: Vec<VisitorRatioStat> = sessions
        .iter()
        .filter(|(_, session)| {
            // 💡 [핵심 필터 추가] 총 요청 수가 전역 상수로 정의한 최소 기준(30회) 이상인 것만 통과!
            session.total_requests >= MIN_REQUESTS_FOR_DETECTION
        })
        .map(|(ip, session)| VisitorRatioStat {
            ip: ip.to_string(),
            static_resource_ratio: session.static_odds_ratio(),
        })
        .collect();

    stats.sort_by(|a, b| {
        b.static_resource_ratio
            .partial_cmp(&a.static_resource_ratio)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut file = File::create(TOTAL_VISITOR_RATIO_CSV_FILE_NAME)?;
    writeln!(file, "IP,StaticResourceRatio")?;

    for stat in &stats {
        writeln!(file, "{},{:.2}", stat.ip, stat.static_resource_ratio)?;
    }

    Ok(stats)
}

fn save_static_odds_table(
    file_name: &str,
    title: &str,
    data: &[f64],
) -> Result<(), Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Ok(());
    }

    let total_count = data.len() as f64;

    let mut pure_zero = 0_u32;
    let mut under_0_05 = 0_u32;
    let mut under_0_10 = 0_u32;
    let mut under_0_20 = 0_u32;
    let mut under_0_50 = 0_u32;
    let mut under_1_00 = 0_u32;
    let mut over_1_00 = 0_u32;

    for &val in data {
        if val == 0.0 {
            pure_zero += 1;
        } else if val < 0.05 {
            under_0_05 += 1;
        } else if val < 0.10 {
            under_0_10 += 1;
        } else if val < 0.20 {
            under_0_20 += 1;
        } else if val < 0.50 {
            under_0_50 += 1;
        } else if val < 1.00 {
            under_1_00 += 1;
        } else {
            over_1_00 += 1;
        }
    }

    if let Some(parent) = Path::new(file_name).parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(file_name)?;

    let mut log_and_write = |msg: String| -> Result<(), Box<dyn std::error::Error>> {
        println!("{}", msg);
        writeln!(file, "{}", msg)?;
        Ok(())
    };

    log_and_write(format!(
        "\n=================================================="
    ))?;
    log_and_write(format!(" 📊 {}", title))?;
    log_and_write(format!(
        "=================================================="
    ))?;
    log_and_write(format!(
        "  구간 (Static/Dynamic 배수) |  고유 IP 수  |  비율"
    ))?;
    log_and_write(format!(
        "--------------------------------------------------"
    ))?;

    let rows = vec![
        ("정확히 0.00 (순수 동적 요청) ", pure_zero),
        ("0.00 초과 ~ 0.05 미만       ", under_0_05),
        ("0.05 이상 ~ 0.10 미만       ", under_0_10),
        ("0.10 이상 ~ 0.20 미만       ", under_0_20),
        ("0.20 이상 ~ 0.50 미만       ", under_0_50),
        ("0.50 이상 ~ 1.00 미만       ", under_1_00),
        ("1.00 이상 (정적 자원 우세)   ", over_1_00),
    ];

    for (label, count) in rows {
        let percentage = (count as f64 / total_count) * 100.0;
        log_and_write(format!(
            "  {} | {:>8}개 | {:>5.1}%",
            label, count, percentage
        ))?;
    }

    log_and_write(format!(
        "--------------------------------------------------"
    ))?;
    log_and_write(format!(
        "  총합                       | {:>8}개 | 100.0%",
        total_count
    ))?;
    log_and_write(format!(
        "==================================================\n"
    ))?;

    Ok(())
}
