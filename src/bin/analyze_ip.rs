use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

// 메모리 오버헤드를 최소화한 실시간 세션 구조체
#[derive(Default)]
struct LiveSession {
    total_requests: u64,
    // error_404_count: u64, // 400 이상의 모든 상태 코드를 카운트하도록 bad_status_count로 확장
    bad_status_count: u64, // 💡 [신규] 400 이상의 상태 코드를 카운트
    dynamic_count: u64,
    static_count: u64,
    is_detected: bool, // 💡 [신규] 이미 봇으로 확정되어 터미널에 출력되었는지 여부 플래그
    detection_type: Option<String>, // 💡 [신규] 봇 탐지 유형 저장 (예: "Vulnerability Scanner", "Stealth Scraper")
}

const OUTPUT_FILE_NAME: &str = "output/ip/detected_bots.csv";
const OUTPUT_TEXT_FILE_NAME: &str = "output/ip/detected_bots.txt";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🛡️ 경량화된 실시간 2축(404 + 정적자원) 봇 탐지 엔진 가동...");

    // IP별 세션 카운터 보관소
    let mut memory_sessions: HashMap<String, LiveSession> = HashMap::new();

    // 💡 맨 끝에 "$host" 도메인이 추가된 로그 전용 정규식
    let log_regex = Regex::new(
        r#"(?P<ip>\S+) - - \[[^\]]+\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d+) \d+ "[^"]*" "(?P<ua>[^"]*)" \d+ \S+ \[[^\]]*\] \[\] .* "(?P<host>[^"]*)"#,
    )?;
    // 원본 실시간 로그 파일 스트림 연결
    let file = File::open("../ingress_nginx.log")?;
    let metadata = file.metadata()?;
    let pb = ProgressBar::new(metadata.len());
    pb.set_style(ProgressStyle::default_bar().template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} | 고속 스캔 중...")?);

    let reader = BufReader::new(file);
    let mut total_lines = 0;
    let mut cmsn_lines = 0;
    let mut unique_bot_ips_count = 0; // 💡 중복을 제외한 고유 '봇 IP 개수' 카운터로 변경

    for line in reader.lines().filter_map(Result::ok) {
        pb.inc(line.len() as u64 + 1);
        total_lines += 1;

        if let Some(caps) = log_regex.captures(&line) {
            let host_domain = &caps["host"];
            let url_path = &caps["url"];
            let url_lower = url_path.to_lowercase();
            let ua = caps["ua"].to_lowercase();
            let ip_str = caps["ip"].to_string();

            // 💡 [핵심 필터 1] 가공된 호스트 도메인을 기반으로 우마미, 그라파나 등 타 서브도메인 인프라 원천 배제
            //    본진 서비스(cmsn.info)와 백엔드 API(api.cmsn.info)로 들어온 트래픽만 통계 집계에 포함합니다.
            if host_domain != "cmsn.info" && host_domain != "api.cmsn.info" {
                continue;
            }

            // 💡 [핵심 필터 2] 시스템 모니터링 툴(Uptime Kuma 등) 및 화이트리스트 검색 봇 패스
            if ua.contains("uptime-kuma") || ua.contains("googlebot") || ua.contains("twitterbot") {
                continue;
            }

            // 💡 [핵심 필터 3] 내부 사설 네트워크(컨테이너 간 통신 대역)는 탐지에서 제외
            let is_internal_network = ip_str.starts_with("10.")
                || ip_str.starts_with("192.168.")
                || (ip_str.starts_with("172.") && {
                    // 172.16.0.0 - 172.31.255.255 범위 체크
                    ip_str
                        .split('.')
                        .nth(1)
                        .and_then(|s| s.parse::<u8>().ok())
                        .map_or(false, |octet| (16..=31).contains(&octet))
                });

            if is_internal_network {
                // 내부 IP면 분석하지 않고 건너뛰어 외부 트래픽에만 집중합니다.
                // 이 IP에 대한 세션 정보도 `memory_sessions`에 생성되지 않으므로
                // 최종 보고서의 '발견된 고유 IP 수'에서도 자연스럽게 제외됩니다.
                continue;
            }
            cmsn_lines += 1; // 본진 유효 트래픽 카운트 증가

            let status_code: i32 = caps["status"].parse().unwrap_or(0);

            // 해당 IP의 카운터 맵 획득
            let session = memory_sessions.entry(ip_str.clone()).or_default();

            // 💡 [정제 정교화을 위한 사전 동적/정적 판단]
            let is_static_file = url_lower.contains(".css")
                || url_lower.contains(".js")
                || url_lower.contains(".png")
                || url_lower.contains(".jpg")
                || url_lower.contains(".jpeg")
                || url_lower.contains(".ico")
                || url_lower.contains(".svg")
                || url_lower.contains(".woff")
                || url_lower.contains("/api/images");

            // 💡 [위치 교정 핵심] 만약 이미 봇으로 마킹이 끝난 IP라면 카운트만 올리고 실시간 탐지 연산/출력은 완전히 건너뜁니다.
            //    판정부 최상단으로 이동하여 불필요한 즉결 처분 문자열 비교 스캔 연산까지 완벽하게 스킵합니다.
            if session.is_detected {
                session.total_requests += 1;
                if status_code >= 400 {
                    session.bad_status_count += 1;
                } // 400 이상 상태 코드 카운트

                if is_static_file {
                    session.static_count += 1;
                } else {
                    session.dynamic_count += 1;
                }
                continue;
            }

            session.total_requests += 1;

            // 1. 400 이상 에러 카운트 (400, 401, 403, 404)
            if status_code == 400 || status_code == 401 || status_code == 403 || status_code == 404
            {
                session.bad_status_count += 1;
            }

            // 2. 정적 자원 vs 동적 문서 카운트 판정 정교화
            if is_static_file {
                session.static_count += 1;
            } else {
                session.dynamic_count += 1;
            }

            // 개발팀 내부 모니터링(Grafana) 및 정상적인 서비스용 검색/분석 API 예외 필터
            let is_normal_app_api = url_lower.contains("/api/ds/") 
                || url_lower.contains("/api/query")
                || url_lower.contains("/api/items")     // 정상적인 피드 검색 API
                || url_lower.contains("/api/users/slug") // 존재 유무 확인용 유저 슬러그 API
                || url_lower.contains("/api/send")       // 분석 로그 전송 API
                || url_lower.contains("/api/record") // 기록용 API
                || url_lower.contains("/public/build/")
                || url_lower.contains("/websites"); // 우마미 웹사이트 메뉴

            // 3. 복합 행동 실시간 판정 (IP당 최소 요청 15회 이상 쌓였을 때)
            if session.total_requests >= 15 {
                let bad_status_ratio =
                    session.bad_status_count as f64 / session.total_requests as f64; // 400 이상 상태 코드 비율
                // 💡 '전체 요청 중 정적 자원의 실제 점유 백분율'
                let static_percentage = session.static_count as f64 / session.total_requests as f64;

                // 판정 필터 A: 민감 정보만 찌르고 다니는 404 악성 스캐너 (Advin 같은 봇)
                let is_vulnerability_scanner = bad_status_ratio > 0.80;

                // 판정 필터 B: 404 에러는 안 내지만 정적 자원(이미지/스타일)을 전혀 안 읽고
                //             동적 텍스트/API만 긁어가는 은밀한 데이터 스크레이퍼 (AI 크롤러)
                let is_stealth_scraper =
                    static_percentage < 0.2 && session.dynamic_count >= 10 && !is_normal_app_api;

                // 💡 [신규] User-Agent에 기반한 정상 크롤러 예외 처리
                if is_vulnerability_scanner || is_stealth_scraper {
                    let ua_lower = ua.to_lowercase();
                    if ua_lower.contains("googlebot")
                        || ua_lower.contains("bingbot")
                        || ua_lower.contains("twitterbot")
                        || ua_lower.contains("applebot")
                        || ua_lower.contains("yandexbot")
                    {
                        // 정상 크롤러로 판단되면, 악성 봇으로 탐지하지 않고 건너뜁니다.
                        // 이 IP는 계속 모니터링은 되지만, 악성으로 분류되지는 않습니다.
                        continue;
                    }
                }

                if is_vulnerability_scanner || is_stealth_scraper {
                    session.is_detected = true; // 플래그를 참으로 만들어 다음 루프부터 이 IP는 즉시 스킵되도록 격리합니다.
                    session.detection_type = Some(if is_vulnerability_scanner {
                        "Vulnerability Scanner".to_string()
                    } else {
                        "Stealth Scraper".to_string()
                    });
                    unique_bot_ips_count += 1; // 고유 봇 IP 카운트 증가

                    if unique_bot_ips_count <= 20 {
                        // 터미널 도배 방지를 위해 상위 유니크 20개까지만 출력
                        pb.suspend(|| {
                            println!("🚨 [봇 검출] IP: {} | 타입: {} | 400+비율: {:.0}% | 정적자원비율: {:.2}",
                                     ip_str,
                                     session.detection_type.as_ref().unwrap(),
                                     bad_status_ratio * 100.0,
                                    static_percentage);
                        });
                    }
                }
            }
        }
    }

    pb.finish_with_message("검사 완료");

    // 봇으로 검출된 IP들을 파일로 저장합니다.
    let mut bot_details: Vec<(&String, &LiveSession)> = memory_sessions
        .iter()
        .filter(|(_, session)| session.is_detected)
        .collect();
    bot_details.sort_by_key(|(ip, _)| *ip); // 가독성을 위해 IP 정렬

    // 1. OUTPUT_FILE_NAME의 상위 폴더가 없다면 모두 생성
    if let Some(parent) = Path::new(OUTPUT_FILE_NAME).parent() {
        fs::create_dir_all(parent)?;
    }

    // 2. OUTPUT_TEXT_FILE_NAME의 상위 폴더가 없다면 모두 생성
    if let Some(parent) = Path::new(OUTPUT_TEXT_FILE_NAME).parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = File::create(OUTPUT_FILE_NAME)?;
    let mut text_file = File::create(OUTPUT_TEXT_FILE_NAME)?;

    writeln!(file, "IP,DetectionType,BadStatusRatio,StaticResourceRatio")?; // csv 헤더 추가

    for (ip, session) in &bot_details {
        let bad_status_ratio = if session.total_requests > 0 {
            session.bad_status_count as f64 / session.total_requests as f64
        } else {
            0.0
        };
        let static_percentage = if session.total_requests > 0 {
            session.static_count as f64 / session.total_requests as f64
        } else {
            0.0
        };
        writeln!(
            file,
            "{},{},{:.2},{:.2}",
            ip,
            session
                .detection_type
                .as_ref()
                .unwrap_or(&"Unknown".to_string()),
            bad_status_ratio * 100.0, // 백분율로 표시
            static_percentage
        )?;

        // 보기 좋은 텍스트 파일로도 저장.
        // 저장 내용: println!("🚨 [봇 검출] IP: {} | 타입: {} | 400+비율: {:.0}% | 정적자원비율: {:.2}",
        writeln!(
            text_file,
            "🚨 [BOT] IP: {} | Type: {} | 400+ ratio: {:.0}% | Static resource ratio: {:.2}",
            ip,
            session
                .detection_type
                .as_ref()
                .unwrap_or(&"Unknown".to_string()),
            bad_status_ratio * 100.0, // 백분율로 표시
            static_percentage
        )?;
    }

    println!("\n=== 📊 CMSN 전용 도메인 탐지 보고서 ===");
    println!("- 인그레스 총 로그 라인 : {} 건", total_lines);
    println!(
        "- CMSN 본진 선별 로그   : {} 건 (전체의 {:.1}%)",
        cmsn_lines,
        (cmsn_lines as f64 / total_lines as f64) * 100.0
    );
    println!("- 실시간 격리된 고유 공격 봇 : {} 개 IP", bot_details.len()); // 💡 신뢰도 정합성 일치
    println!("- 결과 파일 저장 완료   : {} ", OUTPUT_FILE_NAME);

    Ok(())
}
