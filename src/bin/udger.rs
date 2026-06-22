use rusqlite::{Connection, params};
use std::collections::HashMap;
use std::fs::{self, File};
use std::net::IpAddr;
// indicatif에서 필요한 컴포넌트 임포트
use indicatif::{ProgressBar, ProgressStyle};
// plotters 및 csv 컴포넌트 임포트
use plotters::prelude::*;

const OUT_DIR: &str = "output/udger";
// 통계 출력을 위한 전역 상수 정의
const TOP_N_DC: usize = 10;
const TOP_N_COUNTRY: usize = 10;
const TOP_N_URL: usize = 20;
const TOP_N_CRAWLER: usize = 10;

const KNOWN_IP_DATA: &str = "../udgerdb_v3.dat";
const INGRESS_DATA: &str = "../ingress_analytics.db";

fn ip_to_long(ip: &IpAddr) -> Option<u32> {
    match ip {
        IpAddr::V4(ipv4) => Some(u32::from(*ipv4)),
        IpAddr::V6(_) => None,
    }
}

fn draw_bar_chart(val: u64, max_val: u64, max_bars: usize) -> String {
    if max_val == 0 {
        return "".to_string();
    }
    let fill_count = ((val as f64 / max_val as f64) * max_bars as f64).round() as usize;
    let mut bar = "█".repeat(fill_count);
    if fill_count < max_bars
        && (val as f64 / max_val as f64) * max_bars as f64 - fill_count as f64 > 0.3
    {
        bar.push('▌');
    }
    bar
}

// plotters를 사용해 결과를 가로형 바 차트 이미지로 저장하는 헬퍼 함수
fn save_chart_image(
    file_name: &str,
    title: &str,
    data: &[(&String, &u64)],
) -> Result<(), Box<dyn std::error::Error>> {
    if data.is_empty() {
        return Ok(());
    }

    let root = BitMapBackend::new(file_name, (800, 450)).into_drawing_area();
    root.fill(&WHITE)?;

    let max_val = *data.iter().map(|x| x.1).max().unwrap_or(&1);

    // 차트 레이아웃 설정
    let mut chart = ChartBuilder::on(&root)
        .caption(title, ("sans-serif", 22).into_font())
        .margin(20)
        .x_label_area_size(40)
        .y_label_area_size(180) // 라벨이 잘리지 않도록 좌측 여백 확보
        .build_cartesian_2d(0..max_val, 0..data.len())?;

    chart
        .configure_mesh()
        .x_desc("요청 수 (건)")
        .y_label_style(("sans-serif", 12).into_font())
        .y_label_formatter(&|y| {
            if *y < data.len() {
                let label = data[*y].0;
                if label.len() > 22 {
                    format!("{}...", &label[..19])
                } else {
                    label.to_string()
                }
            } else {
                "".to_string()
            }
        })
        .draw()?;

    // 바 차트 그리기
    for (idx, (_, count)) in data.iter().enumerate() {
        chart.draw_series(std::iter::once(Rectangle::new(
            [(0, idx), (**count, idx + 1)],
            RGBAColor(42, 74, 106, 0.8).filled(), // 학술용 차트에 어울리는 차분한 Navy 톤
        )))?;
    }

    root.present()?;
    println!("📈 시각화 차트 저장 완료: {}", file_name);
    Ok(())
}

// 데이터를 CSV 파일로 저장하는 헬퍼 함수
fn save_to_csv(
    file_name: &str,
    headers: &[&str],
    data: &[(&String, &u64)],
) -> Result<(), Box<dyn std::error::Error>> {
    let mut wtr = csv::Writer::from_path(file_name)?;
    wtr.write_record(headers)?;
    for (label, count) in data {
        wtr.write_record(&[label.to_string(), count.to_string()])?;
    }
    wtr.flush()?;
    println!("💾 CSV 데이터 저장 완료: {}", file_name);
    Ok(())
}

// 단일 IP의 봇/데이터센터 여부를 조회하는 헬퍼 함수
fn check_single_ip(
    udger_conn: &Connection,
    ip_str: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let ip_addr: IpAddr = match ip_str.parse() {
        Ok(addr) => addr,
        Err(_) => {
            println!("❌ 유효하지 않은 IP 주소 형식입니다: {}", ip_str);
            return Ok(());
        }
    };

    println!("\n=====================================================================");
    println!("🔍 단일 IP UdgerDB 정밀 조회: {}", ip_str);
    println!("=====================================================================");

    let mut is_detected = false;

    // [A] 데이터센터 조회
    if let Some(ip_long) = ip_to_long(&ip_addr) {
        let mut dc_stmt = udger_conn.prepare(
            "SELECT l.name, l.homepage FROM udger_datacenter_range r 
             JOIN udger_datacenter_list l ON r.datacenter_id = l.id 
             WHERE ?1 BETWEEN r.iplong_from AND r.iplong_to LIMIT 1",
        )?;
        let mut dc_rows = dc_stmt.query(params![ip_long])?;
        if let Some(dc_row) = dc_rows.next()? {
            let dc_name: String = dc_row.get(0)?;
            let dc_home: String = dc_row.get(1).unwrap_or_else(|_| "-".to_string());
            println!("🏢 [데이터센터 검출]");
            println!("  - 인프라명: {}", dc_name);
            println!("  - 홈페이지: {}", dc_home);
            is_detected = true;
        }
    }

    // [B] 알려진 봇/크롤러 IP 조회 (기존 main 구조와 일치하도록 스키마 안정성 확보)
    let mut ip_list_stmt = udger_conn.prepare(
        "SELECT i.ip_country, c.name 
         FROM udger_ip_list i
         LEFT JOIN udger_crawler_list c ON i.crawler_id = c.id
         WHERE i.ip = ?1 LIMIT 1",
    )?;

    let mut ip_list_rows = ip_list_stmt.query(params![ip_str])?;
    if let Some(ip_list_row) = ip_list_rows.next()? {
        let country: Option<String> = ip_list_row.get(0)?;
        let crawler_name: Option<String> = ip_list_row.get(1)?;
        let crawler_family: Option<String> = ip_list_row.get(2)?;
        let author: Option<String> = ip_list_row.get(3)?;
        let author_url: Option<String> = ip_list_row.get(4)?;

        println!("\n🤖 [알려진 IP/봇 검출]");
        println!(
            "  - 국가: {}",
            country.unwrap_or_else(|| "Unknown".to_string())
        );
        println!(
            "  - 봇 이름: {}",
            crawler_name.unwrap_or_else(|| "Unclassified Bot".to_string())
        );
        println!(
            "  - 계열(Family): {}",
            crawler_family.unwrap_or_else(|| "-".to_string())
        );
        println!(
            "  - 제작사(Author): {} ({})",
            author.unwrap_or_else(|| "-".to_string()),
            author_url.unwrap_or_else(|| "-".to_string())
        );
        is_detected = true;
    }

    if !is_detected {
        println!("✅ UdgerDB에 등록되지 않은 일반 IP이거나 탐지되지 않은 주소입니다.");
    }
    println!("=====================================================================\n");

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // CLI 인자 파싱 (첫 번째 인자는 실행 파일 경로이므로 두 번째 인자가 IP인지 확인)
    let args: Vec<String> = std::env::args().collect();

    // 1. DB 로드 (공통 사용)
    let udger_conn = Connection::open(KNOWN_IP_DATA)?;

    if args.len() > 1 {
        // 인자가 주어지면 단일 IP 조회 CLI 모드로 동작
        check_single_ip(&udger_conn, &args[1])?;
        return Ok(());
    }

    // 인자가 없으면 기존 전체 통계 분석 모드로 동작
    println!("⚙️ Udger 데이터베이스 로드 성공.");

    // 0. 출력 디렉토리 생성
    fs::create_dir_all(OUT_DIR)?;

    udger_conn.execute(
        &format!("ATTACH DATABASE {} AS ingress_db", INGRESS_DATA),
        [],
    )?;
    println!("⚙️ 인그레스 로그 DB 결합 완료.");

    let mut datacenter_stats: HashMap<String, u64> = HashMap::new();
    let mut known_ip_stats: HashMap<String, u64> = HashMap::new();
    let mut known_ip_url_stats: HashMap<String, u64> = HashMap::new();
    let mut crawler_name_stats: HashMap<String, u64> = HashMap::new(); // 크롤러/봇 이름 통계 추가
    let mut known_ip_details: HashMap<String, (String, String, u64)> = HashMap::new();

    let mut total_logs = 0;
    let mut datacenter_hits = 0;
    let mut known_ip_hits = 0;

    // 2. Prepared Statements
    let mut dc_stmt = udger_conn.prepare(
        "SELECT l.name FROM udger_datacenter_range r 
         JOIN udger_datacenter_list l ON r.datacenter_id = l.id 
         WHERE ?1 BETWEEN r.iplong_from AND r.iplong_to LIMIT 1",
    )?;

    // udger_ip_list 조회 시 크롤러 이름 메타 맵핑 조인 구조
    let mut ip_list_stmt = udger_conn.prepare(
        "SELECT i.ip_country, c.name 
         FROM udger_ip_list i
         LEFT JOIN udger_crawler_list c ON i.crawler_id = c.id
         WHERE i.ip = ?1 LIMIT 1",
    )?;

    // 3. [프로그래스 바 준비 단계] 전체 처리할 유니크 레코드 수 미리 카운트
    println!("📊 처리 대상을 식별하는 중...");
    let total_rows_to_process: u64 = udger_conn.query_row(
        "SELECT COUNT(*) FROM (SELECT ip, url, user_agent FROM ingress_db.nginx_logs GROUP BY ip, url, user_agent)",
        [],
        |row| row.get(0),
    )?;

    // 4. 프로그래스 바 생성 및 스타일 테마 정의
    let pb = ProgressBar::new(total_rows_to_process);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({percent}%) | ETA: {eta}")?
        .progress_chars("#>-"));

    // 5. 쿼리 실행
    let mut log_stmt = udger_conn
        .prepare("SELECT ip, url, user_agent, COUNT(*) as cnt FROM ingress_db.nginx_logs GROUP BY ip, url, user_agent")?;
    let mut rows = log_stmt.query([])?;

    // 매칭 스캔과 함께 프로그래스 바 업데이트 시작
    while let Some(row) = rows.next()? {
        let ip_str: String = row.get(0)?;
        let url: String = row.get(1)?;
        let raw_ua: String = row.get(2).unwrap_or_else(|_| "Missing UA".to_string());
        let count: u64 = row.get(3)?;
        total_logs += count;

        if let Ok(ip_addr) = ip_str.parse::<IpAddr>() {
            // [A] 데이터센터 매칭
            if let Some(ip_long) = ip_to_long(&ip_addr) {
                let mut dc_rows = dc_stmt.query(params![ip_long])?;
                if let Some(dc_row) = dc_rows.next()? {
                    let dc_name: String = dc_row.get(0)?;
                    *datacenter_stats.entry(dc_name).or_insert(0) += count;
                    datacenter_hits += count;
                }
            }

            // [B] 알려진 IP 및 경로 매칭
            let mut ip_list_rows = ip_list_stmt.query(params![ip_str])?;
            if let Some(ip_list_row) = ip_list_rows.next()? {
                let country: Option<String> = ip_list_row.get(0)?;
                let country_name = country.unwrap_or_else(|| "Unknown/Private".to_string());
                *known_ip_stats.entry(country_name.clone()).or_insert(0) += count;
                known_ip_hits += count;

                *known_ip_url_stats.entry(url).or_insert(0) += count;

                let crawler_name: Option<String> = ip_list_row.get(1)?;
                let final_crawler_name = crawler_name.unwrap_or_else(|| {
                    if raw_ua.contains("Googlebot") {
                        "Googlebot (Est.)".to_string()
                    } else if raw_ua.contains("bingbot") {
                        "Bingbot (Est.)".to_string()
                    } else {
                        "Unclassified Bot".to_string()
                    }
                });
                *crawler_name_stats
                    .entry(final_crawler_name.clone())
                    .or_insert(0) += count;

                let entry =
                    known_ip_details
                        .entry(ip_str)
                        .or_insert((country_name, final_crawler_name, 0));
                entry.2 += count;
            }
        }

        // 행을 하나 처리할 때마다 프로그래스 바를 1씩 전진시킵니다.
        pb.inc(1);
    }

    // 작업 완료 후 프로그래스 바 종료 표시
    pb.finish_with_message("조회 완료");

    // 6. 통계 및 최종 텍스트 차트 출력
    println!("\n=====================================================================");
    println!("📊 UdgerDB 통합 분석 및 유입 시각화 보고서");
    println!("=====================================================================");
    println!("- 전체 수집 로그 수             : {} 건", total_logs);
    if total_logs > 0 {
        println!(
            "- 데이터센터(클라우드/IDC) IP 유입 : {} 건 ({:.2}%)",
            datacenter_hits,
            (datacenter_hits as f64 / total_logs as f64) * 100.0
        );
        println!(
            "- 알려진 IP 리스트 매칭 유입     : {} 건 ({:.2}%)",
            known_ip_hits,
            (known_ip_hits as f64 / total_logs as f64) * 100.0
        );
    }

    println!("\n[ 🏢 데이터센터별 유입 통계 (Top {}) ]", TOP_N_DC);
    let mut dc_vec: Vec<(&String, &u64)> = datacenter_stats.iter().collect();
    dc_vec.sort_by(|a, b| b.1.cmp(a.1));
    let max_dc = dc_vec.first().map(|x| *x.1).unwrap_or(0);
    for (name, count) in dc_vec.iter().take(TOP_N_DC) {
        let bar = draw_bar_chart(**count, max_dc, 30);
        println!("- {:<30} : {:>8} 건 {}", name, count, bar);
    }

    println!(
        "\n[ 🗺️ 알려진 IP 리스트 국가별 통계 (Top {}) ]",
        TOP_N_COUNTRY
    );
    let mut ip_vec: Vec<(&String, &u64)> = known_ip_stats.iter().collect();
    ip_vec.sort_by(|a, b| b.1.cmp(a.1));
    let max_ip = ip_vec.first().map(|x| *x.1).unwrap_or(0);
    for (country, count) in ip_vec.iter().take(TOP_N_COUNTRY) {
        let bar = draw_bar_chart(**count, max_ip, 30);
        println!("- {:<30} : {:>8} 건 {}", country, count, bar);
    }

    println!(
        "\n[ 🎯 알려진 IP(봇/크롤러)의 다빈도 방문 경로 (Top {}) ]",
        TOP_N_URL
    );
    let mut url_vec: Vec<(&String, &u64)> = known_ip_url_stats.iter().collect();
    url_vec.sort_by(|a, b| b.1.cmp(a.1));
    let max_url = url_vec.first().map(|x| *x.1).unwrap_or(0);

    for (url, count) in url_vec.iter().take(TOP_N_URL) {
        let bar = draw_bar_chart(**count, max_url, 30);
        let display_url = if url.len() > 45 {
            format!("{}...", &url[..42])
        } else {
            url.to_string()
        };
        println!("- {:<45} : {:>8} 건 {}", display_url, count, bar);
    }

    // [새 분석 지표] 매칭된 알려진 IP의 크롤러/유저 에이전트 통계 출력
    println!(
        "\n[ 🤖 매칭된 알려진 IP의 크롤러/유저 에이전트 식별 통계 (Top {}) ]",
        TOP_N_CRAWLER
    );
    let mut crawler_vec: Vec<(&String, &u64)> = crawler_name_stats.iter().collect();
    crawler_vec.sort_by(|a, b| b.1.cmp(a.1));
    let max_crawler = crawler_vec.first().map(|x| *x.1).unwrap_or(0);

    for (crawler_name, count) in crawler_vec.iter().take(TOP_N_CRAWLER) {
        let bar = draw_bar_chart(**count, max_crawler, 30);
        let display_name = if crawler_name.len() > 30 {
            format!("{}...", &crawler_name[..27])
        } else {
            crawler_name.to_string()
        };
        println!("- {:<30} : {:>8} 건 {}", display_name, count, bar);
    }

    // 7. 데이터 영구 저장 단계 (CSV 내보내기 및 Plotters를 통한 PNG 그래프 시각화 생성)
    println!("\n=====================================================================");
    println!("💾 데이터 파일 추출 및 파일 시각화 프로세스 가동");
    println!("=====================================================================");

    // 데이터센터 통계 파일화
    let top_dc_data: Vec<(&String, &u64)> = dc_vec.iter().take(TOP_N_DC).cloned().collect();
    save_to_csv(
        &format!("{}/datacenter_stats.csv", OUT_DIR),
        &["Datacenter", "Requests"],
        &top_dc_data,
    )?;
    save_chart_image(
        &format!("{}/datacenter_chart.png", OUT_DIR),
        &format!("Top {} Datacenter Infrastructure Traffic", TOP_N_DC),
        &top_dc_data,
    )?;

    // 봇 식별 명세 통계 파일화
    let top_crawler_data: Vec<(&String, &u64)> =
        crawler_vec.iter().take(TOP_N_CRAWLER).cloned().collect();
    save_to_csv(
        &format!("{}/crawler_stats.csv", OUT_DIR),
        &["Crawler_Name", "Requests"],
        &top_crawler_data,
    )?;
    save_chart_image(
        &format!("{}/crawler_chart.png", OUT_DIR),
        &format!("Top {} Identified Bot Traffic (UdgerDB)", TOP_N_CRAWLER),
        &top_crawler_data,
    )?;

    // 다빈도 표적 경로 명세 통계 파일화
    let top_url_data: Vec<(&String, &u64)> = url_vec.iter().take(TOP_N_URL).cloned().collect();
    save_to_csv(
        &format!("{}/target_url_stats.csv", OUT_DIR),
        &["Target_URL", "Requests"],
        &top_url_data,
    )?;
    save_chart_image(
        &format!("{}/target_url_chart.png", OUT_DIR),
        &format!("Top {} Target Endpoints Visited by Bots", TOP_N_URL),
        &top_url_data,
    )?;

    // [추가] 모든 탐지된 알려진 IP 리스트 CSV 저장
    let mut ip_details_vec: Vec<_> = known_ip_details.into_iter().collect();
    ip_details_vec.sort_by(|a, b| b.1.2.cmp(&a.1.2));

    let known_ips_csv = format!("{}/known_ips.csv", OUT_DIR);
    let mut wtr = csv::Writer::from_path(&known_ips_csv)?;
    wtr.write_record(&["IP", "Country", "Crawler", "Requests"])?;
    for (ip, (country, crawler, count)) in ip_details_vec {
        wtr.write_record(&[ip, country, crawler, count.to_string()])?;
    }
    wtr.flush()?;
    println!("💾 알려진 IP 상세 리스트 저장 완료: {}", known_ips_csv);

    Ok(())
}
