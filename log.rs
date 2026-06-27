use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("⚙️ [Data Enrichment] 기존 인그레스 로그 내 호스트 도메인 복원 작업 시작...");

    let input_path = "../ingress_nginx_1month_total.log";
    let output_path = "../ingress_nginx.log";

    let file = File::open(input_path)?;
    let metadata = file.metadata()?;

    // 프로그래스 바 라인 가동
    let pb = ProgressBar::new(metadata.len());
    pb.set_style(ProgressStyle::default_bar().template("{spinner:.cyan} [{elapsed_precise}] [{bar:40.cyan/blue}] {bytes}/{total_bytes} | 로그 데이터 가공 중...")?);

    let reader = BufReader::new(file);
    // 쓰기 성능 최적화를 위해 BufWriter 사용
    let mut writer = BufWriter::new(File::create(output_path)?);

    // 💡 [수정] 서비스명 뒤의 빈 대괄호 ' []' 패턴까지 정확하게 매칭하도록 정규식 보정
    let log_regex = Regex::new(r#"(?P<before>.*) \[(?P<k8s_service>[^\]]*)\] \[\] (?P<after>.*)"#)?;

    let mut total_lines = 0;
    let mut enriched_lines = 0;

    for line_result in reader.lines() {
        let line = match line_result {
            Ok(l) => l,
            Err(_) => continue,
        };

        pb.inc(line.len() as u64 + 1);
        total_lines += 1;

        if let Some(caps) = log_regex.captures(&line) {
            let k8s_service = &caps["k8s_service"];

            // 💡 인프라 라우팅 규칙에 기반한 호스트 도메인 1:1 리버스 복원
            // [수정] front-service와 back-service를 분리하여 각각 다른 서브도메인 매핑
            let host_domain = if k8s_service.contains("front-service") {
                "cmsn.info"
            } else if k8s_service.contains("back-service") {
                "api.cmsn.info" // 💡 백엔드 전용 서브도메인 격리 복원
            } else if k8s_service.contains("umami") {
                "umami.cmsn.info"
            } else if k8s_service.contains("grafana") {
                "grafana.cmsn.info"
            } else {
                "-"
            };

            // 💡 기존 로우 로그 맨 끝에 Nginx 표준 규격처럼 공백과 함께 "$host" 문자열 주입
            //    향후 실제 배포될 패치 버전 로그 포맷과 완전한 규격 동기화를 이룹니다.
            //    [보정] 출력할 때도 오리지널 포맷 유지를 위해 서비스명 뒤에 빈 대괄호 ' []' 복원
            writeln!(
                writer,
                r#"{} [{}] [] {} "{}""#,
                &caps["before"], k8s_service, &caps["after"], host_domain
            )?;
            enriched_lines += 1;
        } else {
            // 정규식에 매칭되지 않는 예외 라인도 데이터 보존을 위해 그대로 복사
            writeln!(writer, "{}", line)?;
        }
    }

    writer.flush()?;
    pb.finish_with_message("가공 완료");

    println!("\n=== ✨ 데이터 보정 작업 완료 보고서 ===");
    println!("- 원본 로그 라인 : {} 건", total_lines);
    println!("- 호스트 복원 라인 : {} 건", enriched_lines);
    println!("- 보정본 파일 생성 완료 : {}", output_path);

    Ok(())
}
