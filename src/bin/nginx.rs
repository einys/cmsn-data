// ../ingress_nginx.log 로
// ../ingress_analytics.db 생성

use glob::glob;
use regex::Regex;
use rusqlite::{Connection, params};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. SQLite 데이터베이스 파일 생성 및 연결
    let db_path = format!("../ingress_analytics.db");
    let mut conn = Connection::open(&db_path)?;

    // 2. 로그를 담을 테이블 생성 (인덱스까지 추가해서 조회 속도 확보)
    // user_agent 컬럼을 추가했습니다.
    conn.execute(
        "CREATE TABLE IF NOT EXISTS nginx_logs (
            ip TEXT,
            timestamp TEXT,
            method TEXT,
            url TEXT,
            status INTEGER,
            user_agent TEXT,
            host TEXT
        )",
        [],
    )?;

    // 3. 로그 파싱용 정규식
    // Nginx Combined 포맷 뒷부분의 Referer와 User Agent까지 캡처하도록 확장했습니다.
    // (?P<user_agent>[^\"]+) 부분이 큰따옴표 안의 UA 문자열을 가져옵니다.
    let log_regex = Regex::new(
        r#"(?P<ip>\S+) - - \[(?P<time>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) \S+" (?P<status>\d+) \d+ "[^"]*" "(?P<ua>[^"]*)" \d+ \S+ \[[^\]]*\] \[\] .* "(?P<host>[^"]*)"#,
    )?;

    // 4. 대상 파일 목록 수집
    let pattern = format!("../ingress_nginx.log");
    let file_paths: Vec<PathBuf> = glob(&pattern)?.filter_map(Result::ok).collect();

    println!(
        "총 {}개의 파일을 SQLite로 마이그레이션합니다...",
        file_paths.len()
    );

    // 5. SQLite 성능의 핵심: 하나의 대형 트랜잭션으로 묶어서 Write 오버헤드 줄이기
    let tx = conn.transaction()?;

    {
        // 최적화된 Insert Statement 준비
        // user_agent 파라미터(?5)를 추가했습니다.
        let mut stmt =
            tx.prepare("INSERT INTO nginx_logs (ip, timestamp, method, url, status, user_agent, host) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)")?;

        for path in file_paths {
            if let Ok(file) = File::open(path) {
                let reader = BufReader::new(file);
                for line in reader.lines().filter_map(Result::ok) {
                    if let Some(caps) = log_regex.captures(&line) {
                        let ip = &caps["ip"];
                        let timestamp = &caps["time"];
                        let method = &caps["method"];
                        let url = &caps["url"];
                        let status: i32 = caps["status"].parse().unwrap_or(0);
                        // 정규식에서 user_agent 그룹을 추출하며, 매칭되지 않을 경우 공백 지정
                        let user_agent = caps.name("ua").map_or("-", |m| m.as_str());
                        // host 컬럼도 추출
                        let host = caps.name("host").map_or("-", |m| m.as_str());

                        // DB에 삽입
                        stmt.execute(params![
                            ip, timestamp, method, url, status, user_agent, host
                        ])?;
                    }
                }
            }
        }
    } // stmt의 수명이 여기서 끝나야 commit이 가능합니다.

    // 트랜잭션 커밋
    tx.commit()?;
    println!("마이그레이션 완료! DB 파일 위치: {}", db_path);

    // 6. 자주 조회할 컬럼에 인덱스 걸기 (마이그레이션 후에 걸어야 속도가 빠릅니다)
    println!("인덱스 생성 중...");
    conn.execute("CREATE INDEX IF NOT EXISTS idx_url ON nginx_logs(url)", [])?;
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_status ON nginx_logs(status)",
        [],
    )?;
    conn.execute("CREATE INDEX IF NOT EXISTS idx_ip ON nginx_logs(ip)", [])?;
    // UdgerDB와 연동할 때 고속 조회를 위해 user_agent 컬럼에도 인덱스를 추가합니다.
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_ua ON nginx_logs(user_agent)",
        [],
    )?;
    println!("모든 작업이 완료되었습니다.");

    Ok(())
}
