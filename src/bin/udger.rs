use rusqlite::{Connection, Result};
use std::env;

#[derive(Debug)]
struct IpInfo {
    ip: String,
    crawler_id: Option<i32>,
    ip_hostname: Option<String>,
    ip_country: Option<String>,
    ip_city: Option<String>,
    ip_country_code: Option<String>,
}

fn main() -> Result<()> {
    // 1. 데이터베이스 연결
    // (앞서 경로 문제가 발생했으므로, 절대 경로로 적거나 파일이 프로젝트 루트에 있다면 "udgerdb_v3.dat"로 수정해 주세요)
    let db_path = "../udgerdb_v3.dat";
    let conn = Connection::open(db_path)?;

    // 2. 검색할 IP (인자로 받거나 기본값 설정)
    let args: Vec<String> = env::args().collect();
    let target_ip_str = if args.len() > 1 {
        &args[1]
    } else {
        "1.1.1.1" // 테스트용 기본값
    };

    println!("🔎 검색 중인 IP: {}", target_ip_str);

    // 3. 확인된 컬럼명을 반영한 단순 문자열 매칭 쿼리 실행
    let mut stmt = conn.prepare(
        "SELECT ip, crawler_id, ip_hostname, ip_country, ip_city, ip_country_code 
         FROM udger_ip_list 
         WHERE ip = ?1 
         LIMIT 1",
    )?;

    let ip_iter = stmt.query_row([target_ip_str], |row| {
        Ok(IpInfo {
            ip: row.get(0)?,
            crawler_id: row.get(1).ok(),
            ip_hostname: row.get(2).ok(),
            ip_country: row.get(3).ok(),
            ip_city: row.get(4).ok(),
            ip_country_code: row.get(5).ok(),
        })
    });

    // 4. 결과 출력
    match ip_iter {
        Ok(info) => {
            println!("✅ 발견됨: {:?}", info);
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            println!(
                "❌ 해당 IP({ })에 대한 정보를 찾을 수 없습니다.",
                target_ip_str
            );
        }
        Err(e) => println!("⚠️ 에러 발생: {}", e),
    }

    Ok(())
}
