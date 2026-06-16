# SQLite 웹 GUI 도구인 sqlite-web을 기반 이미지로 사용
FROM coleifer/sqlite-web:latest

# 컨테이너 내부에 DB 파일이 마운트될 디렉토리 생성
WORKDIR /data

# 환경변수로 컨테이너가 읽을 기본 DB 파일 경로 지정
ENV SQLITE_DATABASE=/data/udgardb_v3.dat

# 웹 뷰어가 사용할 8080 포트 개방
EXPOSE 8080