use plotters::prelude::*;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::env;
use std::fs;
use std::path::Path;

const DEFAULT_INPUT: &str = "output/route_nginx/session_features.csv";
const DEFAULT_EPS: f64 = 1.8;
const DEFAULT_MIN_POINTS: usize = 4;

#[derive(Debug, Deserialize, Clone)]
struct SessionFeature {
    visit_id: String,
    steps: f64,
    std_dwell: f64,
    cv_dwell: f64,
    entropy_dwell: f64,
    repeat_ratio: f64,
    autocorr_lag1: f64,
}

#[derive(Debug, Clone)]
struct ClusteredSession {
    feature: SessionFeature,
    cluster: i32,
    point_type: &'static str,
}

#[derive(Debug)]
struct Config {
    input_path: String,
    output_dir: String,
    eps: f64,
    min_points: usize,
}

fn parse_args() -> Result<Config, Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.iter().any(|arg| arg == "-h" || arg == "--help") {
        println!(
            "Usage: cargo run --bin dbscan -- [input_csv] [eps] [min_points] [output_dir]\n\
             Default: cargo run --bin dbscan -- {} {} {} output/dbscan_route_nginx",
            DEFAULT_INPUT, DEFAULT_EPS, DEFAULT_MIN_POINTS
        );
        std::process::exit(0);
    }

    let input_path = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| DEFAULT_INPUT.to_string());
    let eps = args
        .get(2)
        .map(|v| v.parse::<f64>())
        .transpose()?
        .unwrap_or(DEFAULT_EPS);
    let min_points = args
        .get(3)
        .map(|v| v.parse::<usize>())
        .transpose()?
        .unwrap_or(DEFAULT_MIN_POINTS);
    let output_dir = args.get(4).cloned().unwrap_or_else(|| {
        let stem = Path::new(&input_path)
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|s| s.to_str())
            .unwrap_or("features");
        format!("output/dbscan_{}", stem)
    });

    if eps <= 0.0 {
        return Err("eps must be greater than 0".into());
    }
    if min_points < 2 {
        return Err("min_points must be at least 2".into());
    }

    Ok(Config {
        input_path,
        output_dir,
        eps,
        min_points,
    })
}

fn load_features(path: &str) -> Result<Vec<SessionFeature>, Box<dyn std::error::Error>> {
    let mut reader = csv::Reader::from_path(path)?;
    let mut rows = Vec::new();

    for row in reader.deserialize() {
        let feature: SessionFeature = row?;
        rows.push(feature);
    }

    Ok(rows)
}

fn to_matrix(features: &[SessionFeature]) -> Vec<Vec<f64>> {
    features
        .iter()
        .map(|f| {
            vec![
                f.steps,
                f.std_dwell,
                f.cv_dwell,
                f.entropy_dwell,
                f.repeat_ratio,
                f.autocorr_lag1,
            ]
        })
        .collect()
}

fn zscore(matrix: &[Vec<f64>]) -> Vec<Vec<f64>> {
    if matrix.is_empty() {
        return Vec::new();
    }

    let rows = matrix.len();
    let cols = matrix[0].len();
    let mut means = vec![0.0; cols];
    let mut stds = vec![0.0; cols];

    for row in matrix {
        for (i, value) in row.iter().enumerate() {
            means[i] += value;
        }
    }
    for mean in &mut means {
        *mean /= rows as f64;
    }

    for row in matrix {
        for (i, value) in row.iter().enumerate() {
            stds[i] += (value - means[i]).powi(2);
        }
    }
    for std in &mut stds {
        *std = (*std / rows as f64).sqrt();
        if *std == 0.0 {
            *std = 1.0;
        }
    }

    matrix
        .iter()
        .map(|row| {
            row.iter()
                .enumerate()
                .map(|(i, value)| (value - means[i]) / stds[i])
                .collect()
        })
        .collect()
}

fn euclidean(a: &[f64], b: &[f64]) -> f64 {
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y).powi(2))
        .sum::<f64>()
        .sqrt()
}

fn region_query(points: &[Vec<f64>], idx: usize, eps: f64) -> Vec<usize> {
    points
        .iter()
        .enumerate()
        .filter_map(|(other_idx, point)| {
            if euclidean(&points[idx], point) <= eps {
                Some(other_idx)
            } else {
                None
            }
        })
        .collect()
}

fn dbscan(points: &[Vec<f64>], eps: f64, min_points: usize) -> Vec<i32> {
    const UNVISITED: i32 = -99;
    const NOISE: i32 = -1;

    let mut labels = vec![UNVISITED; points.len()];
    let mut cluster_id = 0;

    for point_idx in 0..points.len() {
        if labels[point_idx] != UNVISITED {
            continue;
        }

        let neighbors = region_query(points, point_idx, eps);
        if neighbors.len() < min_points {
            labels[point_idx] = NOISE;
            continue;
        }

        labels[point_idx] = cluster_id;
        let mut seeds = neighbors;
        let mut cursor = 0;

        while cursor < seeds.len() {
            let neighbor_idx = seeds[cursor];

            if labels[neighbor_idx] == NOISE {
                labels[neighbor_idx] = cluster_id;
            }

            if labels[neighbor_idx] != UNVISITED {
                cursor += 1;
                continue;
            }

            labels[neighbor_idx] = cluster_id;
            let next_neighbors = region_query(points, neighbor_idx, eps);
            if next_neighbors.len() >= min_points {
                for next_idx in next_neighbors {
                    if !seeds.contains(&next_idx) {
                        seeds.push(next_idx);
                    }
                }
            }

            cursor += 1;
        }

        cluster_id += 1;
    }

    labels
}

fn point_types(
    points: &[Vec<f64>],
    labels: &[i32],
    eps: f64,
    min_points: usize,
) -> Vec<&'static str> {
    points
        .iter()
        .enumerate()
        .map(|(idx, _)| {
            if labels[idx] == -1 {
                "noise"
            } else if region_query(points, idx, eps).len() >= min_points {
                "core"
            } else {
                "border"
            }
        })
        .collect()
}

fn save_labeled_csv(
    rows: &[ClusteredSession],
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut writer = csv::Writer::from_path(path)?;
    writer.write_record([
        "visit_id",
        "cluster",
        "point_type",
        "steps",
        "std_dwell",
        "cv_dwell",
        "entropy_dwell",
        "repeat_ratio",
        "autocorr_lag1",
    ])?;

    for row in rows {
        writer.write_record([
            row.feature.visit_id.as_str(),
            &row.cluster.to_string(),
            row.point_type,
            &format!("{:.4}", row.feature.steps),
            &format!("{:.4}", row.feature.std_dwell),
            &format!("{:.4}", row.feature.cv_dwell),
            &format!("{:.4}", row.feature.entropy_dwell),
            &format!("{:.4}", row.feature.repeat_ratio),
            &format!("{:.4}", row.feature.autocorr_lag1),
        ])?;
    }

    writer.flush()?;
    Ok(())
}

fn save_summary_csv(
    rows: &[ClusteredSession],
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut groups: BTreeMap<i32, Vec<&ClusteredSession>> = BTreeMap::new();
    for row in rows {
        groups.entry(row.cluster).or_default().push(row);
    }

    let mut writer = csv::Writer::from_path(path)?;
    writer.write_record([
        "cluster",
        "label",
        "count",
        "avg_steps",
        "avg_std_dwell",
        "avg_cv_dwell",
        "avg_entropy_dwell",
        "avg_repeat_ratio",
        "avg_autocorr_lag1",
    ])?;

    for (cluster, group) in groups {
        let n = group.len() as f64;
        let label = if cluster == -1 { "noise" } else { "cluster" };
        let avg = |value: fn(&SessionFeature) -> f64| -> f64 {
            group.iter().map(|row| value(&row.feature)).sum::<f64>() / n
        };

        writer.write_record([
            cluster.to_string(),
            label.to_string(),
            group.len().to_string(),
            format!("{:.4}", avg(|f| f.steps)),
            format!("{:.4}", avg(|f| f.std_dwell)),
            format!("{:.4}", avg(|f| f.cv_dwell)),
            format!("{:.4}", avg(|f| f.entropy_dwell)),
            format!("{:.4}", avg(|f| f.repeat_ratio)),
            format!("{:.4}", avg(|f| f.autocorr_lag1)),
        ])?;
    }

    writer.flush()?;
    Ok(())
}

fn draw_scatter(rows: &[ClusteredSession], path: &str) -> Result<(), Box<dyn std::error::Error>> {
    if rows.is_empty() {
        return Ok(());
    }

    let x_min = rows
        .iter()
        .map(|r| r.feature.entropy_dwell)
        .fold(f64::INFINITY, f64::min);
    let x_max = rows
        .iter()
        .map(|r| r.feature.entropy_dwell)
        .fold(f64::NEG_INFINITY, f64::max);
    let y_min = rows
        .iter()
        .map(|r| r.feature.repeat_ratio)
        .fold(f64::INFINITY, f64::min);
    let y_max = rows
        .iter()
        .map(|r| r.feature.repeat_ratio)
        .fold(f64::NEG_INFINITY, f64::max);

    let x_pad = ((x_max - x_min).abs() * 0.1).max(0.1);
    let y_pad = ((y_max - y_min).abs() * 0.1).max(0.05);

    let root = BitMapBackend::new(path, (1000, 650)).into_drawing_area();
    root.fill(&WHITE)?;

    let mut chart = ChartBuilder::on(&root)
        .caption(
            "DBSCAN Clusters: Entropy vs Repeat Ratio",
            ("sans-serif", 22),
        )
        .margin(35)
        .x_label_area_size(55)
        .y_label_area_size(65)
        .build_cartesian_2d(
            (x_min - x_pad)..(x_max + x_pad),
            (y_min - y_pad)..(y_max + y_pad),
        )?;

    chart
        .configure_mesh()
        .x_desc("entropy_dwell")
        .y_desc("repeat_ratio")
        .x_labels(10)
        .y_labels(10)
        .draw()?;

    let palette = [
        RGBColor(31, 119, 180),
        RGBColor(255, 127, 14),
        RGBColor(44, 160, 44),
        RGBColor(214, 39, 40),
        RGBColor(148, 103, 189),
        RGBColor(140, 86, 75),
        RGBColor(227, 119, 194),
        RGBColor(127, 127, 127),
    ];

    chart.draw_series(rows.iter().map(|row| {
        let color = if row.cluster == -1 {
            RGBColor(40, 40, 40)
        } else {
            palette[row.cluster as usize % palette.len()]
        };
        Circle::new(
            (row.feature.entropy_dwell, row.feature.repeat_ratio),
            5,
            color.filled(),
        )
    }))?;

    root.present()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = parse_args()?;
    fs::create_dir_all(&config.output_dir)?;

    let features = load_features(&config.input_path)?;
    if features.is_empty() {
        return Err(format!("no rows found in {}", config.input_path).into());
    }

    let matrix = zscore(&to_matrix(&features));
    let labels = dbscan(&matrix, config.eps, config.min_points);
    let types = point_types(&matrix, &labels, config.eps, config.min_points);

    let rows: Vec<ClusteredSession> = features
        .into_iter()
        .zip(labels.iter())
        .zip(types.iter())
        .map(|((feature, cluster), point_type)| ClusteredSession {
            feature,
            cluster: *cluster,
            point_type,
        })
        .collect();

    let labeled_path = format!("{}/session_clusters.csv", config.output_dir);
    let summary_path = format!("{}/cluster_summary.csv", config.output_dir);
    let scatter_path = format!("{}/cluster_scatter.png", config.output_dir);

    save_labeled_csv(&rows, &labeled_path)?;
    save_summary_csv(&rows, &summary_path)?;
    draw_scatter(&rows, &scatter_path)?;

    let mut counts: HashMap<i32, usize> = HashMap::new();
    for row in &rows {
        *counts.entry(row.cluster).or_insert(0) += 1;
    }
    let mut counts: Vec<(i32, usize)> = counts.into_iter().collect();
    counts.sort_by_key(|(cluster, _)| *cluster);

    println!("=== DBSCAN 완료 ===");
    println!("입력: {}", config.input_path);
    println!("eps: {:.3}, min_points: {}", config.eps, config.min_points);
    println!("세션 수: {}", rows.len());
    for (cluster, count) in counts {
        let label = if cluster == -1 {
            "noise".to_string()
        } else {
            format!("cluster {}", cluster)
        };
        println!("  {}: {}", label, count);
    }
    println!("저장: {}", labeled_path);
    println!("저장: {}", summary_path);
    println!("저장: {}", scatter_path);

    Ok(())
}
