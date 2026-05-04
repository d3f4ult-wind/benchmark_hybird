#!/usr/bin/env python3
"""
analyze_benchmark.py
--------------------
Phân tích và trực quan hóa dữ liệu benchmark XDP + iptables từ file CSV.

Cách dùng:
    python3 analyze_benchmark.py <metrics_csv> <events_csv> [--output-dir <dir>]

Ví dụ:
    python3 analyze_benchmark.py /tmp/benchmark_results/run_20240101_120000_metrics.csv \
                                 /tmp/benchmark_results/run_20240101_120000_events.csv \
                                 --output-dir ./charts

Các biểu đồ được tạo ra:
    1. cpu_timeline.png       — CPU usage theo thời gian với phase annotations
    2. network_throughput.png — RX/TX packet rate theo thời gian
    3. conntrack_timeline.png — Conntrack table size (minh họa khả năng stateful)
    4. irq_rate.png           — Interrupt rate (đo áp lực lên kernel)
    5. phase_comparison.png   — Bảng so sánh trung bình các metric giữa các phase
    6. blacklist_effect.png   — Hiệu quả của auto-blacklist (hits theo thời gian)
    7. summary_dashboard.png  — Dashboard tổng hợp 6 metric trên 1 hình
"""

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")   # Không cần display server
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec
from matplotlib.ticker import MaxNLocator

# ─────────────────────────────────────────
# Màu sắc cho từng phase
# ─────────────────────────────────────────
PHASE_COLORS = {
    0: "#4CAF50",   # Xanh lá — baseline bình thường
    1: "#F44336",   # Đỏ — ICMP flood, XDP đang làm việc nặng
    2: "#FF9800",   # Cam — flood + whitelist traffic
    3: "#9C27B0",   # Tím — tấn công stateful được phát hiện
    4: "#2196F3",   # Xanh dương — sau blacklist, hệ thống phục hồi
    5: "#009688",   # Teal — cool-down
}

PHASE_LABELS = {
    0: "Baseline",
    1: "ICMP Flood\n(XDP DROP)",
    2: "Flood +\nWhitelist Traffic",
    3: "SYN Flood\n(Stateful Detected)",
    4: "Post-Blacklist\n(iptables blocks early)",
    5: "Cool-down",
}


def load_data(metrics_path: str, events_path: str) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Nạp và làm sạch dữ liệu từ CSV."""
    df = pd.read_csv(metrics_path)
    events = pd.read_csv(events_path)

    # Chuyển timestamp sang giây từ thời điểm bắt đầu
    df["time_sec"] = df["timestamp_ms"] / 1000.0
    df["time_sec"] -= df["time_sec"].min()

    events["time_sec"] = events["timestamp_ms"] / 1000.0
    events["time_sec"] -= df["timestamp_ms"].min() / 1000.0

    # Đảm bảo các cột số không có giá trị âm (delta có thể âm nếu counter reset)
    delta_cols = ["rx_packets_delta", "tx_packets_delta", "rx_bytes_delta",
                  "tx_bytes_delta", "irq_delta"]
    for col in delta_cols:
        if col in df.columns:
            df[col] = df[col].clip(lower=0)

    print(f"[*] Đã nạp {len(df)} mẫu metric, {len(events)} events")
    print(f"    Thời gian tổng: {df['time_sec'].max():.1f} giây")
    print(f"    Các phase: {sorted(df['phase'].unique())}")
    return df, events


def add_phase_bands(ax: plt.Axes, df: pd.DataFrame, alpha: float = 0.08):
    """Vẽ dải màu nền cho từng phase lên trục đồ thị."""
    for phase_id, color in PHASE_COLORS.items():
        subset = df[df["phase"] == phase_id]
        if subset.empty:
            continue
        t_start = subset["time_sec"].min()
        t_end   = subset["time_sec"].max()
        ax.axvspan(t_start, t_end, alpha=alpha, color=color, label=f"Phase {phase_id}")


def add_event_lines(ax: plt.Axes, events: pd.DataFrame, y_frac: float = 0.95):
    """Vẽ đường dọc tại thời điểm xảy ra các sự kiện quan trọng."""
    important_keywords = ["bắt đầu", "detected", "blacklist", "kết thúc"]
    for _, row in events.iterrows():
        desc = str(row.get("description", "")).lower()
        if any(kw in desc for kw in important_keywords):
            ax.axvline(x=row["time_sec"], color="gray", linestyle="--",
                       linewidth=0.8, alpha=0.6)


def make_phase_legend(ax: plt.Axes):
    """Tạo legend với màu của từng phase."""
    patches = [
        mpatches.Patch(color=color, alpha=0.5,
                       label=f"P{pid}: {PHASE_LABELS[pid].replace(chr(10), ' ')}")
        for pid, color in PHASE_COLORS.items()
    ]
    ax.legend(handles=patches, loc="upper right", fontsize=7,
              framealpha=0.8, ncol=2)


# ─────────────────────────────────────────
# Biểu đồ 1: CPU Usage Timeline
# ─────────────────────────────────────────
def plot_cpu_timeline(df: pd.DataFrame, events: pd.DataFrame, out_path: Path):
    fig, ax = plt.subplots(figsize=(12, 5))
    add_phase_bands(ax, df)
    add_event_lines(ax, events)

    # Smooth bằng rolling average để giảm nhiễu
    df_plot = df.copy()
    df_plot["cpu_smooth"] = df_plot["cpu_percent"].rolling(window=3, center=True).mean()

    ax.fill_between(df_plot["time_sec"], df_plot["cpu_percent"],
                    alpha=0.2, color="#F44336")
    ax.plot(df_plot["time_sec"], df_plot["cpu_smooth"],
            color="#D32F2F", linewidth=1.5, label="CPU % (smoothed 3s)")
    ax.plot(df_plot["time_sec"], df_plot["cpu_percent"],
            color="#F44336", linewidth=0.5, alpha=0.5, label="CPU % (raw)")

    ax.set_xlabel("Thời gian (giây)", fontsize=11)
    ax.set_ylabel("CPU Usage (%)", fontsize=11)
    ax.set_title("CPU Usage qua các Phase Benchmark\n"
                 "XDP (stateless, 1000 rules) + iptables (stateful)", fontsize=12)
    ax.set_ylim(0, 105)
    ax.yaxis.set_major_locator(MaxNLocator(integer=True))
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.legend(loc="upper left", fontsize=8)
    make_phase_legend(ax)

    # Annotate mean per phase
    for phase_id, color in PHASE_COLORS.items():
        subset = df[df["phase"] == phase_id]
        if subset.empty:
            continue
        mean_val = subset["cpu_percent"].mean()
        t_mid = (subset["time_sec"].min() + subset["time_sec"].max()) / 2
        ax.annotate(f"{mean_val:.1f}%",
                    xy=(t_mid, mean_val),
                    xytext=(0, 8), textcoords="offset points",
                    ha="center", fontsize=8, color=color, fontweight="bold")

    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"  [+] {out_path}")


# ─────────────────────────────────────────
# Biểu đồ 2: Network Throughput
# ─────────────────────────────────────────
def plot_network_throughput(df: pd.DataFrame, events: pd.DataFrame, out_path: Path):
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 7), sharex=True)

    # Packets per second
    add_phase_bands(ax1, df)
    ax1.plot(df["time_sec"], df["rx_packets_delta"],
             color="#1565C0", linewidth=1.2, label="RX packets/s")
    ax1.plot(df["time_sec"], df["tx_packets_delta"],
             color="#E65100", linewidth=1.2, label="TX packets/s", alpha=0.8)
    ax1.set_ylabel("Packets / giây", fontsize=10)
    ax1.set_title("Network Throughput — Packets và Bytes / giây", fontsize=12)
    ax1.legend(fontsize=9)
    ax1.grid(axis="y", linestyle="--", alpha=0.4)
    add_event_lines(ax1, events)

    # Bytes per second → MB/s
    add_phase_bands(ax2, df)
    ax2.plot(df["time_sec"], df["rx_bytes_delta"] / 1e6,
             color="#1565C0", linewidth=1.2, label="RX MB/s")
    ax2.plot(df["time_sec"], df["tx_bytes_delta"] / 1e6,
             color="#E65100", linewidth=1.2, label="TX MB/s", alpha=0.8)
    ax2.set_ylabel("MB / giây", fontsize=10)
    ax2.set_xlabel("Thời gian (giây)", fontsize=10)
    ax2.legend(fontsize=9)
    ax2.grid(axis="y", linestyle="--", alpha=0.4)
    add_event_lines(ax2, events)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"  [+] {out_path}")


# ─────────────────────────────────────────
# Biểu đồ 3: Conntrack Table Size
# (Điểm quan trọng: XDP stateless không dùng conntrack, iptables stateful thì có)
# ─────────────────────────────────────────
def plot_conntrack(df: pd.DataFrame, events: pd.DataFrame, out_path: Path):
    fig, ax = plt.subplots(figsize=(12, 5))
    add_phase_bands(ax, df)
    add_event_lines(ax, events)

    ax.plot(df["time_sec"], df["conntrack_count"],
            color="#7B1FA2", linewidth=1.5, label="Conntrack entries")
    ax.fill_between(df["time_sec"], df["conntrack_count"],
                    alpha=0.15, color="#7B1FA2")

    ax.set_xlabel("Thời gian (giây)", fontsize=11)
    ax.set_ylabel("Số kết nối trong conntrack table", fontsize=11)
    ax.set_title("Conntrack Table Size\n"
                 "Tăng đột biến ở Phase 3 = iptables đang xử lý SYN flood (stateful)", fontsize=12)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.legend(fontsize=9)
    make_phase_legend(ax)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"  [+] {out_path}")


# ─────────────────────────────────────────
# Biểu đồ 4: IRQ Rate
# ─────────────────────────────────────────
def plot_irq_rate(df: pd.DataFrame, events: pd.DataFrame, out_path: Path):
    fig, ax = plt.subplots(figsize=(12, 5))
    add_phase_bands(ax, df)
    add_event_lines(ax, events)

    ax.plot(df["time_sec"], df["irq_delta"],
            color="#00695C", linewidth=1.3, label="IRQ/s (tổng)")
    ax.fill_between(df["time_sec"], df["irq_delta"],
                    alpha=0.15, color="#00695C")

    ax.set_xlabel("Thời gian (giây)", fontsize=11)
    ax.set_ylabel("Số ngắt / giây", fontsize=11)
    ax.set_title("Interrupt Rate\n"
                 "XDP hoạt động trước interrupt nên IRQ thấp hơn iptables-only", fontsize=12)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.legend(fontsize=9)
    make_phase_legend(ax)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"  [+] {out_path}")


# ─────────────────────────────────────────
# Biểu đồ 5: Phase Comparison (Bar chart)
# ─────────────────────────────────────────
def plot_phase_comparison(df: pd.DataFrame, out_path: Path):
    metrics = {
        "cpu_percent":      "CPU (%)",
        "rx_packets_delta": "RX Packets/s",
        "conntrack_count":  "Conntrack Entries",
        "irq_delta":        "IRQ/s",
    }

    # Tính trung bình và std cho mỗi phase
    summary = df.groupby("phase")[list(metrics.keys())].agg(["mean", "std"])

    phases = sorted(df["phase"].unique())
    n_metrics = len(metrics)
    n_phases  = len(phases)

    fig, axes = plt.subplots(1, n_metrics, figsize=(4 * n_metrics, 6))
    fig.suptitle("So sánh Metric Trung Bình giữa các Phase\n"
                 "(Error bar = ±1 std)", fontsize=13, y=1.01)

    for ax, (col, label) in zip(axes, metrics.items()):
        means = [summary.loc[p, (col, "mean")] if p in summary.index else 0
                 for p in phases]
        stds  = [summary.loc[p, (col, "std")]  if p in summary.index else 0
                 for p in phases]
        colors = [PHASE_COLORS.get(p, "#999") for p in phases]
        bars = ax.bar(range(n_phases), means, yerr=stds,
                      color=colors, alpha=0.8, capsize=4)
        ax.set_xticks(range(n_phases))
        ax.set_xticklabels([f"P{p}" for p in phases], fontsize=9)
        ax.set_ylabel(label, fontsize=10)
        ax.set_title(label, fontsize=10, fontweight="bold")
        ax.grid(axis="y", linestyle="--", alpha=0.4)

        # Ghi giá trị lên đỉnh bar
        for bar, mean in zip(bars, means):
            height = bar.get_height()
            ax.annotate(f"{mean:.0f}",
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3), textcoords="offset points",
                        ha="center", va="bottom", fontsize=8)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  [+] {out_path}")


# ─────────────────────────────────────────
# Biểu đồ 6: Blacklist Effect
# ─────────────────────────────────────────
def plot_blacklist_effect(df: pd.DataFrame, events: pd.DataFrame, out_path: Path):
    fig, ax = plt.subplots(figsize=(12, 5))
    add_phase_bands(ax, df)
    add_event_lines(ax, events)

    ax.plot(df["time_sec"], df["iptables_blacklist_hits"],
            color="#BF360C", linewidth=1.5,
            label="iptables Blacklist Rule Hits (cumulative)")

    # Đánh dấu phase 4 đặc biệt
    p4 = df[df["phase"] == 4]
    if not p4.empty:
        ax.fill_between(p4["time_sec"], p4["iptables_blacklist_hits"],
                        alpha=0.3, color="#2196F3",
                        label="Phase 4: IP đã bị blacklist (chặn sớm)")

    ax.set_xlabel("Thời gian (giây)", fontsize=11)
    ax.set_ylabel("Số lần rule blacklist match (lũy tiến)", fontsize=11)
    ax.set_title("Hiệu quả của Auto-Blacklist\n"
                 "Sau Phase 3: iptables chặn IP sớm ngay ở rule đầu tiên", fontsize=12)
    ax.grid(axis="y", linestyle="--", alpha=0.4)
    ax.legend(fontsize=9)
    make_phase_legend(ax)

    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"  [+] {out_path}")


# ─────────────────────────────────────────
# Biểu đồ 7: Summary Dashboard
# ─────────────────────────────────────────
def plot_dashboard(df: pd.DataFrame, events: pd.DataFrame, out_path: Path):
    fig = plt.figure(figsize=(18, 12))
    gs  = GridSpec(3, 2, figure=fig, hspace=0.45, wspace=0.35)

    subplots_config = [
        (gs[0, 0], "cpu_percent",         "CPU (%)",           "#D32F2F"),
        (gs[0, 1], "rx_packets_delta",    "RX Packets/s",      "#1565C0"),
        (gs[1, 0], "conntrack_count",     "Conntrack Entries", "#7B1FA2"),
        (gs[1, 1], "irq_delta",           "IRQ/s",             "#00695C"),
        (gs[2, 0], "iptables_blacklist_hits", "Blacklist Hits", "#BF360C"),
        (gs[2, 1], "mem_mb",              "Memory (MB)",       "#37474F"),
    ]

    for spec, col, label, color in subplots_config:
        ax = fig.add_subplot(spec)
        add_phase_bands(ax, df, alpha=0.06)
        add_event_lines(ax, events)
        ax.plot(df["time_sec"], df[col], color=color, linewidth=1.2)
        ax.set_ylabel(label, fontsize=9)
        ax.set_xlabel("Thời gian (s)", fontsize=8)
        ax.set_title(label, fontsize=10, fontweight="bold", color=color)
        ax.grid(axis="y", linestyle="--", alpha=0.3)
        ax.tick_params(labelsize=8)

    fig.suptitle(
        "Dashboard Benchmark: XDP Stateless (1000 rules) + iptables Stateful\n"
        "Kịch bản: ICMP Flood → SYN Flood từ whitelist IP → Auto-Blacklist",
        fontsize=13, fontweight="bold", y=1.01
    )

    # Legend tổng ở dưới
    legend_patches = [
        mpatches.Patch(color=c, alpha=0.5,
                       label=f"P{pid}: {PHASE_LABELS[pid].replace(chr(10),' ')}")
        for pid, c in PHASE_COLORS.items()
    ]
    fig.legend(handles=legend_patches, loc="lower center",
               ncol=3, fontsize=8, bbox_to_anchor=(0.5, -0.04),
               framealpha=0.9)

    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"  [+] {out_path}")


# ─────────────────────────────────────────
# Tạo báo cáo text summary
# ─────────────────────────────────────────
def print_summary(df: pd.DataFrame):
    print("\n" + "="*60)
    print("  SUMMARY BENCHMARK")
    print("="*60)
    for phase_id in sorted(df["phase"].unique()):
        subset = df[df["phase"] == phase_id]
        label  = PHASE_LABELS.get(phase_id, f"Phase {phase_id}").replace("\n", " ")
        print(f"\n  Phase {phase_id}: {label}")
        print(f"    Duration     : {subset['time_sec'].max() - subset['time_sec'].min():.1f}s"
              f" ({len(subset)} samples)")
        print(f"    CPU mean/max : {subset['cpu_percent'].mean():.1f}% / {subset['cpu_percent'].max():.1f}%")
        print(f"    RX pkt/s avg : {subset['rx_packets_delta'].mean():.0f}")
        print(f"    Conntrack avg: {subset['conntrack_count'].mean():.0f}")
        print(f"    IRQ/s avg    : {subset['irq_delta'].mean():.0f}")
    print("\n" + "="*60)


# ─────────────────────────────────────────
# Main
# ─────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="Phân tích và vẽ biểu đồ benchmark XDP + iptables"
    )
    parser.add_argument("metrics_csv", help="File CSV metrics từ run_benchmark.sh")
    parser.add_argument("events_csv",  help="File CSV events từ run_benchmark.sh")
    parser.add_argument("--output-dir", default="./benchmark_charts",
                        help="Thư mục lưu biểu đồ (default: ./benchmark_charts)")
    args = parser.parse_args()

    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Kiểm tra thư viện
    try:
        import matplotlib
        import pandas
        import numpy
    except ImportError as e:
        print(f"[!] Thiếu thư viện: {e}")
        print("    Cài đặt: pip install matplotlib pandas numpy")
        sys.exit(1)

    print(f"[*] Nạp dữ liệu...")
    df, events = load_data(args.metrics_csv, args.events_csv)

    print(f"[*] Tạo biểu đồ vào {out_dir}/...")
    plot_cpu_timeline(df, events,       out_dir / "cpu_timeline.png")
    plot_network_throughput(df, events, out_dir / "network_throughput.png")
    plot_conntrack(df, events,          out_dir / "conntrack_timeline.png")
    plot_irq_rate(df, events,           out_dir / "irq_rate.png")
    plot_phase_comparison(df,           out_dir / "phase_comparison.png")
    plot_blacklist_effect(df, events,   out_dir / "blacklist_effect.png")
    plot_dashboard(df, events,          out_dir / "summary_dashboard.png")

    print_summary(df)

    print(f"\n[+] Hoàn tất! {len(list(out_dir.glob('*.png')))} biểu đồ đã lưu vào {out_dir}/")


if __name__ == "__main__":
    main()
