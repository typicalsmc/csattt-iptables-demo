#!/usr/bin/env python3
"""
iptables + ipset + fail2ban Demo Client
========================================
Demonstrates TCP flag filtering, IP blocking, NAT, ipset bulk blocking,
and fail2ban auto-banning using Scapy, requests, and paramiko.

Usage:
  python3 demo.py            # run all tests automatically
  python3 demo.py --list     # list available test names
  python3 demo.py <test_id>  # run a single test by number or name
"""

import os
import random
import socket
import subprocess
import sys
import time

import requests
from scapy.all import IP, TCP, conf, sr1

# ─────────────────────────────────────────────────────────────────────────────
#  Config (override via environment variables)
# ─────────────────────────────────────────────────────────────────────────────
SERVER_IP   = os.environ.get("SERVER_IP",   "172.20.0.10")
CLIENT_IP   = os.environ.get("CLIENT_IP",   "172.20.0.20")
SERVER_PORT = int(os.environ.get("SERVER_PORT", "80"))
SSH_PORT    = int(os.environ.get("SSH_PORT",    "22"))
TIMEOUT     = float(os.environ.get("SCAPY_TIMEOUT", "2"))

# Suppress Scapy's noisy output
conf.verb = 0

# ─────────────────────────────────────────────────────────────────────────────
#  ANSI colours
# ─────────────────────────────────────────────────────────────────────────────
R  = "\033[91m"   # red
G  = "\033[92m"   # green
Y  = "\033[93m"   # yellow
B  = "\033[94m"   # blue
M  = "\033[95m"   # magenta
C  = "\033[96m"   # cyan
W  = "\033[97m"   # white
BD = "\033[1m"    # bold
DM = "\033[2m"    # dim
RS = "\033[0m"    # reset

# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────
def banner(text: str) -> None:
    w = 66
    print(f"\n{BD}{B}{'═'*w}")
    print(f"  {text}")
    print(f"{'═'*w}{RS}")


def section(num: int, title: str, expected: str) -> None:
    colour = G if "ĐẠT" in expected else R
    print(f"\n{BD}{'─'*66}")
    print(f"  BÀI KIỂM TRA {num:>2}: {title}")
    print(f"  Kết quả mong đợi: {colour}{BD}{expected}{RS}")
    print(f"{'─'*66}{RS}")


def info(msg: str) -> None:
    print(f"  {DM}{Y}ℹ  {msg}{RS}")


def rule(r: str) -> None:
    print(f"  {DM}Quy tắc: {C}{r}{RS}")


def result_pass(msg: str) -> None:
    print(f"\n  {G}{BD}✓ ĐẠT{RS}  {msg}")


def result_block(msg: str) -> None:
    print(f"\n  {R}{BD}✗ BỊ CHẶN{RS}  {msg}")


def result_unexpected(label: str, msg: str) -> None:
    print(f"\n  {M}{BD}? {label}{RS}  {msg}")


def sport() -> int:
    """Random ephemeral source port."""
    return random.randint(10_000, 60_000)


def send_raw(flags, label: str, seq: int | None = None) -> object | None:
    """
    Send a single TCP packet with the given flags.
    Returns the first response packet, or None on timeout (= dropped).
    """
    seq = seq or random.randint(1_000, 999_999)
    pkt = IP(dst=SERVER_IP) / TCP(
        sport=sport(),
        dport=SERVER_PORT,
        flags=flags,
        seq=seq,
    )
    return sr1(pkt, timeout=TIMEOUT, verbose=0)


def check(resp, test_name: str, expect_blocked: bool = True) -> bool:
    """
    Evaluate the response and print the result.
    Returns True if the outcome matched the expectation.
    """
    dropped = resp is None
    if expect_blocked:
        if dropped:
            result_block("Không nhận được phản hồi — gói tin đã bị tường lửa loại bỏ.")
            return True
        else:
            flags = resp[TCP].flags if TCP in resp else "?"
            result_unexpected("PHẢN HỒI KHÔNG MONG ĐỢI", f"Nhận được phản hồi với cờ TCP: {flags}")
            return False
    else:
        if not dropped:
            flags = resp[TCP].flags if TCP in resp else "?"
            result_pass(f"Đã nhận phản hồi (cờ TCP: {flags})")
            return True
        else:
            result_unexpected("CHẶN KHÔNG MONG ĐỢI", "Mong đợi phản hồi nhưng không nhận được gì.")
            return False


def pause(s: float = 0.6) -> None:
    time.sleep(s)


# ─────────────────────────────────────────────────────────────────────────────
#  Wait for server
# ─────────────────────────────────────────────────────────────────────────────
def wait_for_server(max_wait: int = 30) -> bool:
    print(f"\n{Y}Đang chờ server {SERVER_IP}:{SERVER_PORT} sẵn sàng...{RS}")
    for i in range(max_wait):
        try:
            s = socket.create_connection((SERVER_IP, SERVER_PORT), timeout=2)
            s.close()
            print(f"{G}{BD}Server đã sẵn sàng!{RS}\n")
            return True
        except OSError:
            sys.stdout.write(".")
            sys.stdout.flush()
            time.sleep(1)
    print(f"\n{R}Không thể kết nối đến server sau {max_wait}s — hủy bỏ.{RS}")
    return False


# ─────────────────────────────────────────────────────────────────────────────
#  Reference tables
# ─────────────────────────────────────────────────────────────────────────────
def print_reference() -> None:
    banner("THAM KHẢO CỜ TCP & CÁC KIỂU TẤN CÔNG")

    print(f"\n{BD}  Các Bit Cờ TCP{RS}")
    flags = [
        ("SYN (S, 0x02)", "Đồng bộ — khởi tạo kết nối TCP mới"),
        ("ACK (A, 0x10)", "Xác nhận — xác nhận đã nhận dữ liệu"),
        ("FIN (F, 0x01)", "Kết thúc — đóng kết nối một cách nhẹ nhàng"),
        ("RST (R, 0x04)", "Đặt lại — hủy kết nối đột ngột"),
        ("PSH (P, 0x08)", "Đẩy — gửi dữ liệu đệm đến ứng dụng ngay lập tức"),
        ("URG (U, 0x20)", "Khẩn cấp — đánh dấu dữ liệu nội tuyến khẩn cấp"),
        ("ECE (E, 0x40)", "ECN-Echo — thông báo tắc nghẽn ECN"),
        ("CWR (C, 0x80)", "Giảm cửa sổ tắc nghẽn — phản hồi ECN"),
    ]
    for flag, desc in flags:
        print(f"    {C}{flag:<20}{RS}  {desc}")

    print(f"\n{BD}  Các Kiểu Tấn Công Bị Chặn{RS}")
    attacks = [
        ("NULL scan",          "0 cờ",              "Nhận dạng hệ điều hành / quét lén lút"),
        ("XMAS scan",          "tất cả 6 cờ",        "Nmap -sX — vượt qua tường lửa không trạng thái"),
        ("FIN scan",           "chỉ FIN",            "Nmap -sF — vượt qua tường lửa cũ"),
        ("FIN+SYN",            "mâu thuẫn",          "Không hợp lệ — RFC nói là không thể"),
        ("SYN+RST",            "mâu thuẫn",          "Không hợp lệ — RFC nói là không thể"),
        ("FIN+RST",            "mâu thuẫn",          "Không hợp lệ — RFC nói là không thể"),
        ("URG không có ACK",   "chỉ URG",            "URG không có ACK luôn không hợp lệ"),
        ("PSH không có ACK",   "chỉ PSH",            "PSH không có ACK luôn không hợp lệ"),
        ("Gói phân mảnh",      "cờ -f",              "Vượt qua bộ lọc không nhận biết phân mảnh"),
    ]
    for name, flags_, desc in attacks:
        print(f"    {R}{name:<22}{RS}  {Y}{flags_:<16}{RS}  {desc}")

    print(f"\n{BD}  NAT (Dịch Địa Chỉ Mạng){RS}")
    nat_types = [
        ("SNAT / MASQUERADE", "Ghi lại IP nguồn của gói tin gửi đi (NAT router gia đình)"),
        ("DNAT",              "Ghi lại IP đích — chuyển tiếp cổng / reverse proxy"),
        ("POSTROUTING",       "Kích hoạt sau quyết định định tuyến, trước khi gói rời NIC"),
        ("PREROUTING",        "Kích hoạt trước quyết định định tuyến, khi gói đến"),
    ]
    for term, desc in nat_types:
        print(f"    {C}{term:<22}{RS}  {desc}")

    print(f"\n{BD}  ipset + fail2ban{RS}")
    ipset_info = [
        ("ssh-blocklist",    "hash:ip  ", "fail2ban thêm IP quét SSH; tự động hết hạn theo bantime"),
        ("proxy-blocklist",  "hash:net ", "fetch-proxies.sh tải danh sách proxy/exit-node công khai"),
        ("manual-blocklist", "hash:ip  ", "Chặn tay ad-hoc — thêm/xóa bằng `ipset add/del`"),
    ]
    for name, type_, desc in ipset_info:
        print(f"    {C}{name:<20}{RS}  {DM}{type_}{RS}  {desc}")


# ─────────────────────────────────────────────────────────────────────────────
#  Individual tests (1–15 — original iptables tests)
# ─────────────────────────────────────────────────────────────────────────────

def test_normal_http() -> bool:
    section(1, "Yêu cầu HTTP GET Thông Thường", "ĐẠT — lưu lượng hợp lệ được cho phép")
    info("Sử dụng TCP stack của OS: SYN → SYN-ACK → ACK → GET → 200 OK")
    info("Không có quy tắc mangle nào khớp với bắt tay SYN thông thường.")
    rule(":POSTROUTING ACCEPT [0:0]  (NAT passthrough — tất cả lưu lượng hợp lệ được NAT và chuyển tiếp)")
    try:
        r = requests.get(f"http://{SERVER_IP}:{SERVER_PORT}/", timeout=5)
        result_pass(f"HTTP {r.status_code} — Nội dung: {r.json().get('message', '')}")
        return True
    except Exception as exc:
        result_unexpected("LỖI HTTP", str(exc))
        return False


def test_null_scan() -> bool:
    section(2, "Quét NULL — Không Có Cờ TCP (0x00)", "BỊ CHẶN")
    info("Được dùng bởi Nmap (-sN) để quét cổng lén lút.")
    info("Không có giao tiếp TCP hợp lệ nào có cờ bằng không.")
    rule("-A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP")
    resp = send_raw(0, "NULL")
    return check(resp, "null_scan")


def test_xmas_scan() -> bool:
    section(3, "Quét XMAS — Tất Cả 6 Cờ (FIN+SYN+RST+PSH+ACK+URG)", "BỊ CHẶN")
    info("Gói 'cây Giáng sinh' — mọi cờ đều bật. Dùng bởi Nmap -sX.")
    info("RFC 793 nói hành vi không xác định khi tất cả cờ được đặt.")
    rule("-A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,PSH,ACK,URG -j DROP")
    resp = send_raw("FSRPAU", "XMAS")
    return check(resp, "xmas_scan")


def test_fin_syn() -> bool:
    section(4, "FIN + SYN Đồng Thời", "BỊ CHẶN")
    info("SYN mở kết nối; FIN đóng nó — mâu thuẫn theo định nghĩa.")
    rule("-A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP")
    resp = send_raw("FS", "FIN+SYN")
    return check(resp, "fin_syn")


def test_syn_rst() -> bool:
    section(5, "SYN + RST Đồng Thời", "BỊ CHẶN")
    info("SYN khởi tạo; RST hủy bỏ — không thể cùng hợp lệ một lúc.")
    rule("-A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP")
    resp = send_raw("SR", "SYN+RST")
    return check(resp, "syn_rst")


def test_fin_rst() -> bool:
    section(6, "FIN + RST Đồng Thời", "BỊ CHẶN")
    info("FIN = đóng nhẹ nhàng; RST = hủy đột ngột — loại trừ lẫn nhau khi kết thúc.")
    rule("-A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP")
    resp = send_raw("FR", "FIN+RST")
    return check(resp, "fin_rst")


def test_fin_no_ack() -> bool:
    section(7, "FIN Không Có ACK", "BỊ CHẶN")
    info("RFC 793 §3.5: FIN luôn đi kèm ACK trong quá trình kết thúc TCP hợp lệ.")
    rule("-A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP")
    resp = send_raw("F", "FIN")
    return check(resp, "fin_no_ack")


def test_urg_no_ack() -> bool:
    section(8, "URG Không Có ACK", "BỊ CHẶN")
    info("Dữ liệu URG là một phần của luồng thông thường — phải cùng tồn tại với ACK.")
    rule("-A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP")
    resp = send_raw("U", "URG")
    return check(resp, "urg_no_ack")


def test_psh_no_ack() -> bool:
    section(9, "PSH Không Có ACK", "BỊ CHẶN")
    info("PSH yêu cầu stack xả dữ liệu; luôn được gửi với ACK trong các đoạn dữ liệu.")
    rule("-A PREROUTING -p tcp --tcp-flags PSH,ACK PSH -j DROP")
    resp = send_raw("P", "PSH")
    return check(resp, "psh_no_ack")


def test_fin_psh_urg() -> bool:
    section(10, "FIN + PSH + URG (biến thể XMAS của Nmap)", "BỊ CHẶN")
    info("Biến thể 'FIN scan' RFC 793 cổ điển — dùng để phát hiện hệ điều hành.")
    rule("-A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,PSH,URG -j DROP")
    resp = send_raw("FPU", "FIN+PSH+URG")
    return check(resp, "fin_psh_urg")


def test_fin_syn_psh_urg() -> bool:
    section(11, "FIN + SYN + PSH + URG", "BỊ CHẶN")
    info("Một tổ hợp không thể khác — 4 cờ không thể cùng tồn tại.")
    rule("-A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,PSH,URG -j DROP")
    resp = send_raw("FSPU", "FIN+SYN+PSH+URG")
    return check(resp, "fin_syn_psh_urg")


def test_fin_syn_rst_ack_urg() -> bool:
    section(12, "FIN + SYN + RST + ACK + URG", "BỊ CHẶN")
    info("Bất thường 5 cờ — không có TCP stack hợp lệ nào tạo ra điều này.")
    rule("-A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG FIN,SYN,RST,ACK,URG -j DROP")
    resp = send_raw("FSRAU", "FIN+SYN+RST+ACK+URG")
    return check(resp, "fin_syn_rst_ack_urg")


def test_invalid_conntrack() -> bool:
    section(13, "Trạng thái conntrack KHÔNG HỢP LỆ (ACK trên kết nối không tồn tại)", "BỊ CHẶN")
    info("Gửi ACK không có SYN trước — conntrack đánh dấu là KHÔNG HỢP LỆ.")
    info("Quy tắc conntrack INVALID kích hoạt trước các quy tắc mangle cờ.")
    rule("-A PREROUTING -m conntrack --ctstate INVALID -j DROP")
    resp = send_raw("A", "ACK/no-conn")
    return check(resp, "invalid_conntrack")


def test_fragmented() -> bool:
    section(14, "Gói IP Bị Phân Mảnh (cờ MF được đặt)", "BỊ CHẶN")
    info("Phân mảnh IP có thể bị lạm dụng để vượt qua bộ lọc gói tin.")
    info("Khớp -f bắt các mảnh không đầu tiên; MF=1 trên mảnh đầu kích hoạt quy tắc này.")
    rule("-A PREROUTING -f -j DROP")
    # Build a fragment: set More Fragments (MF) and non-zero offset
    from scapy.all import IP, TCP, fragment
    pkt = IP(dst=SERVER_IP) / TCP(sport=sport(), dport=SERVER_PORT, flags="S") / (b"X" * 300)
    frags = fragment(pkt, fragsize=100)
    # Send only fragment 1 (non-first → has frag offset > 0)
    if len(frags) < 2:
        info("Không thể tạo phân mảnh (gói quá nhỏ) — bỏ qua.")
        return True
    resp = sr1(frags[1], timeout=TIMEOUT, verbose=0)
    return check(resp, "fragmented")


# ─────────────────────────────────────────────────────────────────────────────
#  IP Blocking Demo
# ─────────────────────────────────────────────────────────────────────────────
def test_ip_blocking() -> bool:
    banner("DEMO CHẶN IP  (chuỗi filter INPUT trên OUTPUT của client)")
    info(f"Chúng ta sẽ thêm quy tắc OUTPUT DROP cục bộ để mô phỏng bị chặn.")
    info(f"Mục tiêu chặn: {SERVER_IP}:{SERVER_PORT}")
    print()

    # Step 1: baseline — connection must work
    try:
        r = requests.get(f"http://{SERVER_IP}:{SERVER_PORT}/", timeout=5)
        result_pass(f"[Trước khi chặn] HTTP {r.status_code} — kết nối OK")
    except Exception as exc:
        result_unexpected("LỖI CƠ SỞ", str(exc))
        return False

    # Step 2: apply iptables OUTPUT DROP on the client
    block_cmd = [
        "iptables", "-A", "OUTPUT",
        "-d", SERVER_IP,
        "-p", "tcp", "--dport", str(SERVER_PORT),
        "-j", "DROP",
    ]
    unblock_cmd = [
        "iptables", "-D", "OUTPUT",
        "-d", SERVER_IP,
        "-p", "tcp", "--dport", str(SERVER_PORT),
        "-j", "DROP",
    ]

    info(f"Đang áp dụng: {' '.join(block_cmd)}")
    subprocess.run(block_cmd, capture_output=True)
    time.sleep(0.3)

    try:
        r = requests.get(f"http://{SERVER_IP}:{SERVER_PORT}/", timeout=3)
        result_unexpected("KHÔNG BỊ CHẶN", f"HTTP {r.status_code} — quy tắc không kích hoạt?")
    except Exception:
        result_block("[Sau khi chặn] Kết nối bị từ chối/hết giờ — IP đã bị chặn hiệu quả!")

    # Step 3: remove the rule
    info(f"Xóa quy tắc: {' '.join(unblock_cmd)}")
    subprocess.run(unblock_cmd, capture_output=True)
    time.sleep(0.3)

    try:
        r = requests.get(f"http://{SERVER_IP}:{SERVER_PORT}/", timeout=5)
        result_pass(f"[Sau khi bỏ chặn] HTTP {r.status_code} — lưu lượng đã được khôi phục!")
        return True
    except Exception as exc:
        result_unexpected("VẪN BỊ CHẶN", str(exc))
        return False


# ─────────────────────────────────────────────────────────────────────────────
#  NAT explanation (observational)
# ─────────────────────────────────────────────────────────────────────────────
def explain_nat() -> None:
    banner("DEMO NAT  (POSTROUTING / MASQUERADE)")

    info("Server có các quy tắc NAT đang hoạt động:")
    print(f"\n  {C}iptables -t nat -P POSTROUTING ACCEPT{RS}")
    print(f"  {DM}  → Chính sách mặc định của chuỗi POSTROUTING là ACCEPT.{RS}")
    print(f"  {DM}    Gói không khớp quy tắc nào sẽ đi qua không thay đổi.{RS}")
    print()
    print(f"  {C}iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE{RS}")
    print(f"  {DM}  → Bất kỳ gói nào rời qua eth0 có IP nguồn{RS}")
    print(f"  {DM}    được ghi lại thành IP của giao diện (SNAT / NAT masquerade).{RS}")
    print(f"  {DM}    Đây là cách router gia đình cho mọi thiết bị truy cập internet{RS}")
    print(f"  {DM}    qua một địa chỉ IP công cộng duy nhất.{RS}")
    print()

    info("Đang xác minh: đọc bảng NAT từ bên trong container client...")
    try:
        result = subprocess.run(
            ["iptables", "-t", "nat", "-L", "POSTROUTING", "-n", "-v"],
            capture_output=True, text=True,
        )
        if result.returncode == 0:
            print(f"\n{DM}{result.stdout}{RS}")
        else:
            info("(iptables không khả dụng trên đường dẫn client, kiểm tra log server)")
    except FileNotFoundError:
        info("(không tìm thấy file thực thi iptables)")

    print(f"\n  {BD}Ví dụ DNAT (chuyển tiếp cổng):{RS}")
    print(f"  {C}iptables -t nat -A PREROUTING -p tcp --dport 8888 -j DNAT --to-destination 172.20.0.10:80{RS}")
    print(f"  {DM}  → Kết nối đến cổng 8888 được chuyển tiếp đến cổng 80 của server.{RS}")
    print(f"  {DM}    Hữu ích cho reverse proxy và tường lửa chuyển tiếp cổng.{RS}")


# ─────────────────────────────────────────────────────────────────────────────
#  Test 16: ipset — client-side bulk IP block using ipset + iptables
# ─────────────────────────────────────────────────────────────────────────────
def test_ipset_client_block() -> bool:
    banner("DEMO IPSET  (chặn bulk IP phía client bằng ipset)")
    info("ipset cho phép quản lý danh sách IP lớn hiệu quả hơn nhiều quy tắc iptables riêng lẻ.")
    info(f"Tạo ipset 'demo-block', thêm {SERVER_IP}, thêm OUTPUT rule tham chiếu set.")
    print()

    SETNAME = "demo-block"

    def _ipset(*args) -> subprocess.CompletedProcess:
        return subprocess.run(["ipset"] + list(args), capture_output=True)

    def _ipt(*args) -> subprocess.CompletedProcess:
        return subprocess.run(["iptables"] + list(args), capture_output=True)

    # Cleanup helper
    def cleanup():
        _ipt("-D", "OUTPUT", "-m", "set", "--match-set", SETNAME, "dst", "-j", "DROP")
        _ipset("destroy", SETNAME)

    cleanup()  # ensure fresh state

    # ── Step 1: baseline ──────────────────────────────────────
    try:
        r = requests.get(f"http://{SERVER_IP}:{SERVER_PORT}/", timeout=5)
        result_pass(f"[Trước khi tạo ipset] HTTP {r.status_code} — kết nối OK")
    except Exception as exc:
        result_unexpected("LỖI CƠ SỞ", str(exc))
        return False

    # ── Step 2: create ipset, add server IP, add OUTPUT rule ──
    info(f"ipset create {SETNAME} hash:ip")
    _ipset("create", SETNAME, "hash:ip", "-exist")

    info(f"ipset add {SETNAME} {SERVER_IP}")
    _ipset("add", SETNAME, SERVER_IP, "-exist")

    info(f"iptables -A OUTPUT -m set --match-set {SETNAME} dst -j DROP")
    _ipt("-A", "OUTPUT", "-m", "set", "--match-set", SETNAME, "dst", "-j", "DROP")
    time.sleep(0.3)

    try:
        r = requests.get(f"http://{SERVER_IP}:{SERVER_PORT}/", timeout=3)
        result_unexpected("KHÔNG BỊ CHẶN", f"HTTP {r.status_code} — ipset rule không kích hoạt?")
        cleanup()
        return False
    except Exception:
        result_block(f"[Sau khi thêm vào ipset] Kết nối tới {SERVER_IP} bị chặn bởi ipset OUTPUT rule!")

    # ── Step 3: destroy ipset and rule ────────────────────────
    info(f"Xóa ipset và iptables rule")
    cleanup()
    time.sleep(0.3)

    try:
        r = requests.get(f"http://{SERVER_IP}:{SERVER_PORT}/", timeout=5)
        result_pass(f"[Sau khi xóa ipset] HTTP {r.status_code} — lưu lượng được khôi phục!")
        return True
    except Exception as exc:
        result_unexpected("VẪN BỊ CHẶN", str(exc))
        return False


# ─────────────────────────────────────────────────────────────────────────────
#  Test 17: fail2ban SSH ban — simulate brute force, verify ipset entry
# ─────────────────────────────────────────────────────────────────────────────
def test_fail2ban_ssh_ban() -> bool:
    banner("DEMO FAIL2BAN  (SSH brute-force → ipset ssh-blocklist → xác minh)")
    info("Client thực hiện nhiều lần đăng nhập SSH thất bại liên tiếp.")
    info("fail2ban phát hiện và thêm IP client vào ssh-blocklist ipset.")
    info(f"Cấu hình: maxretry=3, findtime=30s, bantime=120s")
    print()

    try:
        import paramiko
    except ImportError:
        result_unexpected("THIẾU THƯ VIỆN", "paramiko chưa được cài đặt — pip install paramiko")
        return False

    MY_IP = CLIENT_IP

    # ── Step 1: verify not currently banned ───────────────────
    info("Kiểm tra trạng thái ban hiện tại...")
    try:
        r = requests.get(f"http://{SERVER_IP}:{SERVER_PORT}/ipset/ssh-blocklist", timeout=5)
        data = r.json()
        if MY_IP in data.get("members", []):
            info(f"{MY_IP} đang bị ban từ trước — đang thử xóa...")
            # Try to check if we can still reach HTTP; if fail2ban only blocks SSH, we still can
    except Exception as exc:
        info(f"Không thể truy vấn ipset endpoint: {exc}")

    # ── Step 2: make 4 failed SSH authentication attempts ─────
    ATTEMPTS = 4
    info(f"Thực hiện {ATTEMPTS} lần đăng nhập SSH thất bại tới {SERVER_IP}:{SSH_PORT}...")
    for i in range(1, ATTEMPTS + 1):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            ssh.connect(
                SERVER_IP,
                port=SSH_PORT,
                username=f"attacker{i}",
                password="wrongpassword123",
                timeout=5,
                banner_timeout=8,
                auth_timeout=5,
                look_for_keys=False,
                allow_agent=False,
            )
            ssh.close()
        except paramiko.AuthenticationException:
            info(f"  Lần {i}/{ATTEMPTS}: Xác thực thất bại (dự kiến) ✓")
        except Exception as exc:
            info(f"  Lần {i}/{ATTEMPTS}: Lỗi kết nối — {exc}")
        time.sleep(0.5)

    # ── Step 3: wait for fail2ban to process the log ──────────
    WAIT = 12
    info(f"Chờ {WAIT}s để fail2ban xử lý log và thêm IP vào ipset...")
    for remaining in range(WAIT, 0, -3):
        time.sleep(3)
        sys.stdout.write(f"  {remaining}s còn lại...\r")
        sys.stdout.flush()
    print()

    # ── Step 4: query the server's ipset via HTTP ─────────────
    info(f"Truy vấn server: GET /ipset/ssh-blocklist")
    try:
        r = requests.get(f"http://{SERVER_IP}:{SERVER_PORT}/ipset/ssh-blocklist", timeout=5)
        data = r.json()
    except Exception as exc:
        result_unexpected("KHÔNG THỂ TRUY VẤN", f"Không thể truy vấn /ipset/ssh-blocklist: {exc}")
        return False

    members = data.get("members", [])
    count = data.get("count", 0)
    info(f"ssh-blocklist hiện có {count} mục: {members[:5]}{'...' if count > 5 else ''}")

    if MY_IP in members:
        result_block(
            f"[fail2ban đã ban] {MY_IP} có trong ssh-blocklist!\n"
            f"  {DM}→ fail2ban phát hiện brute-force SSH và thêm IP vào ipset tự động.{RS}"
        )
        banned = True
    else:
        result_unexpected(
            "CHƯA BỊ BAN",
            f"{MY_IP} chưa xuất hiện trong ssh-blocklist — fail2ban có thể chưa xử lý log.\n"
            f"  {DM}Kiểm tra: docker exec iptables_server fail2ban-client status sshd{RS}",
        )
        banned = False

    # ── Step 5: verify SSH is now blocked ─────────────────────
    if banned:
        info("Xác minh SSH bị chặn bởi iptables + ipset rule...")
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(SERVER_IP, port=SSH_PORT, username="root", password="DemoPass123!",
                        timeout=4, banner_timeout=5, auth_timeout=4,
                        look_for_keys=False, allow_agent=False)
            ssh.close()
            result_unexpected("KẾT NỐI THÀNH CÔNG", "Mong đợi SSH bị chặn bởi ipset nhưng vẫn kết nối được")
        except paramiko.AuthenticationException:
            result_unexpected("AUTH LỖI", "Kết nối đến SSH nhưng bị từ chối auth — ipset rule có thể chưa kích hoạt")
        except Exception:
            result_block("[Xác nhận] SSH bị DROP bởi iptables ipset rule — kết nối timeout/refused!")

    return banned


# ─────────────────────────────────────────────────────────────────────────────
#  Test 18: proxy-blocklist — verify fetch-proxies.sh populated the ipset
# ─────────────────────────────────────────────────────────────────────────────
def test_proxy_blocklist() -> bool:
    banner("DEMO PROXY BLOCKLIST  (fetch-proxies.sh → proxy-blocklist ipset)")
    info("Server chạy fetch-proxies.sh khi khởi động để tải danh sách proxy công khai.")
    info("Test xác minh proxy-blocklist ipset đã được điền dữ liệu.")
    print()

    # ── Step 1: query the proxy-blocklist ─────────────────────
    info(f"Truy vấn server: GET /ipset/proxy-blocklist")
    try:
        r = requests.get(f"http://{SERVER_IP}:{SERVER_PORT}/ipset/proxy-blocklist", timeout=5)
        data = r.json()
    except Exception as exc:
        result_unexpected("KHÔNG THỂ TRUY VẤN", str(exc))
        return False

    if "error" in data:
        result_unexpected("IPSET LỖI", data["error"])
        return False

    members  = data.get("members", [])
    count    = data.get("count", 0)
    header   = data.get("header", {})

    info(f"Loại set:      {header.get('type', '?')}")
    info(f"Số phần tử:    {count}")
    info(f"Tối đa:        {header.get('maxelem', '?')}")
    info(f"Mẫu (5 đầu):  {members[:5]}")

    if count > 0:
        result_pass(
            f"proxy-blocklist có {BD}{count}{RS} mục — fetch-proxies.sh đã tải dữ liệu thành công!\n"
            f"  {DM}→ Mọi traffic từ những IP/CIDR này sẽ bị DROP bởi iptables ipset rule.{RS}"
        )
        # ── Step 2: explain the iptables rule ─────────────────
        print()
        info("Quy tắc iptables sử dụng ipset:")
        print(f"  {C}iptables -A INPUT -m set --match-set proxy-blocklist src -j DROP{RS}")
        print(f"  {DM}  → Một quy tắc duy nhất chặn hàng nghìn IP/CIDR hiệu quả.{RS}")
        print(f"  {DM}    ipset dùng hash table O(1) thay vì duyệt tuyến tính qua danh sách quy tắc.{RS}")
        return True
    else:
        result_unexpected(
            "IPSET TRỐNG",
            "proxy-blocklist không có mục — fetch-proxies.sh có thể đã gặp lỗi mạng.\n"
            f"  {DM}Kiểm tra: docker exec iptables_server /fetch-proxies.sh --verbose{RS}",
        )
        return False


# ─────────────────────────────────────────────────────────────────────────────
#  Test registry
# ─────────────────────────────────────────────────────────────────────────────
TESTS = [
    ("normal_http",          test_normal_http),
    ("null_scan",            test_null_scan),
    ("xmas_scan",            test_xmas_scan),
    ("fin_syn",              test_fin_syn),
    ("syn_rst",              test_syn_rst),
    ("fin_rst",              test_fin_rst),
    ("fin_no_ack",           test_fin_no_ack),
    ("urg_no_ack",           test_urg_no_ack),
    ("psh_no_ack",           test_psh_no_ack),
    ("fin_psh_urg",          test_fin_psh_urg),
    ("fin_syn_psh_urg",      test_fin_syn_psh_urg),
    ("fin_syn_rst_ack_urg",  test_fin_syn_rst_ack_urg),
    ("invalid_conntrack",    test_invalid_conntrack),
    ("fragmented",           test_fragmented),
    ("ip_blocking",          test_ip_blocking),
    # ── ipset + fail2ban tests ───────────────────────────────
    ("ipset_client_block",   test_ipset_client_block),
    ("fail2ban_ssh_ban",     test_fail2ban_ssh_ban),
    ("proxy_blocklist",      test_proxy_blocklist),
]


# ─────────────────────────────────────────────────────────────────────────────
#  Main
# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    args = sys.argv[1:]

    if "--list" in args:
        print("Các bài kiểm tra có sẵn:")
        for i, (name, _) in enumerate(TESTS, 1):
            marker = "  [ipset/fail2ban]" if i >= 16 else ""
            print(f"  {i:>2}. {name}{marker}")
        return

    banner(
        "iptables + ipset + fail2ban Demo — Lọc Cờ TCP · Chặn IP · NAT · ipset · fail2ban"
        f"\n  Server: {BD}{SERVER_IP}:{SERVER_PORT}{RS}{B}   "
        f"Client: {BD}{CLIENT_IP}{RS}"
    )

    if not wait_for_server():
        sys.exit(1)

    print_reference()

    # Determine which tests to run
    if args:
        selected = []
        for arg in args:
            if arg.isdigit():
                idx = int(arg) - 1
                if 0 <= idx < len(TESTS):
                    selected.append(TESTS[idx])
                else:
                    print(f"{R}Chỉ số bài kiểm tra không xác định: {arg}{RS}")
            else:
                matches = [(n, fn) for n, fn in TESTS if n == arg]
                if matches:
                    selected.extend(matches)
                else:
                    print(f"{R}Tên bài kiểm tra không xác định: {arg}{RS}")
        tests_to_run = selected
    else:
        tests_to_run = TESTS

    passed = 0
    failed = 0

    for name, fn in tests_to_run:
        try:
            ok_ = fn()
            if ok_:
                passed += 1
            else:
                failed += 1
        except Exception as exc:
            print(f"\n  {R}LỖI trong {name}: {exc}{RS}")
            failed += 1
        pause()

    # NAT explanation (not a pass/fail test, just informational)
    if not args or "nat" in args:
        explain_nat()

    # Summary
    total = passed + failed
    banner(f"KẾT QUẢ:  {G}{passed} đạt{RS}{BD}  /  {R}{failed} thất bại{RS}{BD}  /  {total} tổng")
    if failed == 0:
        print(f"  {G}{BD}Tất cả quy tắc cho iptables đã hoạt động đúng như đã setup!{RS}\n")
    else:
        print(f"  {Y}Một số bài kiểm tra cho kết quả không mong đợi — kiểm tra đầu ra quy tắc ở trên.{RS}\n")


if __name__ == "__main__":
    main()
