'use strict';
const fs = require('fs');
const path = require('path');
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  Header, Footer, AlignmentType, LevelFormat, TableOfContents,
  HeadingLevel, BorderStyle, WidthType, ShadingType, VerticalAlign,
  PageNumber, PageBreak
} = require('docx');

const OUT = path.join(__dirname, 'TaiLieu-Demo-CSATTT.docx');

// ── Colours / shared constants ─────────────────────────────────────────────
const BLUE_HDR = 'D5E8F0';
const LIGHT_GRAY = 'F5F5F5';
const tableBorder = { style: BorderStyle.SINGLE, size: 1, color: 'CCCCCC' };
const cellBorders = { top: tableBorder, bottom: tableBorder, left: tableBorder, right: tableBorder };

// ── Helpers ─────────────────────────────────────────────────────────────────
function h1(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(text)] });
}
function h2(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(text)] });
}
function h3(text) {
  return new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun(text)] });
}
function p(text, opts = {}) {
  return new Paragraph({
    spacing: { after: 120 },
    children: [new TextRun({ text, size: 24, font: 'Arial', ...opts })],
  });
}
function pBold(text) { return p(text, { bold: true }); }
function empty() { return new Paragraph({ children: [new TextRun('')] }); }

function bullet(text) {
  return new Paragraph({
    numbering: { reference: 'bullet-list', level: 0 },
    spacing: { after: 80 },
    children: [new TextRun({ text, size: 24, font: 'Arial' })],
  });
}
function numbered(text, ref) {
  return new Paragraph({
    numbering: { reference: ref, level: 0 },
    spacing: { after: 80 },
    children: [new TextRun({ text, size: 24, font: 'Arial' })],
  });
}

function code(text) {
  return new Paragraph({
    spacing: { after: 80 },
    indent: { left: 360 },
    children: [new TextRun({ text, size: 20, font: 'Courier New', color: '2B4590' })],
  });
}

// ── Table helpers ────────────────────────────────────────────────────────────
function hdrCell(text, width) {
  return new TableCell({
    borders: cellBorders,
    width: { size: width, type: WidthType.DXA },
    shading: { fill: BLUE_HDR, type: ShadingType.CLEAR },
    verticalAlign: VerticalAlign.CENTER,
    children: [new Paragraph({
      alignment: AlignmentType.CENTER,
      spacing: { after: 60, before: 60 },
      children: [new TextRun({ text, bold: true, size: 22, font: 'Arial' })],
    })],
  });
}

function dataCell(text, width, bold = false, shade = null) {
  return new TableCell({
    borders: cellBorders,
    width: { size: width, type: WidthType.DXA },
    shading: shade ? { fill: shade, type: ShadingType.CLEAR } : undefined,
    verticalAlign: VerticalAlign.CENTER,
    children: [new Paragraph({
      spacing: { after: 60, before: 60 },
      children: [new TextRun({ text, bold, size: 22, font: 'Arial' })],
    })],
  });
}

// ── Section 1: Giới thiệu ────────────────────────────────────────────────────
function sec1() {
  return [
    h1('1. Giới thiệu tổng quan'),
    h2('1.1. Mục đích'),
    p('Tài liệu này mô tả hệ thống demo an toàn thông tin csattt-demo — một phòng lab Docker Compose khép kín nhằm minh họa các khái niệm tường lửa Linux thông qua các bài kiểm tra gói tin tự động và trực tiếp.'),
    p('Hệ thống được thiết kế phục vụ mục đích học tập, giảng dạy và trình diễn các cơ chế bảo mật mạng cơ bản bao gồm:'),
    bullet('Lọc cờ TCP (TCP flag filtering) với iptables'),
    bullet('Chặn IP đơn lẻ và theo tập hợp với ipset'),
    bullet('Tự động phát hiện và cấm IP quét SSH với fail2ban'),
    bullet('Dịch địa chỉ mạng (NAT) — SNAT/MASQUERADE và DNAT'),
    bullet('Tải danh sách proxy công khai vào ipset'),
    empty(),
    h2('1.2. Tóm tắt kiến trúc'),
    p('Hệ thống chạy 2 container Docker trên một mạng bridge cô lập (172.25.0.0/24):'),
    empty(),
    new Table({
      columnWidths: [2000, 2000, 5360],
      margins: { top: 80, bottom: 80, left: 180, right: 180 },
      rows: [
        new TableRow({
          tableHeader: true,
          children: [hdrCell('Container', 2000), hdrCell('Địa chỉ IP', 2000), hdrCell('Vai trò', 5360)],
        }),
        new TableRow({ children: [
          dataCell('iptables_server', 2000, true),
          dataCell('172.25.0.10', 2000),
          dataCell('Máy chủ HTTP + SSH với bộ quy tắc iptables/ipset/fail2ban đầy đủ', 5360),
        ]}),
        new TableRow({ children: [
          dataCell('iptables_client', 2000, true),
          dataCell('172.25.0.20', 2000),
          dataCell('Trình chạy thử nghiệm tự động (Scapy + requests + paramiko)', 5360),
        ]}),
      ],
    }),
    empty(),
    p('Client tạo ra các gói tin đặc biệt và xác minh rằng từng quy tắc/cơ chế hoạt động đúng như kỳ vọng. Toàn bộ 18 bài kiểm tra chạy tự động khi khởi động.'),
  ];
}

// ── Section 2: Kiến trúc hệ thống ───────────────────────────────────────────
function sec2() {
  return [
    h1('2. Kiến trúc hệ thống'),
    h2('2.1. Sơ đồ mạng'),
    p('Hệ thống sử dụng Docker bridge network với subnet 172.25.0.0/24. Cả hai container đều có thuộc tính privileged: true để cho phép thao tác iptables, ipset và raw socket.'),
    empty(),
    p('Luồng giao tiếp:', { bold: true }),
    bullet('Client (172.25.0.20) gửi gói tin đến Server (172.25.0.10) qua cổng 80 (HTTP) và cổng 22 (SSH)'),
    bullet('Server áp dụng bộ lọc iptables tại mangle PREROUTING trước khi xử lý gói tin'),
    bullet('Gói tin hợp lệ được chuyển đến HTTP server hoặc SSH daemon'),
    bullet('Gói tin bất thường bị DROP tại tầng mangle hoặc filter INPUT'),
    empty(),
    h2('2.2. Cấu hình Docker Compose'),
    p('Tệp docker-compose.yml định nghĩa 2 service với cấu hình mạng tĩnh:'),
    empty(),
    new Table({
      columnWidths: [2500, 2000, 4860],
      margins: { top: 80, bottom: 80, left: 180, right: 180 },
      rows: [
        new TableRow({
          tableHeader: true,
          children: [hdrCell('Tham số', 2500), hdrCell('Giá trị', 2000), hdrCell('Mô tả', 4860)],
        }),
        new TableRow({ children: [dataCell('subnet', 2500), dataCell('172.25.0.0/24', 2000), dataCell('Mạng bridge cô lập riêng', 4860)] }),
        new TableRow({ children: [dataCell('server IP', 2500), dataCell('172.25.0.10', 2000), dataCell('Địa chỉ cố định của server', 4860)] }),
        new TableRow({ children: [dataCell('client IP', 2500), dataCell('172.25.0.20', 2000), dataCell('Địa chỉ cố định của client', 4860)] }),
        new TableRow({ children: [dataCell('privileged', 2500), dataCell('true', 2000), dataCell('Bắt buộc cho raw socket, iptables, ipset', 4860)] }),
        new TableRow({ children: [dataCell('port 8080:80', 2500), dataCell('HTTP', 2000), dataCell('Truy cập HTTP thủ công từ host', 4860)] }),
        new TableRow({ children: [dataCell('port 2222:22', 2500), dataCell('SSH', 2000), dataCell('Truy cập SSH thủ công / demo fail2ban từ host', 4860)] }),
      ],
    }),
    empty(),
    h2('2.3. Biến môi trường'),
    empty(),
    new Table({
      columnWidths: [2500, 2000, 4860],
      margins: { top: 80, bottom: 80, left: 180, right: 180 },
      rows: [
        new TableRow({
          tableHeader: true,
          children: [hdrCell('Biến', 2500), hdrCell('Mặc định', 2000), hdrCell('Mô tả', 4860)],
        }),
        new TableRow({ children: [dataCell('SERVER_IP', 2500), dataCell('172.25.0.10', 2000), dataCell('Địa chỉ IP của server', 4860)] }),
        new TableRow({ children: [dataCell('CLIENT_IP', 2500), dataCell('172.25.0.20', 2000), dataCell('Địa chỉ IP của client', 4860)] }),
        new TableRow({ children: [dataCell('SERVER_PORT', 2500), dataCell('80', 2000), dataCell('Cổng HTTP của server', 4860)] }),
        new TableRow({ children: [dataCell('SSH_PORT', 2500), dataCell('22', 2000), dataCell('Cổng SSH của server', 4860)] }),
        new TableRow({ children: [dataCell('SCAPY_TIMEOUT', 2500), dataCell('2', 2000), dataCell('Thời gian chờ phản hồi gói tin raw (giây)', 4860)] }),
      ],
    }),
    empty(),
  ];
}

// ── Section 3: Thành phần Server ────────────────────────────────────────────
function sec3() {
  return [
    h1('3. Thành phần Server'),
    h2('3.1. Tổng quan'),
    p('Server được xây dựng trên Ubuntu 22.04 với các thành phần chính:'),
    bullet('iptables / ip6tables — tường lửa packet filtering'),
    bullet('ipset — quản lý tập hợp IP/CIDR hiệu suất cao'),
    bullet('fail2ban — phát hiện và tự động cấm IP tấn công SSH'),
    bullet('OpenSSH Server — máy chủ SSH phục vụ demo fail2ban'),
    bullet('rsyslog — ghi log xác thực SSH vào /var/log/auth.log'),
    bullet('Python 3 — HTTP server cung cấp REST API kiểm tra ipset'),
    empty(),
    h2('3.2. Entrypoint (entrypoint.sh)'),
    p('Script entrypoint.sh thực hiện các bước sau khi container khởi động:'),
    empty(),
    new Table({
      columnWidths: [720, 2880, 5760],
      margins: { top: 80, bottom: 80, left: 180, right: 180 },
      rows: [
        new TableRow({
          tableHeader: true,
          children: [hdrCell('Bước', 720), hdrCell('Hành động', 2880), hdrCell('Chi tiết', 5760)],
        }),
        new TableRow({ children: [dataCell('1', 720), dataCell('Flush quy tắc', 2880), dataCell('Xóa toàn bộ quy tắc iptables hiện có (-F, -X) trên tất cả bảng', 5760)] }),
        new TableRow({ children: [dataCell('2', 720), dataCell('Cài NAT', 2880), dataCell('Thiết lập POSTROUTING ACCEPT + MASQUERADE trên eth0', 5760)] }),
        new TableRow({ children: [dataCell('3', 720), dataCell('Quy tắc mangle', 2880), dataCell('Áp dụng 14 quy tắc lọc cờ TCP tại mangle PREROUTING', 5760)] }),
        new TableRow({ children: [dataCell('4', 720), dataCell('Chặn IP tĩnh', 2880), dataCell('DROP 172.20.0.99 tại filter INPUT (ví dụ minh họa)', 5760)] }),
        new TableRow({ children: [dataCell('5', 720), dataCell('Tạo ipset', 2880), dataCell('Tạo proxy-blocklist (hash:net) và manual-blocklist (hash:ip)', 5760)] }),
        new TableRow({ children: [dataCell('6', 720), dataCell('Kết nối ipset', 2880), dataCell('Thêm quy tắc iptables INPUT tham chiếu đến 2 ipset trên', 5760)] }),
        new TableRow({ children: [dataCell('7', 720), dataCell('fetch-proxies.sh', 2880), dataCell('Tải danh sách proxy công khai vào proxy-blocklist', 5760)] }),
        new TableRow({ children: [dataCell('8', 720), dataCell('Khởi động SSH', 2880), dataCell('Chạy sshd, đặt mật khẩu demo root: DemoPass123!', 5760)] }),
        new TableRow({ children: [dataCell('9', 720), dataCell('Khởi động rsyslog', 2880), dataCell('Đảm bảo pipeline sshd → /var/log/auth.log cho fail2ban', 5760)] }),
        new TableRow({ children: [dataCell('10', 720), dataCell('Khởi động fail2ban', 2880), dataCell('Kích hoạt jail sshd với cấu hình trong fail2ban-jail.local', 5760)] }),
        new TableRow({ children: [dataCell('11', 720), dataCell('Khởi động HTTP', 2880), dataCell('Chạy server.py trên cổng 80 (exec python3 -u /app/server.py)', 5760)] }),
      ],
    }),
    empty(),
    h2('3.3. HTTP Server (server.py)'),
    p('Server HTTP cung cấp 2 endpoint REST:'),
    empty(),
    new Table({
      columnWidths: [3000, 6360],
      margins: { top: 80, bottom: 80, left: 180, right: 180 },
      rows: [
        new TableRow({
          tableHeader: true,
          children: [hdrCell('Endpoint', 3000), hdrCell('Chức năng', 6360)],
        }),
        new TableRow({ children: [dataCell('GET /', 3000, true), dataCell('Health check — trả về JSON với status, message, client IP, timestamp', 6360)] }),
        new TableRow({ children: [dataCell('GET /ipset/<name>', 3000, true), dataCell('Liệt kê các thành viên của ipset theo tên — dùng để xác minh kết quả test', 6360)] }),
      ],
    }),
    empty(),
    p('Endpoint /ipset/<name> thực thi lệnh ipset list <setname> và trả về JSON bao gồm tên set, header metadata, danh sách thành viên và số lượng phần tử. Tên set được kiểm tra bằng regex an toàn trước khi thực thi.'),
    empty(),
    h2('3.4. Cấu trúc quy tắc iptables'),
    empty(),
    new Table({
      columnWidths: [1500, 2000, 5860],
      margins: { top: 80, bottom: 80, left: 180, right: 180 },
      rows: [
        new TableRow({
          tableHeader: true,
          children: [hdrCell('Bảng', 1500), hdrCell('Chain', 2000), hdrCell('Quy tắc', 5860)],
        }),
        new TableRow({ children: [dataCell('nat', 1500), dataCell('POSTROUTING', 2000), dataCell('MASQUERADE trên eth0 — SNAT/NAT gateway demo', 5860)] }),
        new TableRow({ children: [dataCell('mangle', 1500), dataCell('PREROUTING', 2000), dataCell('DROP trạng thái conntrack INVALID', 5860)] }),
        new TableRow({ children: [dataCell('mangle', 1500), dataCell('PREROUTING', 2000), dataCell('DROP kết nối NEW không phải SYN thuần túy', 5860)] }),
        new TableRow({ children: [dataCell('mangle', 1500), dataCell('PREROUTING', 2000), dataCell('DROP NULL scan (không có cờ)', 5860)] }),
        new TableRow({ children: [dataCell('mangle', 1500), dataCell('PREROUTING', 2000), dataCell('DROP FIN+SYN, SYN+RST, FIN+RST (cờ mâu thuẫn)', 5860)] }),
        new TableRow({ children: [dataCell('mangle', 1500), dataCell('PREROUTING', 2000), dataCell('DROP FIN/URG/PSH không có ACK', 5860)] }),
        new TableRow({ children: [dataCell('mangle', 1500), dataCell('PREROUTING', 2000), dataCell('DROP XMAS scan và các biến thể', 5860)] }),
        new TableRow({ children: [dataCell('mangle', 1500), dataCell('PREROUTING', 2000), dataCell('DROP gói IP bị phân mảnh', 5860)] }),
        new TableRow({ children: [dataCell('filter', 1500), dataCell('INPUT', 2000), dataCell('DROP 172.20.0.99 (ví dụ chặn IP tĩnh)', 5860)] }),
        new TableRow({ children: [dataCell('filter', 1500), dataCell('INPUT', 2000), dataCell('DROP src trong proxy-blocklist ipset', 5860)] }),
        new TableRow({ children: [dataCell('filter', 1500), dataCell('INPUT', 2000), dataCell('DROP src trong manual-blocklist ipset', 5860)] }),
        new TableRow({ children: [dataCell('filter', 1500), dataCell('INPUT', 2000), dataCell('DROP src trong ssh-blocklist ipset (do fail2ban quản lý)', 5860)] }),
      ],
    }),
    empty(),
  ];
}

// ── Section 4: Thành phần Client ─────────────────────────────────────────────
function sec4() {
  return [
    h1('4. Thành phần Client'),
    h2('4.1. Tổng quan'),
    p('Client chạy Python 3.11-slim và sử dụng các thư viện sau:'),
    empty(),
    new Table({
      columnWidths: [2500, 6860],
      margins: { top: 80, bottom: 80, left: 180, right: 180 },
      rows: [
        new TableRow({
          tableHeader: true,
          children: [hdrCell('Thư viện', 2500), hdrCell('Mục đích sử dụng', 6860)],
        }),
        new TableRow({ children: [dataCell('Scapy', 2500, true), dataCell('Tạo và gửi gói tin TCP raw với cờ tùy chỉnh — kiểm tra bộ lọc iptables', 6860)] }),
        new TableRow({ children: [dataCell('requests', 2500, true), dataCell('Thực hiện HTTP GET để xác minh lưu lượng hợp lệ và truy vấn endpoint /ipset/', 6860)] }),
        new TableRow({ children: [dataCell('paramiko', 2500, true), dataCell('Mô phỏng đăng nhập SSH thất bại để kích hoạt fail2ban banning', 6860)] }),
        new TableRow({ children: [dataCell('ipset (CLI)', 2500, true), dataCell('Tạo và quản lý ipset cục bộ tại client trong bài kiểm tra 16', 6860)] }),
        new TableRow({ children: [dataCell('iptables (CLI)', 2500, true), dataCell('Thêm/xóa quy tắc OUTPUT DROP cục bộ tại client trong bài kiểm tra 15 và 16', 6860)] }),
      ],
    }),
    empty(),
    h2('4.2. Luồng thực thi (demo.py)'),
    bullet('Chờ server sẵn sàng (tối đa 30 giây, thử kết nối TCP mỗi 1 giây)'),
    bullet('In bảng tham chiếu: cờ TCP, các kiểu tấn công, NAT, ipset'),
    bullet('Chạy tuần tự 18 bài kiểm tra và in kết quả có màu (ĐẠT / BỊ CHẶN)'),
    bullet('Sau khi chạy hết, in phần giải thích NAT quan sát'),
    bullet('Tóm tắt tổng số bài đạt / thất bại'),
    empty(),
    p('Có thể chạy từng bài kiểm tra riêng lẻ theo số thứ tự hoặc tên:'),
    code('python3 /demo.py <tên_bài_kiểm_tra>'),
    code('python3 /demo.py <số_thứ_tự>'),
    code('python3 /demo.py --list'),
    empty(),
  ];
}

// ── Section 5: Chi tiết 18 bài kiểm tra ─────────────────────────────────────
function sec5() {
  const tests = [
    ['1', 'normal_http', 'HTTP GET thông thường', 'Gửi yêu cầu HTTP GET hợp lệ qua TCP stack của OS', 'ĐẠT — HTTP 200 OK'],
    ['2', 'null_scan', 'NULL scan (0x00)', 'Gói TCP không có cờ — Nmap -sN', 'BỊ CHẶN'],
    ['3', 'xmas_scan', 'XMAS scan (tất cả 6 cờ)', 'FIN+SYN+RST+PSH+ACK+URG — Nmap -sX', 'BỊ CHẶN'],
    ['4', 'fin_syn', 'FIN + SYN đồng thời', 'Cờ mâu thuẫn: SYN mở / FIN đóng cùng lúc', 'BỊ CHẶN'],
    ['5', 'syn_rst', 'SYN + RST đồng thời', 'Cờ mâu thuẫn: SYN khởi tạo / RST hủy bỏ', 'BỊ CHẶN'],
    ['6', 'fin_rst', 'FIN + RST đồng thời', 'Cả hai cờ kết thúc kết nối — loại trừ lẫn nhau', 'BỊ CHẶN'],
    ['7', 'fin_no_ack', 'FIN không có ACK', 'RFC 793: FIN luôn đi kèm ACK trong teardown hợp lệ', 'BỊ CHẶN'],
    ['8', 'urg_no_ack', 'URG không có ACK', 'Dữ liệu URG yêu cầu ACK trong luồng TCP', 'BỊ CHẶN'],
    ['9', 'psh_no_ack', 'PSH không có ACK', 'PSH luôn được gửi kèm ACK trong đoạn dữ liệu', 'BỊ CHẶN'],
    ['10', 'fin_psh_urg', 'FIN+PSH+URG (XMAS Nmap)', 'Biến thể FIN scan RFC 793 cổ điển', 'BỊ CHẶN'],
    ['11', 'fin_syn_psh_urg', 'FIN+SYN+PSH+URG', 'Tổ hợp 4 cờ không hợp lệ', 'BỊ CHẶN'],
    ['12', 'fin_syn_rst_ack_urg', 'FIN+SYN+RST+ACK+URG', 'Tổ hợp 5 cờ bất thường', 'BỊ CHẶN'],
    ['13', 'invalid_conntrack', 'ACK không có kết nối (INVALID conntrack)', 'Bare ACK — không có SYN trước — conntrack đánh dấu INVALID', 'BỊ CHẶN'],
    ['14', 'fragmented', 'Gói IP bị phân mảnh', 'Mảnh không phải đầu tiên (frag offset > 0) — bypass filter', 'BỊ CHẶN'],
    ['15', 'ip_blocking', 'Chặn IP động (OUTPUT DROP)', 'Thêm quy tắc OUTPUT DROP cục bộ, xác minh chặn, sau đó khôi phục', 'BỊ CHẶN rồi khôi phục'],
    ['16', 'ipset_client_block', 'ipset bulk block phía client', 'Tạo demo-block ipset, thêm SERVER_IP, thêm OUTPUT rule, xác minh, dọn dẹp', 'BỊ CHẶN rồi khôi phục'],
    ['17', 'fail2ban_ssh_ban', 'fail2ban SSH ban', '4 lần đăng nhập SSH thất bại → IP client vào ssh-blocklist → SSH bị DROP', 'IP bị cấm tự động'],
    ['18', 'proxy_blocklist', 'proxy-blocklist qua fetch-proxies.sh', 'Xác minh proxy-blocklist ipset đã được điền từ danh sách proxy công khai', 'ĐẠT — ipset có dữ liệu'],
  ];

  const colWidths = [400, 1600, 2200, 3200, 1960];

  const rows = [
    new TableRow({
      tableHeader: true,
      children: [
        hdrCell('STT', 400),
        hdrCell('Tên bài kiểm tra', 1600),
        hdrCell('Loại kiểm tra', 2200),
        hdrCell('Nội dung', 3200),
        hdrCell('Kết quả mong đợi', 1960),
      ],
    }),
    ...tests.map(([num, name, type_, content, expected]) =>
      new TableRow({
        children: [
          dataCell(num, 400, true, num <= '15' ? null : LIGHT_GRAY),
          dataCell(name, 1600, false, num <= '15' ? null : LIGHT_GRAY),
          dataCell(type_, 2200, false, num <= '15' ? null : LIGHT_GRAY),
          dataCell(content, 3200, false, num <= '15' ? null : LIGHT_GRAY),
          dataCell(expected, 1960, false, num <= '15' ? null : LIGHT_GRAY),
        ],
      })
    ),
  ];

  return [
    h1('5. Chi tiết 18 bài kiểm tra'),
    p('Bảng dưới tóm tắt toàn bộ 18 bài kiểm tra tự động. Bài 1–15 kiểm tra bộ lọc iptables/TCP. Bài 16–18 kiểm tra ipset và fail2ban (nền xám).'),
    empty(),
    new Table({ columnWidths: colWidths, margins: { top: 80, bottom: 80, left: 100, right: 100 }, rows }),
    empty(),
  ];
}

// ── Section 6: Cấu hình bảo mật ─────────────────────────────────────────────
function sec6() {
  return [
    h1('6. Cấu hình bảo mật'),
    h2('6.1. fail2ban (fail2ban-jail.local)'),
    p('Jail sshd được cấu hình với các thông số sau:'),
    empty(),
    new Table({
      columnWidths: [2500, 2000, 4860],
      margins: { top: 80, bottom: 80, left: 180, right: 180 },
      rows: [
        new TableRow({ tableHeader: true, children: [hdrCell('Tham số', 2500), hdrCell('Giá trị', 2000), hdrCell('Mô tả', 4860)] }),
        new TableRow({ children: [dataCell('maxretry', 2500), dataCell('3', 2000), dataCell('Số lần đăng nhập SSH thất bại trước khi cấm', 4860)] }),
        new TableRow({ children: [dataCell('findtime', 2500), dataCell('30s', 2000), dataCell('Cửa sổ thời gian đếm số lần thất bại', 4860)] }),
        new TableRow({ children: [dataCell('bantime', 2500), dataCell('120s', 2000), dataCell('Thời gian IP bị cấm (2 phút)', 4860)] }),
        new TableRow({ children: [dataCell('action', 2500), dataCell('ipset-ssh', 2000), dataCell('Action tùy chỉnh — thêm IP vào ssh-blocklist ipset với timeout', 4860)] }),
        new TableRow({ children: [dataCell('logpath', 2500), dataCell('/var/log/auth.log', 2000), dataCell('File log xác thực SSH (qua rsyslog)', 4860)] }),
      ],
    }),
    empty(),
    h2('6.2. ipset — Ba tập hợp IP'),
    empty(),
    new Table({
      columnWidths: [2500, 1500, 2000, 3360],
      margins: { top: 80, bottom: 80, left: 180, right: 180 },
      rows: [
        new TableRow({ tableHeader: true, children: [hdrCell('Tên ipset', 2500), hdrCell('Loại', 1500), hdrCell('Quản lý bởi', 2000), hdrCell('Mục đích', 3360)] }),
        new TableRow({ children: [dataCell('ssh-blocklist', 2500, true), dataCell('hash:ip', 1500), dataCell('fail2ban', 2000), dataCell('IP quét SSH tự động thêm với TTL 120s', 3360)] }),
        new TableRow({ children: [dataCell('proxy-blocklist', 2500, true), dataCell('hash:net', 1500), dataCell('fetch-proxies.sh', 2000), dataCell('CIDR proxy/Tor exit node công khai', 3360)] }),
        new TableRow({ children: [dataCell('manual-blocklist', 2500, true), dataCell('hash:ip', 1500), dataCell('Thủ công', 2000), dataCell('Chặn IP ad-hoc tùy chỉnh', 3360)] }),
      ],
    }),
    empty(),
    h2('6.3. SSH Server (sshd_config)'),
    p('Cấu hình SSH được tối giản cho mục đích demo:'),
    bullet('PermitRootLogin yes — cho phép đăng nhập root (chỉ dùng trong demo)'),
    bullet('PasswordAuthentication yes — bật xác thực bằng mật khẩu'),
    bullet('Mật khẩu root demo: DemoPass123!'),
    bullet('Không sử dụng trong môi trường production'),
    empty(),
    h2('6.4. fetch-proxies.sh — Nguồn danh sách proxy'),
    p('Script tải dữ liệu từ 3 nguồn GitHub công khai:'),
    bullet('TheSpeedX/PROXY-List'),
    bullet('clarketm/proxy-list'),
    bullet('ShiftyTR/Proxy-List'),
    p('Nếu tất cả nguồn không thể truy cập, script sẽ sử dụng bộ CIDR proxy/Tor fallback được tích hợp sẵn.'),
    p('Hỗ trợ các tùy chọn: --dry-run (xem trước), --verbose (in từng IP), --stats (thống kê ipset).'),
    empty(),
  ];
}

// ── Section 7: Hướng dẫn sử dụng ────────────────────────────────────────────
function sec7() {
  return [
    h1('7. Hướng dẫn sử dụng'),
    h2('7.1. Yêu cầu hệ thống'),
    bullet('Docker Engine (phiên bản 20.10+)'),
    bullet('Docker Compose (v2+)'),
    bullet('Hệ điều hành Linux (hoặc Linux VM) — bắt buộc vì privileged: true cần quyền iptables/ipset thực sự'),
    bullet('Không hỗ trợ Docker Desktop on Windows/macOS trực tiếp (thiếu kernel module)'),
    empty(),
    h2('7.2. Khởi động và dừng'),
    p('Khởi động và chạy toàn bộ lab tự động:'),
    code('docker compose up --build'),
    empty(),
    p('Chạy nền và tương tác thủ công:'),
    code('docker compose up --build -d'),
    code('docker exec -it iptables_client bash'),
    code('python3 /demo.py'),
    empty(),
    p('Dừng và xóa container:'),
    code('docker compose down'),
    empty(),
    h2('7.3. Chạy bài kiểm tra'),
    p('Chạy toàn bộ 18 bài kiểm tra:'),
    code('docker exec -it iptables_client python3 /demo.py'),
    empty(),
    p('Chạy bài kiểm tra theo tên:'),
    code('docker exec -it iptables_client python3 /demo.py fail2ban_ssh_ban'),
    code('docker exec -it iptables_client python3 /demo.py null_scan'),
    code('docker exec -it iptables_client python3 /demo.py proxy_blocklist'),
    empty(),
    p('Chạy bài kiểm tra theo số thứ tự:'),
    code('docker exec -it iptables_client python3 /demo.py 17'),
    code('docker exec -it iptables_client python3 /demo.py 2'),
    empty(),
    p('Liệt kê tất cả tên bài kiểm tra:'),
    code('docker exec -it iptables_client python3 /demo.py --list'),
    empty(),
    h2('7.4. Truy cập server thủ công'),
    p('Kiểm tra HTTP từ host:'),
    code('curl http://localhost:8080/'),
    code('curl http://localhost:8080/ipset/ssh-blocklist'),
    code('curl http://localhost:8080/ipset/proxy-blocklist'),
    empty(),
    p('Kết nối SSH (demo fail2ban):'),
    code('ssh -p 2222 root@localhost   # mật khẩu: DemoPass123!'),
    empty(),
    h2('7.5. Thao tác ipset thủ công'),
    code('docker exec -it iptables_server bash'),
    code('ipset list -t                              # liệt kê tất cả ipset'),
    code('ipset add manual-blocklist 1.2.3.4         # chặn IP'),
    code('ipset del manual-blocklist 1.2.3.4         # bỏ chặn IP'),
    code('ipset test manual-blocklist 1.2.3.4        # kiểm tra IP trong set'),
    code('fail2ban-client status sshd                # xem IP đang bị cấm'),
    code('fail2ban-client set sshd banip 1.2.3.4     # cấm thủ công'),
    code('fail2ban-client set sshd unbanip 1.2.3.4   # bỏ cấm thủ công'),
    code('/fetch-proxies.sh --stats                  # cập nhật proxy list'),
    empty(),
  ];
}

// ── Section 8: Giải thích khái niệm NAT ──────────────────────────────────────
function sec8() {
  return [
    h1('8. Giải thích khái niệm NAT'),
    h2('8.1. SNAT / MASQUERADE'),
    p('MASQUERADE là một dạng đặc biệt của SNAT (Source NAT) — tự động sử dụng địa chỉ IP của giao diện mạng đầu ra làm địa chỉ nguồn mới. Đây là cơ chế hoạt động của router gia đình và văn phòng, cho phép nhiều thiết bị trong mạng nội bộ chia sẻ một địa chỉ IP công cộng duy nhất.'),
    empty(),
    p('Quy tắc trong demo:'),
    code('iptables -t nat -P POSTROUTING ACCEPT'),
    code('iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE'),
    empty(),
    p('Giải thích: Bất kỳ gói tin nào rời đi qua eth0 sẽ có địa chỉ IP nguồn được thay thế bằng địa chỉ IP của eth0. POSTROUTING kích hoạt sau khi quyết định định tuyến được thực hiện, ngay trước khi gói tin rời khỏi card mạng.'),
    empty(),
    h2('8.2. DNAT (Destination NAT / Port Forwarding)'),
    p('DNAT thay đổi địa chỉ IP đích của gói tin — thường được dùng cho chuyển tiếp cổng (port forwarding) và reverse proxy. PREROUTING kích hoạt trước khi quyết định định tuyến, khi gói tin vừa đến.'),
    empty(),
    p('Ví dụ chuyển tiếp cổng (không được kích hoạt trong demo mặc định):'),
    code('iptables -t nat -A PREROUTING -p tcp --dport 8888 -j DNAT --to-destination 172.20.0.10:80'),
    empty(),
    p('Kết nối đến cổng 8888 sẽ được chuyển hướng đến cổng 80 của server nội bộ. Hữu ích cho load balancer và reverse proxy.'),
    empty(),
    h2('8.3. Bảng so sánh NAT'),
    empty(),
    new Table({
      columnWidths: [2000, 2000, 2860, 2500],
      margins: { top: 80, bottom: 80, left: 180, right: 180 },
      rows: [
        new TableRow({ tableHeader: true, children: [hdrCell('Loại NAT', 2000), hdrCell('Chain', 2000), hdrCell('Thay đổi', 2860), hdrCell('Ví dụ sử dụng', 2500)] }),
        new TableRow({ children: [dataCell('SNAT', 2000, true), dataCell('POSTROUTING', 2000), dataCell('IP nguồn', 2860), dataCell('NAT router, chia sẻ IP công cộng', 2500)] }),
        new TableRow({ children: [dataCell('MASQUERADE', 2000, true), dataCell('POSTROUTING', 2000), dataCell('IP nguồn (động)', 2860), dataCell('IP động, PPP, dial-up', 2500)] }),
        new TableRow({ children: [dataCell('DNAT', 2000, true), dataCell('PREROUTING', 2000), dataCell('IP đích / cổng', 2860), dataCell('Port forwarding, reverse proxy', 2500)] }),
      ],
    }),
    empty(),
  ];
}

// ── Section 9: Lưu ý quan trọng ─────────────────────────────────────────────
function sec9() {
  return [
    h1('9. Lưu ý quan trọng'),
    h2('9.1. Chế độ Privileged'),
    p('Cả hai container đều yêu cầu privileged: true trong docker-compose.yml. Điều này cần thiết để:'),
    bullet('Thao tác iptables và ip6tables'),
    bullet('Tạo và quản lý ipset'),
    bullet('Sử dụng raw socket với Scapy để tạo gói tin TCP tùy chỉnh'),
    p('Chế độ privileged cấp cho container quyền truy cập đầy đủ vào kernel của host. Điều này là an toàn trong môi trường lab cô lập nhưng không nên dùng trong production.', { color: 'CC3300' }),
    empty(),
    h2('9.2. Mật khẩu Demo'),
    p('Server SSH sử dụng mật khẩu root mặc định DemoPass123! và bật PasswordAuthentication. Đây là cấu hình cố ý không an toàn nhằm phục vụ demo fail2ban. Tuyệt đối không sử dụng cấu hình này trong môi trường thực tế.', { color: 'CC3300' }),
    empty(),
    h2('9.3. Yêu cầu Linux Host'),
    p('Docker Desktop trên Windows hoặc macOS không hỗ trợ trực tiếp vì thiếu các kernel module iptables/ipset thực sự. Cần chạy trên Linux host hoặc Linux VM với kernel đầy đủ.'),
    empty(),
    h2('9.4. Mục đích sử dụng'),
    p('Hệ thống này được thiết kế dành riêng cho mục đích học tập và trình diễn trong môi trường lab cô lập. Không sử dụng cho sản xuất, không kết nối Internet trực tiếp, và không dùng để thực hiện các cuộc tấn công thực sự vào hệ thống ngoài lab.'),
    empty(),
  ];
}

// ── Build Document ────────────────────────────────────────────────────────────
const doc = new Document({
  styles: {
    default: {
      document: { run: { font: 'Arial', size: 24 } },
    },
    paragraphStyles: [
      {
        id: 'Title', name: 'Title', basedOn: 'Normal',
        run: { size: 52, bold: true, color: '1A1A2E', font: 'Arial' },
        paragraph: { spacing: { before: 240, after: 120 }, alignment: AlignmentType.CENTER },
      },
      {
        id: 'Heading1', name: 'Heading 1', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 36, bold: true, color: '1A3A6B', font: 'Arial' },
        paragraph: { spacing: { before: 360, after: 180 }, outlineLevel: 0 },
      },
      {
        id: 'Heading2', name: 'Heading 2', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 28, bold: true, color: '2B5AAD', font: 'Arial' },
        paragraph: { spacing: { before: 240, after: 120 }, outlineLevel: 1 },
      },
      {
        id: 'Heading3', name: 'Heading 3', basedOn: 'Normal', next: 'Normal', quickFormat: true,
        run: { size: 24, bold: true, color: '3D7AB5', font: 'Arial' },
        paragraph: { spacing: { before: 180, after: 80 }, outlineLevel: 2 },
      },
    ],
  },
  numbering: {
    config: [
      {
        reference: 'bullet-list',
        levels: [{
          level: 0, format: LevelFormat.BULLET, text: '\u2022',
          alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } },
        }],
      },
      {
        reference: 'prereq-list',
        levels: [{
          level: 0, format: LevelFormat.DECIMAL, text: '%1.',
          alignment: AlignmentType.LEFT,
          style: { paragraph: { indent: { left: 720, hanging: 360 } } },
        }],
      },
    ],
  },
  sections: [
    {
      properties: {
        page: { margin: { top: 1440, right: 1260, bottom: 1440, left: 1260 } },
      },
      headers: {
        default: new Header({
          children: [new Paragraph({
            alignment: AlignmentType.RIGHT,
            border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: 'AAAAAA' } },
            spacing: { after: 80 },
            children: [new TextRun({ text: 'Tài liệu Hệ thống Demo An Toàn Thông Tin — csattt-demo', size: 18, font: 'Arial', color: '666666' })],
          })],
        }),
      },
      footers: {
        default: new Footer({
          children: [new Paragraph({
            alignment: AlignmentType.CENTER,
            border: { top: { style: BorderStyle.SINGLE, size: 6, color: 'AAAAAA' } },
            spacing: { before: 80 },
            children: [
              new TextRun({ text: 'Trang ', size: 18, font: 'Arial', color: '666666' }),
              new TextRun({ children: [PageNumber.CURRENT], size: 18, font: 'Arial', color: '666666' }),
              new TextRun({ text: ' / ', size: 18, font: 'Arial', color: '666666' }),
              new TextRun({ children: [PageNumber.TOTAL_PAGES], size: 18, font: 'Arial', color: '666666' }),
            ],
          })],
        }),
      },
      children: [
        // ── Cover Page ──────────────────────────────────────────────────────
        new Paragraph({ spacing: { before: 1440, after: 480 }, children: [new TextRun('')] }),
        new Paragraph({
          heading: HeadingLevel.TITLE,
          alignment: AlignmentType.CENTER,
          spacing: { before: 0, after: 240 },
          children: [new TextRun({ text: 'TÀI LIỆU HƯỚNG DẪN', font: 'Arial', size: 52, bold: true, color: '1A1A2E' })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 240 },
          children: [new TextRun({ text: 'HỆ THỐNG DEMO AN TOÀN THÔNG TIN', font: 'Arial', size: 44, bold: true, color: '1A3A6B' })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 120 },
          children: [new TextRun({ text: 'csattt-demo', font: 'Arial', size: 32, bold: true, color: '2B5AAD' })],
        }),
        new Paragraph({ spacing: { after: 240 }, children: [new TextRun('')] }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 120 },
          children: [new TextRun({ text: 'iptables  \u00B7  ipset  \u00B7  fail2ban  \u00B7  NAT', font: 'Arial', size: 26, color: '555555' })],
        }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 120 },
          children: [new TextRun({ text: 'Lab Docker Compose — 18 bài kiểm tra tự động', font: 'Arial', size: 24, color: '777777' })],
        }),
        new Paragraph({ spacing: { after: 480 }, children: [new TextRun('')] }),
        new Paragraph({
          alignment: AlignmentType.CENTER,
          spacing: { after: 120 },
          children: [new TextRun({ text: 'Ngày: 18/03/2026', font: 'Arial', size: 22, color: '888888' })],
        }),
        new Paragraph({ children: [new PageBreak()] }),

        // ── Table of Contents ───────────────────────────────────────────────
        new Paragraph({
          heading: HeadingLevel.HEADING_1,
          children: [new TextRun('Mục lục')],
        }),
        new TableOfContents('Mục lục', { hyperlink: true, headingStyleRange: '1-3' }),
        new Paragraph({ children: [new PageBreak()] }),

        // ── Sections ────────────────────────────────────────────────────────
        ...sec1(),
        ...sec2(),
        ...sec3(),
        ...sec4(),
        ...sec5(),
        ...sec6(),
        ...sec7(),
        ...sec8(),
        ...sec9(),
      ],
    },
  ],
});

Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync(OUT, buffer);
  console.log('OK — written:', OUT, `(${(buffer.length / 1024).toFixed(1)} KB)`);
}).catch(err => {
  console.error('ERROR:', err);
  process.exit(1);
});
