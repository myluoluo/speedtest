<?php
error_reporting(0);
$tokenFile = "token/" . $_SERVER['REMOTE_ADDR'] . ".token";
if(!file_exists($tokenFile)) {
    set_time_limit(1);
    fastcgi_finish_request();
    http_response_code(401);
    die();
} else {
    $content = (int)file_get_contents($tokenFile);
    if(time() - $content > 120) {
        @unlink($tokenFile);
        die();
    }
}

header('HTTP/1.1 200 OK');

if (isset($_GET['cors'])) {
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST');
    header('Access-Control-Allow-Headers: Content-Encoding, Content-Type');
}

header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0, s-maxage=0');
header('Cache-Control: post-check=0, pre-check=0', false);
header('Pragma: no-cache');
header('Connection: keep-alive');
