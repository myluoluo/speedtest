<?php
error_reporting(0);
define("reCAPTCHA_SECRET", "");
function validate_rechapcha($response)
{
    if(reCAPTCHA_SECRET == '') return true;
    
    // Verifying the user's response (https://developers.google.com/recaptcha/docs/verify)
    $verifyURL = 'https://www.google.com/recaptcha/api/siteverify';

    $query_data = [
        'secret' => reCAPTCHA_SECRET,
        'response' => $response,
        // 'remoteip' => $_SERVER['REMOTE_ADDR']
    ];

    // Collect and build POST data
    $post_data = http_build_query($query_data, '', '&');

    // Send data on the best possible way
    if (function_exists('curl_init') && function_exists('curl_setopt') && function_exists('curl_exec'))
    {
        // Use cURL to get data 10x faster than using file_get_contents or other methods
        $ch = curl_init($verifyURL);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_HTTPHEADER, array('Accept: application/json', 'Content-type: application/x-www-form-urlencoded'));
        $response = curl_exec($ch);
        curl_close($ch);
    }
    else
    {
        // If server not have active cURL module, use file_get_contents
        $opts = array('http' =>
            array(
                'method' => 'POST',
                'header' => 'Content-type: application/x-www-form-urlencoded',
                'content' => $post_data
            )
        );
        $context = stream_context_create($opts);
        $response = file_get_contents($verifyURL, false, $context);
    }

    // Verify all reponses and avoid PHP errors
    if ($response)
    {
        $result = json_decode($response);
        if ($result->success === true)
        {
            return true;
        }
        else
        {
            return $result;
        }
    }

    // Dead end
    return false;
}

$token = trim($_REQUEST["token"]);
$tokenFile = "token/" . $_SERVER['REMOTE_ADDR'] . ".token";

if($token == '' || !validate_rechapcha($_REQUEST["token"])) {
    @unlink("token/" . $_SERVER['REMOTE_ADDR'] . ".token");
    http_response_code(401);
    echo json_encode(['processedString' => "Need verification", 'rawIspInfo' => ""]);
    die();
} else {
    if(!is_dir("token")) {
        @mkdir("token");
    }
    
    // 清除旧的授权文件
    $dir = scandir('token/');
    foreach($dir as $v) {
        if(strrchr($v, '.') == '.token' && is_file("token/$v")) {
            $content = (int)file_get_contents("token/$v");
            if(time() - $content > 120) {
                @unlink("token/$v");
            }
        }
    }
    @unlink("token/" . $_SERVER['REMOTE_ADDR'] . ".token");

    // 创建授权文件
    file_put_contents($tokenFile, time());
}

/*
 * This script detects the client's IP address and fetches ISP info from ipinfo.io/
 * Output from this script is a JSON string composed of 2 objects: a string called processedString which contains the combined IP, ISP, Contry and distance as it can be presented to the user; and an object called rawIspInfo which contains the raw data from ipinfo.io (will be empty if isp detection is disabled).
 * Client side, the output of this script can be treated as JSON or as regular text. If the output is regular text, it will be shown to the user as is.
 */

define('API_KEY_FILE', 'getIP_ipInfo_apikey.php');
define('SERVER_LOCATION_CACHE_FILE', 'getIP_serverLocation.php');

/**
 * @return string
 */
function getClientIp()
{
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_REAL_IP'])) {
        $ip = $_SERVER['HTTP_X_REAL_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        $ip = preg_replace('/,.*/', '', $ip); # hosts are comma-separated, client is first
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }

    return preg_replace('/^::ffff:/', '', $ip);
}

/**
 * @param string $ip
 *
 * @return string|null
 */
function getLocalOrPrivateIpInfo($ip)
{
    // ::1/128 is the only localhost ipv6 address. there are no others, no need to strpos this
    if ('::1' === $ip) {
        return 'localhost IPv6 access';
    }

    // simplified IPv6 link-local address (should match fe80::/10)
    if (stripos($ip, 'fe80:') === 0) {
        return 'link-local IPv6 access';
    }

    // anything within the 127/8 range is localhost ipv4, the ip must start with 127.0
    if (strpos($ip, '127.') === 0) {
        return 'localhost IPv4 access';
    }

    // 10/8 private IPv4
    if (strpos($ip, '10.') === 0) {
        return 'private IPv4 access';
    }

    // 172.16/12 private IPv4
    if (preg_match('/^172\.(1[6-9]|2\d|3[01])\./', $ip) === 1) {
        return 'private IPv4 access';
    }

    // 192.168/16 private IPv4
    if (strpos($ip, '192.168.') === 0) {
        return 'private IPv4 access';
    }

    // IPv4 link-local
    if (strpos($ip, '169.254.') === 0) {
        return 'link-local IPv4 access';
    }

    return null;
}

/**
 * @return string
 */
function getIpInfoTokenString()
{
    if (
        !file_exists(API_KEY_FILE)
        || !is_readable(API_KEY_FILE)
    ) {
        return '';
    }

    require API_KEY_FILE;

    if (empty($IPINFO_APIKEY)) {
        return '';
    }

    return '?token='.$IPINFO_APIKEY;
}

/**
 * @param string $ip
 *
 * @return array|null
 */
function getIspInfo($ip)
{
    $json = file_get_contents('https://ipinfo.io/'.$ip.'/json'.getIpInfoTokenString());
    if (!is_string($json)) {
        return null;
    }

    $data = json_decode($json, true);
    if (!is_array($data)) {
        return null;
    }

    return $data;
}

/**
 * @param array|null $rawIspInfo
 *
 * @return string
 */
function getIsp($rawIspInfo)
{
    if (
        !is_array($rawIspInfo)
        || !array_key_exists('org', $rawIspInfo)
        || !is_string($rawIspInfo['org'])
        || empty($rawIspInfo['org'])
    ) {
        return 'Unknown ISP';
    }

    // Remove AS##### from ISP name, if present
    return preg_replace('/AS\\d+\\s/', '', $rawIspInfo['org']);
}

/**
 * @return string|null
 */
function getServerLocation()
{
    $serverLoc = null;
    if (
        file_exists(SERVER_LOCATION_CACHE_FILE)
        && is_readable(SERVER_LOCATION_CACHE_FILE)
    ) {
        require SERVER_LOCATION_CACHE_FILE;
    }
    if (is_string($serverLoc) && !empty($serverLoc)) {
        return $serverLoc;
    }

    $json = file_get_contents('https://ipinfo.io/json'.getIpInfoTokenString());
    if (!is_string($json)) {
        return null;
    }

    $details = json_decode($json, true);
    if (
        !is_array($details)
        || !array_key_exists('loc', $details)
        || !is_string($details['loc'])
        || empty($details['loc'])
    ) {
        return null;
    }

    $serverLoc = $details['loc'];
    $cacheData = "<?php\n\n\$serverLoc = '".addslashes($serverLoc)."';\n";
    file_put_contents(SERVER_LOCATION_CACHE_FILE, $cacheData);

    return $serverLoc;
}

/**
 * Optimized algorithm from http://www.codexworld.com
 *
 * @param float $latitudeFrom
 * @param float $longitudeFrom
 * @param float $latitudeTo
 * @param float $longitudeTo
 *
 * @return float [km]
 */
function distance(
    $latitudeFrom,
    $longitudeFrom,
    $latitudeTo,
    $longitudeTo
) {
    $rad = M_PI / 180;
    $theta = $longitudeFrom - $longitudeTo;
    $dist = sin($latitudeFrom * $rad)
        * sin($latitudeTo * $rad)
        + cos($latitudeFrom * $rad)
        * cos($latitudeTo * $rad)
        * cos($theta * $rad);

    return acos($dist) / $rad * 60 * 1.853;
}

/**
 * @param array|null $rawIspInfo
 *
 * @return string|null
 */
function getDistance($rawIspInfo)
{
    if (
        !is_array($rawIspInfo)
        || !array_key_exists('loc', $rawIspInfo)
        || !isset($_GET['distance'])
        || !in_array($_GET['distance'], ['mi', 'km'], true)
    ) {
        return null;
    }

    $unit = $_GET['distance'];
    $clientLocation = $rawIspInfo['loc'];
    $serverLocation = getServerLocation();

    if (!is_string($serverLocation)) {
        return null;
    }

    return calculateDistance(
        $serverLocation,
        $clientLocation,
        $unit
    );
}

/**
 * @param string $clientLocation
 * @param string $serverLocation
 * @param string $unit
 *
 * @return string
 */
function calculateDistance($clientLocation, $serverLocation, $unit)
{
    list($clientLatitude, $clientLongitude) = explode(',', $clientLocation);
    list($serverLatitude, $serverLongitude) = explode(',', $serverLocation);
    $dist = distance(
        $clientLatitude,
        $clientLongitude,
        $serverLatitude,
        $serverLongitude
    );

    if ('mi' === $unit) {
        $dist /= 1.609344;
        $dist = round($dist, -1);
        if ($dist < 15) {
            $dist = '<15';
        }

        return $dist.' mi';
    }

    if ('km' === $unit) {
        $dist = round($dist, -1);
        if ($dist < 20) {
            $dist = '<20';
        }

        return $dist.' km';
    }

    return null;
}

/**
 * @return void
 */
function sendHeaders()
{
    header('Content-Type: application/json; charset=utf-8');

    if (isset($_GET['cors'])) {
        header('Access-Control-Allow-Origin: *');
        header('Access-Control-Allow-Methods: GET, POST');
    }

    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0, s-maxage=0');
    header('Cache-Control: post-check=0, pre-check=0', false);
    header('Pragma: no-cache');
}

/**
 * @param string $ip
 * @param string|null $ipInfo
 * @param string|null $distance
 * @param array|null $rawIspInfo
 *
 * @return void
 */
function sendResponse(
    $ip,
    $ipInfo = null,
    $distance = null,
    $rawIspInfo = null
) {
    $processedString = $ip;
    if (is_string($ipInfo)) {
        $processedString .= ' - '.$ipInfo;
    }

    if (
        is_array($rawIspInfo)
        && array_key_exists('country', $rawIspInfo)
    ) {
        $processedString .= ', '.$rawIspInfo['country'];
    }
    if (is_string($distance)) {
        $processedString .= ' ('.$distance.')';
    }

    sendHeaders();
    echo json_encode([
        'processedString' => $processedString,
        'rawIspInfo' => $rawIspInfo ?: '',
    ]);
}

$ip = getClientIp();

$localIpInfo = getLocalOrPrivateIpInfo($ip);
// local ip, no need to fetch further information
if (is_string($localIpInfo)) {
    sendResponse($ip, $localIpInfo);
    exit;
}

if (!isset($_GET['isp'])) {
    sendResponse($ip);
    exit;
}

$rawIspInfo = getIspInfo($ip);
$isp = getIsp($rawIspInfo);
$distance = getDistance($rawIspInfo);

sendResponse($ip, $isp, $distance, $rawIspInfo);
