<?php
/**
 * OSSN SpamShield Component
 * 
 * Multi-layer spam protection for OSSN
 * - Honeypot fields
 * - JavaScript detection
 * - Cookie verification
 * - Timing validation
 * - User Agent filtering
 * - Rate limiting
 *
 * @package OssnSpamShield
 * @author Van Isle Web Solutions
 * @license GPL-3.0-or-later
 */

define('__OSSN_SPAMSHIELD__', ossn_route()->com . 'OssnSpamShield/');

/**
 * Initialize OssnSpamShield component
 */
function ossn_spamshield() {

    // Register action validation hook
    ossn_register_callback('action', 'load', 'ossn_spamshield_validate_action');

    // Inject SpamShield hidden fields into signup form
    ossn_extend_view('forms/signup/before/submit', 'forms/signup/before/spamshield_fields');

    // Load JavaScript on all pages
    // ossn_extend_view('js/ossn_page', 'js/ossn_spamshield');

    // Set probe cookie
    ossn_spamshield_set_probe_cookie();
    
    // Register admin settings
    if(ossn_isAdminLoggedin()) {
        // Register admin panel using OSSN 8.x standard method
        ossn_register_com_panel('OssnSpamShield', 'settings');
        
        // Register settings action
        ossn_register_action('spamshield/admin/settings', __OSSN_SPAMSHIELD__ . 'actions/admin/settings.php');
    }
}

/**
 * Install database table if it doesn't exist
 */
function ossn_spamshield_install_table() {
    
    $db = ossn_database();
    $prefix = ossn_table_prefix();
    
    // Check if table exists
    $db->statement("SHOW TABLES LIKE '{$prefix}spamshield_log'");
    $db->execute();
    $check = $db->fetch();
    
    if($check) {
        return true;
    }
    
    // Create log table
    $sql = "CREATE TABLE IF NOT EXISTS {$prefix}spamshield_log (
        id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        time_created INT UNSIGNED NOT NULL,
        ip VARCHAR(64) NOT NULL,
        user_guid INT UNSIGNED NULL,
        type VARCHAR(32) NOT NULL,
        reason VARCHAR(255) NOT NULL,
        details TEXT NULL,
        INDEX idx_time (time_created),
        INDEX idx_ip (ip),
        INDEX idx_type (type)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4";
    
    $db->statement($sql);
    return $db->execute();
}

/**
 * Set default settings if not already set
 */
function ossn_spamshield_set_defaults() {
    
    $component = new OssnComponents();
    $settings = $component->getSettings('OssnSpamShield');
    
    // Only set defaults if no settings exist yet
    if(!$settings) {
        $defaults = array(
            'enabled' => 'yes',
            'min_submit_time' => 1,
            'rate_limit_window' => 10,
            'samesite' => 'Lax'
        );
        $component->setSettings('OssnSpamShield', $defaults);
    }
}

/**
 * Get a component setting value
 */
function ossn_spamshield_get_setting($name, $default = null) {
    $component = new OssnComponents();
    $settings = $component->getSettings('OssnSpamShield');
    
    if($settings && isset($settings->$name)) {
        return $settings->$name;
    }
    
    return $default;
}

/**
 * Set probe cookie to verify browser capability
 */
function ossn_spamshield_set_probe_cookie() {
    
    if(headers_sent()) {
        return;
    }
    
    // Check if cookie already set
    if(isset($_COOKIE['ps_probe'])) {
        return;
    }
    
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || ((int)($_SERVER['SERVER_PORT'] ?? 80) === 443);
    
    $samesite = ossn_spamshield_get_setting('samesite', 'Lax');
    
    $cookie_params = [
        'ps_probe=1',
        'Path=/',
        "SameSite={$samesite}",
        $secure ? 'Secure' : null,
        'HttpOnly',
    ];
    
    header('Set-Cookie: ' . implode('; ', array_filter($cookie_params)), false);
}

/**
 * Validate all actions for spam protection
 */
function ossn_spamshield_validate_action($callback, $type, $params) {
    
    // Check if component is enabled
    if(ossn_spamshield_get_setting('enabled', 'yes') !== 'yes') {
        return;
    }
	
	// Skip validation entirely for logged-in users (they're already authenticated)
if(ossn_isLoggedin()) {
    return;
}
    
    $action = $params['action'] ?? '';
	
	// Actions that should NOT be validated (whitelist)
$skip_actions = [
    'user/login',
    'admin/login',
    'logout',
];

// Skip validation for whitelisted actions
if(in_array($action, $skip_actions)) {
    return;
}
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $now = time();
    
    // Check user status
    $is_logged_in = ossn_isLoggedin();
    $is_admin = ossn_isAdminLoggedin();
    
    // Actions requiring strict validation for GUESTS only
    $guest_strict_actions = [
        'user/register',           // User registration
        'user/resetpassword',      // Password reset
        'contact',                 // Contact forms
    ];
    
    // Determine if strict validation required
    $requires_strict = !$is_logged_in && in_array($action, $guest_strict_actions);
    
    // 1. HONEYPOT CHECK (only when field is present)
    if(isset($_POST['_psh']) && input('_psh') !== 'nobot') {
    ossn_spamshield_log('honeypot', 'Honeypot field filled', ['ip' => $ip, 'action' => $action]);
    
    // For AJAX requests (like registration), return JSON error
    if(!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
        header('Content-Type: application/json');
        echo json_encode(['dataerr' => ossn_print('spamshield:blocked:honeypot')]);
        exit;
    }
    
    // For regular requests, redirect
    ossn_trigger_message(ossn_print('spamshield:blocked:honeypot'), 'error');
    redirect(REF);
    exit;
}
    
    // 2. JAVASCRIPT CHECK (strict validation only, admins exempt)
    if($requires_strict && !$is_admin && empty(input('ps_ajax'))) {
    ossn_spamshield_log('noajax', 'Missing ps_ajax flag', ['ip' => $ip, 'action' => $action]);
    
    // For AJAX requests, return JSON error
    if(!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
        header('Content-Type: application/json');
        echo json_encode(['dataerr' => ossn_print('spamshield:blocked:noajax')]);
        exit;
    }
    
    // For regular requests, redirect
    ossn_trigger_message(ossn_print('spamshield:blocked:noajax'), 'error');
    redirect(REF);
    exit;
}
    
    // 3. TIMING CHECK (strict validation only, admins exempt)
    if($requires_strict && !$is_admin) {
    $min_time = (int)ossn_spamshield_get_setting('min_submit_time', 7);
    $start = (int)input('_pst') ?: 0;
    
    if($start > 0 && ($now - $start) < $min_time) {
        ossn_spamshield_log('timing', 'Submitted too fast', [
            'ip' => $ip,
            'action' => $action,
            'delta' => $now - $start
        ]);
        
        // For AJAX requests, return JSON error
        if(!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
            header('Content-Type: application/json');
            echo json_encode(['dataerr' => ossn_print('spamshield:blocked:timing')]);
            exit;
        }
        
        // For regular requests, redirect
        ossn_trigger_message(ossn_print('spamshield:blocked:timing'), 'error');
        redirect(REF);
        exit;
    }
}
    
    // 4. COOKIE CHECK (guests only)
    if(empty($_COOKIE['ps_probe']) && !$is_logged_in && !$is_admin) {
    ossn_spamshield_log('cookie', 'Missing ps_probe cookie', ['ip' => $ip, 'action' => $action]);
    
    // For AJAX requests, return JSON error
    if(!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
        header('Content-Type: application/json');
        echo json_encode(['dataerr' => ossn_print('spamshield:blocked:nocookie')]);
        exit;
    }
    
    // For regular requests, redirect
    ossn_trigger_message(ossn_print('spamshield:blocked:nocookie'), 'error');
    redirect(REF);
    exit;
}
    
    // 5. USER AGENT CHECK (all actions)
    if(!$ua || preg_match('~curl|python|wget|libwww|bot|spider~i', $ua)) {
    ossn_spamshield_log('ua', 'Suspicious UA', ['ip' => $ip, 'ua' => $ua, 'action' => $action]);
    
    // For AJAX requests, return JSON error
    if(!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
        header('Content-Type: application/json');
        echo json_encode(['dataerr' => ossn_print('spamshield:blocked:ua')]);
        exit;
    }
    
    // For regular requests, redirect
    ossn_trigger_message(ossn_print('spamshield:blocked:ua'), 'error');
    redirect(REF);
    exit;
}
    
    // 6. RATE LIMITING (database-based)
$window = (int)ossn_spamshield_get_setting('rate_limit_window', 10);
$cutoff_time = $now - $window;

// Log this attempt FIRST for rate limiting future requests
ossn_spamshield_log('ratelimit', 'Action attempt', [
    'ip' => $ip,
    'action' => $action
]);

// Query database for recent submissions from this IP
$db = new OssnDatabase();
$db->statement("
    SELECT COUNT(*) as count FROM ossn_spamshield_log 
    WHERE ip = ? 
    AND type = 'ratelimit'
    AND time_created > ?
");
$db->execute([$ip, $cutoff_time]);
$result = $db->fetch();

// If more than 1 attempt (current one was already logged), block
if($result && $result->count > 1) {
    // For AJAX requests, return JSON error
    if(!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
        header('Content-Type: application/json');
        echo json_encode(['dataerr' => ossn_print('spamshield:blocked:ratelimit')]);
        exit;
    }
    
    // For regular requests, redirect
    ossn_trigger_message(ossn_print('spamshield:blocked:ratelimit'), 'error');
    redirect(REF);
    exit;
}
}

/**
 * Log spam detection event
 */
function ossn_spamshield_log($type, $reason, $details = []) {
    
    try {
        $db = new OssnDatabase();
        
        $time = time();
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        $user_guid = ossn_loggedin_user() ? (int)ossn_loggedin_user()->guid : 0;
        $details_json = json_encode($details, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

    // Use OssnDatabase insert method
        $params = [
        'into' => 'spamshield_log',
        'names' => ['time_created', 'ip', 'user_guid', 'type', 'reason', 'details'],
        'values' => [$time, $ip, $user_guid, $type, $reason, $details_json]
    ];

    $db->insert($params);
        
    } catch(Exception $e) {
        error_log("OssnSpamShield Logger Error: " . $e->getMessage());
    }
}

/**
 * Run setup ONLY when the component is enabled
 */
function ossn_spamshield_on_enable($callback, $type, $params) {

    // Make sure this is OUR component
    if (!isset($params['component']) || $params['component'] !== 'OssnSpamShield') {
        return;
    }

    // Safe to use database here
    ossn_spamshield_install_table();
    ossn_spamshield_set_defaults();
}

// Register the enable callback
ossn_register_callback('ossn', 'component:enabled', 'ossn_spamshield_on_enable');

// Register component initialization
ossn_register_callback('ossn', 'init', 'ossn_spamshield');
