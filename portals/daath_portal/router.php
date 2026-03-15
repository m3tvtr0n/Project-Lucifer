cat > $PORTAL_DIR/router.php << 'EOF'
<?php
// Get the requested resource
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$file = __DIR__ . $path;

// 1. If it's a real file (css, js, image), serve it.
if (is_file($file)) {
    return false; 
}

// 2. APPLE SPECIFIC OPTIMIZATION
// Instead of redirecting Apple probes, we just INCLUDE index.php right here.
// This tricks the CNA into loading the page faster without a "302 Found" hop.
$host = $_SERVER['HTTP_HOST'] ?? '';
if (strpos($host, 'apple.com') !== false || strpos($host, 'captive') !== false) {
    include 'index.php';
    exit();
}

// 3. For everyone else (Google, Microsoft), redirect them.
header("HTTP/1.1 302 Found");
header("Location: http://192.168.4.1/index.php");
exit();
?>
EOF