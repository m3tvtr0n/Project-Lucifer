<?php
// router.php - The Traffic Cop for Captive Portals

// 1. Get the requested file path (e.g. /login.php, /style.css, or /favicon.ico)
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$file = __DIR__ . $path;

// 2. SAFETY CHECK: If the requested file actually exists locally, serve it!
// This is critical. Without this, when the user clicks "Submit",
// the router would redirect the POST request back to index.php
// and delete their credentials before saving them.
if (is_file($file)) {
    return false; // returning false tells PHP: "Serve this file as-is."
}

// 3. CAPTIVE PORTAL DETECTION (The Trap)
// If the file doesn't exist locally (e.g. the user typed 'google.com'),
// we force them to our index.php page.
header("HTTP/1.1 302 Found");
header("Location: http://192.168.4.1/index.php");
exit();
?>