<?php
// Human check for the contact forms (client feedback v3): issues a signed proof-of-work challenge, ALTCHA style.
// The browser must find `number` such that sha256(salt . number) === challenge before demo.php accepts a form.
// The signature (HMAC with the build's secret from demo-config.php) stops anyone from making their own challenges;
// demo.php also rejects challenges that are expired, reused or answered too fast. No third-party service.
header('Content-Type: application/json');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
if ($_SERVER['REQUEST_METHOD'] !== 'GET') { http_response_code(405); echo '{"error":"Method not allowed"}'; exit; }

$cfg = is_file(__DIR__ . '/demo-config.php') ? (include __DIR__ . '/demo-config.php') : [];
$secret = is_array($cfg) ? (string)($cfg['captcha_secret'] ?? '') : '';
if (strlen($secret) < 32) { http_response_code(503); echo '{"error":"Contact form is not configured."}'; exit; }

const MAX_NUMBER = 250000; // ~0.2-0.8 s on a laptop, a few s on a phone; costly for bulk senders
$now = time();
$salt = bin2hex(random_bytes(12)) . '?issued=' . $now . '&expires=' . ($now + 900);
$number = random_int(0, MAX_NUMBER);
$challenge = hash('sha256', $salt . $number);
echo json_encode([
  'algorithm' => 'SHA-256',
  'challenge' => $challenge,
  'maxnumber' => MAX_NUMBER,
  'salt' => $salt,
  'signature' => hash_hmac('sha256', $challenge, $secret),
]);
