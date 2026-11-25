<?php
// Contact endpoint for the static deployment: "Book a demo" requests (kind = demo) and messages (kind = message).
// Each submission is stored as a JSON line in demo-requests/ (not web-readable) and emailed, formatted as HTML with
// a plain-text alternative, to the address in demo-config.php. `pnpm build:hostinger` and `pnpm release:client`
// generate demo-config.php from DEMO_NOTIFY_TO (and a fresh captcha_secret); without an address the default is used.
// The address is only on the server: the pages never show it (client feedback v3).
// Human check (client feedback v3): every submission must carry a solved proof-of-work challenge from challenge.php,
// not expired, not reused and not answered within a few seconds; each visitor is rate-limited; plus a honeypot field.
$demoConfig = is_file(__DIR__ . '/demo-config.php') ? (include __DIR__ . '/demo-config.php') : [];
$notifyTo = is_array($demoConfig) ? (string)($demoConfig['notify_to'] ?? '') : '';
if ($notifyTo === '') { $notifyTo = 'datasyncher@spectrasoln.com'; }
$captchaSecret = is_array($demoConfig) ? (string)($demoConfig['captcha_secret'] ?? '') : '';

header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
function fail(int $code, string $msg): void { http_response_code($code); echo json_encode(['ok' => false, 'error' => $msg]); exit; }
function one_line(string $s, int $max): string { return mb_substr(trim(preg_replace('/[\r\n\t]+/', ' ', $s)), 0, $max); }

if ($_SERVER['REQUEST_METHOD'] !== 'POST') { fail(405, 'Method not allowed'); }
$raw = file_get_contents('php://input', false, null, 0, 20000);
$body = json_decode($raw ?: '', true);
if (!is_array($body)) { fail(400, 'Invalid request.'); }
// Honeypot: real visitors never fill the hidden "website" field.
if (trim((string)($body['website'] ?? '')) !== '') { echo json_encode(['ok' => true]); exit; }

$dir = __DIR__ . '/demo-requests';
if (!is_dir($dir)) { @mkdir($dir, 0750, true); }

// ---- Rate limit: at most 5 submissions per visitor (hashed IP) per 10 minutes --------------------------------
$ipKey = hash('sha256', ($_SERVER['REMOTE_ADDR'] ?? '') . $captchaSecret);
$rateFile = $dir . '/rate.json';
$fh = @fopen($rateFile, 'c+');
if ($fh && flock($fh, LOCK_EX)) {
  $rates = json_decode(stream_get_contents($fh) ?: '{}', true) ?: [];
  $now = time();
  foreach ($rates as $k => $times) { $rates[$k] = array_values(array_filter($times, fn($t) => $t > $now - 600)); if (!$rates[$k]) unset($rates[$k]); }
  $limited = count($rates[$ipKey] ?? []) >= 5;
  if (!$limited) { $rates[$ipKey][] = $now; }
  ftruncate($fh, 0); rewind($fh); fwrite($fh, json_encode($rates)); flock($fh, LOCK_UN); fclose($fh);
  if ($limited) { fail(429, 'Too many messages from your connection. Please try again in a few minutes.'); }
}

// ---- Proof of work ---------------------------------------------------------------------------------------------
function human_check_fails(array $body, string $secret, string $dir): ?string {
  if (strlen($secret) < 32) { return 'The contact form is not configured.'; }
  $p = json_decode(base64_decode((string)($body['proof'] ?? ''), true) ?: '', true);
  if (!is_array($p)) { return 'Please wait for the security check to finish, then send again.'; }
  $salt = (string)($p['salt'] ?? ''); $challenge = (string)($p['challenge'] ?? '');
  $number = $p['number'] ?? null; $signature = (string)($p['signature'] ?? '');
  if (!is_int($number) || $number < 0) { return 'Security check failed. Please reload the page.'; }
  if (!hash_equals(hash_hmac('sha256', $challenge, $secret), $signature)) { return 'Security check failed. Please reload the page.'; }
  if (!hash_equals($challenge, hash('sha256', $salt . $number))) { return 'Security check failed. Please reload the page.'; }
  parse_str(explode('?', $salt, 2)[1] ?? '', $q);
  $issued = (int)($q['issued'] ?? 0); $expires = (int)($q['expires'] ?? 0); $now = time();
  if ($expires < $now) { return 'The security check expired. Please send again.'; }
  if ($now - $issued < 3) { return 'That was very fast. Please check your details and send again.'; }
  // Each challenge can be used once.
  $usedFile = $dir . '/used-challenges.txt';
  $fh = @fopen($usedFile, 'c+');
  if (!$fh || !flock($fh, LOCK_EX)) { return null; }
  $keep = []; $seen = false;
  foreach (preg_split('/\n/', stream_get_contents($fh) ?: '', -1, PREG_SPLIT_NO_EMPTY) as $line) {
    [$t, $sig] = array_pad(explode(' ', $line, 2), 2, '');
    if ((int)$t > $now - 1800) { $keep[] = $line; if (hash_equals($sig, $signature)) { $seen = true; } }
  }
  if (!$seen) { $keep[] = $now . ' ' . $signature; }
  ftruncate($fh, 0); rewind($fh); fwrite($fh, implode("\n", $keep) . "\n"); flock($fh, LOCK_UN); fclose($fh);
  return $seen ? 'This form was already sent. Please reload the page to send another.' : null;
}

$kind = ($body['kind'] ?? 'demo') === 'message' ? 'message' : 'demo';
$name = one_line((string)($body['name'] ?? ''), 200);
$email = one_line((string)($body['email'] ?? ''), 200);
$company = one_line((string)($body['company'] ?? ''), 200);
$subject = one_line((string)($body['subject'] ?? ''), 200);
$message = mb_substr(trim((string)($body['message'] ?? '')), 0, 4000);
if ($name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) { fail(422, 'Please enter your name and a valid email address.'); }
if ($kind === 'demo' && $company === '') { fail(422, 'Name, company and a valid work email are required.'); }
if ($kind === 'message' && $message === '') { fail(422, 'Please write a message.'); }
$sources = array_slice(array_map(fn($s) => one_line((string)$s, 80), is_array($body['sources'] ?? null) ? $body['sources'] : []), 0, 20);
$why = human_check_fails($body, $captchaSecret, $dir);
if ($why !== null) { fail(403, $why); }

$record = ['kind' => $kind, 'name' => $name, 'email' => $email, 'company' => $company, 'subject' => $subject,
  'sources' => $sources, 'message' => $message, 'receivedAt' => gmdate('c')];
@file_put_contents($dir . '/requests.jsonl', json_encode($record) . "\n", FILE_APPEND | LOCK_EX);

// ---- Email -------------------------------------------------------------------------------------------------
$h = fn(string $s) => htmlspecialchars($s, ENT_QUOTES, 'UTF-8');
$title = $kind === 'demo' ? 'New demo request' : 'New message from the website';
$rows = [['Name', $name], ['Email', $email]];
if ($company !== '') { $rows[] = ['Company', $company]; }
if ($kind === 'demo') { $rows[] = ['Systems to connect', $sources ? implode(', ', $sources) : 'Not specified']; }
if ($kind === 'message' && $subject !== '') { $rows[] = ['Subject', $subject]; }
$rows[] = ['Received', gmdate('j M Y, H:i') . ' UTC'];

$text = "$title\n\n";
foreach ($rows as [$k, $v]) { $text .= "$k: $v\n"; }
$text .= "\n" . ($kind === 'demo' ? 'Notes' : 'Message') . ":\n" . ($message !== '' ? $message : '(none)') . "\n";

$tr = '';
foreach ($rows as [$k, $v]) {
  $val = $k === 'Email' ? '<a href="mailto:' . $h($v) . '" style="color:#5b22bf">' . $h($v) . '</a>' : $h($v);
  $tr .= '<tr><td style="padding:8px 12px;color:#5f6b85;width:170px;vertical-align:top;border-bottom:1px solid #e6e9f2">' . $h($k)
    . '</td><td style="padding:8px 12px;color:#1b1340;border-bottom:1px solid #e6e9f2">' . $val . '</td></tr>';
}
$msgHtml = $message !== '' ? nl2br($h($message)) : '<span style="color:#5f6b85">(none)</span>';
$html = '<!doctype html><html><body style="margin:0;background:#f6f8fc;font-family:Inter,Segoe UI,Arial,sans-serif">'
  . '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#f6f8fc;padding:24px 0"><tr><td align="center">'
  . '<table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;background:#ffffff;border:1px solid #e6e9f2;border-radius:16px;overflow:hidden">'
  . '<tr><td style="background:#6e2fd5;padding:18px 24px;color:#ffffff;font-size:20px;font-weight:700">Datasyncher</td></tr>'
  . '<tr><td style="padding:24px 24px 8px;font-size:18px;font-weight:700;color:#1b1340">' . $h($title) . '</td></tr>'
  . '<tr><td style="padding:8px 12px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="font-size:14px">' . $tr . '</table></td></tr>'
  . '<tr><td style="padding:16px 24px 4px;font-size:14px;font-weight:700;color:#1b1340">' . ($kind === 'demo' ? 'Notes' : 'Message') . '</td></tr>'
  . '<tr><td style="padding:0 24px 24px;font-size:14px;line-height:22px;color:#1b1340">' . $msgHtml . '</td></tr>'
  . '<tr><td style="padding:14px 24px;background:#f6f8fc;font-size:12px;color:#5f6b85">Reply to this email to answer ' . $h($name) . ' directly.</td></tr>'
  . '</table></td></tr></table></body></html>';

$host = preg_replace('/[^a-z0-9.\-]/i', '', preg_replace('/:\d+$/', '', $_SERVER['HTTP_HOST'] ?? 'datasyncher.com'));
$host = preg_replace('/^www\./i', '', $host);
$boundary = 'ds-' . bin2hex(random_bytes(8));
$headers = implode("\r\n", [
  'From: Datasyncher website <no-reply@' . $host . '>',
  'Reply-To: ' . $email,
  'MIME-Version: 1.0',
  'Content-Type: multipart/alternative; boundary="' . $boundary . '"',
]);
$mailBody = "--$boundary\r\nContent-Type: text/plain; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n$text\r\n"
  . "--$boundary\r\nContent-Type: text/html; charset=UTF-8\r\nContent-Transfer-Encoding: 8bit\r\n\r\n$html\r\n--$boundary--\r\n";
$mailSubject = $kind === 'demo' ? 'Demo request: ' . ($company !== '' ? $company : $name) : 'Website message: ' . ($subject !== '' ? $subject : $name);
@mail($notifyTo, '=?UTF-8?B?' . base64_encode($mailSubject) . '?=', $mailBody, $headers);

echo json_encode(['ok' => true]);
