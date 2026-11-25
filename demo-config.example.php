<?php
// Copy to site/demo-config.php on deploy hosts that run PHP (Apache + mail()).
// On GKE batch we serve static nginx only until PHP is added.
return [
    'notify_to' => 'admin@example.com',
    'captcha_secret' => 'replace-with-build-time-secret',
];