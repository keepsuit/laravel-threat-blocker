# Upgrade guide

## Upgrading from 0.2.x to 1.0.0

### Cached lists

The detectors lists (`AbuseIpDetector`, `EmailReputationDetector`) are stored in a new format, the lists cached by
0.2.x are ignored and fetched again by the first protected request. Run `php artisan threat-blocker:update`
right after the deploy to avoid the download during a request.

### EmailReputationDetector

- `check_mx` now blocks only domains that do not accept mail: a domain without MX records is accepted when it has
  an A/AAAA record, a domain with a null MX is blocked. When the DNS lookup fails the request is allowed and nothing is cached.
- The exception message is now `Email domain does not accept mail.`, the `reason` in the context is still `no_mx`.
- Custom `Keepsuit\ThreatBlocker\Contracts\DnsResolver` implementations must replace `hasMxRecord(string $domain): bool`
  with `acceptsMail(string $domain): ?bool`, returning `null` when the lookup fails.

### AiSpamDetector

- `AiSpamDetector::EXCLUDED_FIELDS` are now case-insensitive patterns: fields whose name contains `token`,
  `password` or `secret` are never sent to the provider.

### Other changes

- `Keepsuit\ThreatBlocker\Commands\UpdateAbuseIpCommand` was renamed to `UpdateSourcesCommand`, the
  `threat-blocker:update` signature is unchanged. A failing source no longer stops the update of the others,
  and the command exits with a failure code.
- `ThreatBlocker::$enabled` is no longer public, use `ThreatBlocker::enabled()`.
- `laravel/ai` must be `^1.0` and `spatie/laravel-honeypot` must be `^4.5` when installed.

## Upgrading from 0.1.x to 0.2.0

### Requirements

- Laravel 11 is no longer supported, Laravel 12 or 13 is required.

### Configuration

Compare your published `config/threat-blocker.php` with the package one:

- `Keepsuit\ThreatBlocker\Reponders` was renamed to `Keepsuit\ThreatBlocker\Responders`: update the `BlankPageResponder` / `ForbiddenResponder` import.
- New top-level `methods` option (default `['POST']`), an HTTP methods allowlist for all detectors. Each detector can override it with its own `methods` option, `'*'` means any method. Detectors that read the request body (`FormHoneypotDetector`, `AiSpamDetector`, `EmailReputationDetector`) only run on `POST`, `PUT` and `PATCH`.
- **`AbuseIpDetector` no longer checks `GET` requests** (and any method other than `POST`). To keep the previous behavior set `'methods' => ['*']` on it.
- The `detectors` array is not merged with the package defaults, so new detectors must be added to your published config:
  - `EmailReputationDetector` and `BotSignatureDetector` are enabled by default (the latter blocks missing and known bot User-Agents).
  - `AiSpamDetector` is disabled by default and requires `laravel/ai` and a configured classification provider.

### Events and exceptions

- `ThreatDetectedEvent` no longer has the `detectorId` property, use `$event->exception->detectorId`.
- `ThreatDetectedException` now takes the detector id and an optional context: `new ThreatDetectedException($this->id(), 'Message.', ['key' => 'value'])`. The message is prefixed with the detector id (`[bot-signature] Known bot User-Agent detected.`), and `$exception->context` exposes the detection details.
- Detector ids changed: `abuseip` is now `abuse-ip` and `formhoneyp` is now `form-honeypot` (also shown by `threat-blocker:update`).
- The package does not log detections, listen to `ThreatDetectedEvent` to do it (see the README).

### Custom detectors

- Implement the new `id(): string` method of the `Detector` contract, it returns the detector id (e.g. `'my-detector'`).
- `ThreatBlocker::detectorId()` was removed, use `$detector->id()`.
- Optionally honor the `methods` option with `Keepsuit\ThreatBlocker\Enums\HttpMethod::fromOptions($options)` and `HttpMethod::matches($methods, $request)`.
