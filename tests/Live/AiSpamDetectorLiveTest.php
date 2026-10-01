<?php

use Illuminate\Http\Request;
use Illuminate\Log\Events\MessageLogged;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Facades\Http;
use Keepsuit\ThreatBlocker\Detectors\AiSpamDetector;
use Keepsuit\ThreatBlocker\Exceptions\ThreatDetectedException;
use Keepsuit\ThreatBlocker\ThreatBlocker;
use Laravel\Ai\Events\Classified;
use Laravel\Ai\Responses\Data\ChoiceAnswer;

pest()->group('live');

// Testbench only loads the skeleton's .env, not the package root one.
Dotenv\Dotenv::createImmutable(dirname(__DIR__, 2))->safeLoad();

beforeEach(function () {
    $provider = env('THREAT_BLOCKER_AI_SPAM_DETECTOR_PROVIDER') ?: match (true) {
        filled(env('TYPESAFE_API_KEY')) => 'typesafe',
        filled(env('OPENROUTER_API_KEY')) => 'openrouter',
        default => null,
    };
    $key = $provider === null ? null : env(strtoupper($provider).'_API_KEY');

    if (blank($key)) {
        $this->markTestSkipped('Set TYPESAFE_API_KEY or OPENROUTER_API_KEY to run the live AI spam tests.');
    }

    config()->set("ai.providers.{$provider}.key", $key);
    config()->set('threat-blocker.detectors', [
        AiSpamDetector::class => [
            'provider' => $provider,
            'model' => env('THREAT_BLOCKER_AI_SPAM_DETECTOR_MODEL'),
            'timeout' => 20,
        ],
    ]);

    Http::allowStrayRequests();
});

function aiLiveCheck(string $category, string $name, array $payload): void
{
    $answers = [];
    $failures = [];

    Event::listen(Classified::class, function (Classified $event) use (&$answers) {
        $answers[] = $event->response->answer('category');
    });
    Event::listen(MessageLogged::class, function (MessageLogged $event) use (&$failures) {
        if ($event->level === 'warning' && str_starts_with($event->message, 'AiSpamDetector:')) {
            $failures[] = $event->message.' '.json_encode($event->context);
        }
    });

    $blocked = false;

    try {
        app(ThreatBlocker::class)->getDetector(AiSpamDetector::class)
            ->check(Request::create('/contact', 'POST', $payload));
    } catch (ThreatDetectedException) {
        $blocked = true;
    }

    expect($failures)->toBe([]);
    expect($answers)->toHaveCount(1);
    expect($answers[0])->toBeInstanceOf(ChoiceAnswer::class);

    $probabilities = $answers[0]->probabilities;

    fwrite(STDERR, sprintf(
        "[%s] %s: %s -> %s\n",
        $category,
        $name,
        implode(' ', array_map(fn ($label, $value) => sprintf('%s=%.2f', $label, $value), array_keys($probabilities), $probabilities)),
        $blocked ? 'blocked' : 'allowed',
    ));

    expect($probabilities)->not->toBeEmpty();
    expect($blocked)->toBe($category !== 'legitimate');
}

test('allows legitimate submissions', function (string $name, array $payload) {
    aiLiveCheck('legitimate', $name, $payload);
})->with([
    'quote-with-website' => [
        'quote-with-website',
        [
            'name' => 'Giulia Bianchi',
            'email' => 'giulia.bianchi@officinebianchi.it',
            'website' => 'https://www.officinebianchi.it',
            'message' => 'Buongiorno, siamo un\'officina meccanica di Forlì e vorremmo un preventivo per un gestionale collegato al nostro ERP. Trovate la nostra attività su https://www.officinebianchi.it. Grazie, Giulia Bianchi',
        ],
    ],
    'support-question' => [
        'support-question',
        [
            'name' => 'Marco Rossi',
            'email' => 'marco.rossi@example.com',
            'message' => 'Hello, since last week I cannot export the monthly report from my dashboard: the download starts and then stops at 90%. Could you tell me whether this is a known issue? Thanks, Marco',
        ],
    ],
    'job-application' => [
        'job-application',
        [
            'name' => 'Elena Verdi',
            'email' => 'elena.verdi@example.com',
            'message' => 'Buongiorno, mi chiamo Elena e sono una sviluppatrice PHP con cinque anni di esperienza su Laravel. Vorrei candidarmi per la posizione aperta e allego il curriculum in risposta al vostro annuncio.',
        ],
    ],
    'job-application-en' => [
        'job-application-en',
        [
            'name' => 'Thomas Miller',
            'email' => 'thomas.miller@example.com',
            'website' => 'https://github.com/tmiller',
            'message' => 'Hi, I am a frontend developer with four years of experience in Vue and TypeScript. I would like to apply for the open position; my GitHub profile is linked above.',
        ],
    ],
    'call-me-back' => [
        'call-me-back',
        [
            'name' => 'Paolo',
            'email' => 'paolo@example.com',
            'message' => 'Richiamatemi appena possibile, grazie.',
        ],
    ],
]);

test('blocks spam submissions', function (string $name, array $payload) {
    aiLiveCheck('spam', $name, $payload);
})->with([
    'seo-backlinks' => [
        'seo-backlinks',
        [
            'name' => 'Kevin Smith',
            'email' => 'kevin@rankboost-seo.biz',
            'website' => 'https://rankboost-seo.biz',
            'message' => 'Hello, we can put your website on the first page of Google in 30 days. Buy 500 high quality backlinks for only $49! Visit https://rankboost-seo.biz/offer now.',
        ],
    ],
    'seo-backlinks-it' => [
        'seo-backlinks-it',
        [
            'name' => 'Agenzia Web Top',
            'email' => 'info@webtop-posizionamento.xyz',
            'message' => 'Offriamo posizionamento SEO garantito e backlink di qualità a prezzi bassissimi. Il vostro sito sarà primo su Google! Scoprite l\'offerta su http://webtop-posizionamento.xyz',
        ],
    ],
    'crypto-casino' => [
        'crypto-casino',
        [
            'name' => 'Crypto Winner',
            'email' => 'winner@bonus-casino777.top',
            'website' => 'https://bonus-casino777.top',
            'message' => 'Get 200 free spins and a 300% crypto bonus on your first deposit! Play now at https://bonus-casino777.top and earn up to 5 BTC every week.',
        ],
    ],
    'crypto-investment-it' => [
        'crypto-investment-it',
        [
            'name' => 'Investimenti Facili',
            'email' => 'team@cripto-profitti.top',
            'message' => 'Raddoppia i tuoi guadagni con il nostro bot di trading automatico: rendimento garantito del 20% al giorno in criptovalute. Iscriviti ora: https://cripto-profitti.top/registrati',
        ],
    ],
    'generic-marketing' => [
        'generic-marketing',
        [
            'name' => 'Lisa Marketing',
            'email' => 'lisa@growth-leads-pro.com',
            'website' => 'https://growth-leads-pro.com',
            'message' => 'Dear Sir or Madam, in today\'s fast-paced digital landscape, unlocking your business potential is essential. Our cutting-edge platform delivers unparalleled synergy and scalable growth. Learn more: https://growth-leads-pro.com/learn https://growth-leads-pro.com/pricing',
        ],
    ],
]);

test('blocks phishing submissions', function (string $name, array $payload) {
    aiLiveCheck('phishing', $name, $payload);
})->with([
    'fake-invoice' => [
        'fake-invoice',
        [
            'name' => 'Amministrazione',
            'email' => 'fatture@pagamenti-online-servizi.com',
            'message' => 'Gentile cliente, la fattura n. 2026/4471 di 1.284,50 EUR risulta non pagata. Per evitare il blocco del servizio effettui il pagamento entro 24 ore da qui: http://pagamenti-online-servizi.com/fattura/4471',
        ],
    ],
    'account-suspended' => [
        'account-suspended',
        [
            'name' => 'Security Team',
            'email' => 'security@account-verify-center.com',
            'message' => 'Your account has been suspended due to unusual activity. To restore access, confirm your password within 12 hours at https://account-verify-center.com/reset or your account will be permanently deleted.',
        ],
    ],
    'fake-courier' => [
        'fake-courier',
        [
            'name' => 'Corriere Express',
            'email' => 'consegne@spedizioni-express-it.com',
            'message' => 'Il suo pacco è in giacenza. Per riprogrammare la consegna è necessario pagare 1,99 EUR di spese doganali su http://spedizioni-express-it.com/paga con la sua carta.',
        ],
    ],
    'ceo-fraud' => [
        'ceo-fraud',
        [
            'name' => 'Andrea Neri - CEO',
            'email' => 'andrea.neri.ceo@gmail.com',
            'message' => 'Sono in riunione e non posso parlare. Ho bisogno che tu effettui subito un bonifico urgente di 18.500 EUR a un nuovo fornitore, IBAN DE89 3704 0044 0532 0130 00. Mantieni la riservatezza e confermami appena fatto.',
        ],
    ],
    'ceo-fraud-en' => [
        'ceo-fraud-en',
        [
            'name' => 'Richard Evans, Managing Director',
            'email' => 'r.evans.director@outlook.com',
            'message' => 'I am in a meeting and unreachable by phone. Please process an urgent wire transfer of 24,000 EUR to the account below today and keep it confidential. Reply as soon as it is done.',
        ],
    ],
]);
