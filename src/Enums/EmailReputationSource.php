<?php

namespace Keepsuit\ThreatBlocker\Enums;

enum EmailReputationSource
{
    case DisposableEmailDomains;
    case Groundcat;
    case Castle;
    case ValidEmailChecker;

    public function url(): string
    {
        return match ($this) {
            self::DisposableEmailDomains => 'https://disposable.github.io/disposable-email-domains/domains.txt',
            self::Groundcat => 'https://raw.githubusercontent.com/groundcat/disposable-email-domain-list/master/domains.txt',
            self::Castle => 'https://raw.githubusercontent.com/castle/disposable-email-domains/master/disposable-email-domains.txt',
            self::ValidEmailChecker => 'https://www.validemailchecker.com/disposable-email-domains.txt',
        };
    }
}
