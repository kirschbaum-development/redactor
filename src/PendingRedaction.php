<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor;

use Illuminate\Support\Traits\Conditionable;
use Illuminate\Support\Traits\Macroable;
use Kirschbaum\Redactor\Detection\EntityFilter;

/**
 * A redaction being configured before it runs.
 *
 *     Redactor::profile('strict')->withoutMarkers()->redact($payload);
 *     Redactor::profile('observability')->inspect($payload)->findings;
 */
class PendingRedaction
{
    use Conditionable;
    use Macroable;

    protected ?bool $markers = null;

    protected ?EntityFilter $entities = null;

    public function __construct(
        protected Redactor $redactor,
        protected ?string $profile = null,
    ) {}

    /**
     * Use the given profile.
     */
    public function profile(?string $profile): static
    {
        $this->profile = $profile;

        return $this;
    }

    /**
     * Never write the "_redacted" markers into the payload.
     */
    public function withoutMarkers(): static
    {
        $this->markers = false;

        return $this;
    }

    /**
     * Write the "_redacted" markers into the payload, whatever the profile says.
     */
    public function withMarkers(): static
    {
        $this->markers = true;

        return $this;
    }

    /**
     * Act only on the given entities this time.
     *
     * @param  array<int, string>  $entities
     */
    public function only(array $entities): static
    {
        $this->entities = ($this->entities ?? EntityFilter::all())->only($entities);

        return $this;
    }

    /**
     * Act on every entity but the given ones this time.
     *
     * @param  array<int, string>  $entities
     */
    public function except(array $entities): static
    {
        $this->entities = ($this->entities ?? EntityFilter::all())->except($entities);

        return $this;
    }

    /**
     * Redact the content and return it.
     */
    public function redact(mixed $content): mixed
    {
        return $this->inspect($content)->value;
    }

    /**
     * Redact the content and return it with what was found.
     */
    public function inspect(mixed $content): RedactionResult
    {
        return $this->redactor->inspect($content, $this->profile, $this->markers, $this->entities);
    }

    /**
     * Redact the content without ever throwing, replacing it if redaction fails.
     */
    public function redactSafely(mixed $content): mixed
    {
        try {
            return $this->redact($content);
        } catch (\Throwable) {
            return $this->redactor->redactSafely($content, $this->profile);
        }
    }
}
