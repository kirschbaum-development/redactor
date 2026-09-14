<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Detection;

/**
 * Which entities one redaction should act on.
 *
 * A profile says what can be found; a call can say what it cares about this
 * time, so an export that only needs emails and cards hidden does not need a
 * profile of its own. Entities are compared case-insensitively, and a key
 * rule's entity is the key name.
 */
class EntityFilter
{
    /** @var array<string, true>|null */
    protected ?array $only = null;

    /** @var array<string, true> */
    protected array $except = [];

    /**
     * Create a filter that allows every entity.
     */
    public static function all(): self
    {
        return new self;
    }

    /**
     * Allow only the given entities.
     *
     * @param  array<int, string>  $entities
     */
    public function only(array $entities): static
    {
        $this->only = $this->index($entities);

        return $this;
    }

    /**
     * Allow every entity but the given ones.
     *
     * @param  array<int, string>  $entities
     */
    public function except(array $entities): static
    {
        $this->except = [...$this->except, ...$this->index($entities)];

        return $this;
    }

    /**
     * Determine if the filter allows every entity.
     */
    public function allowsEverything(): bool
    {
        return $this->only === null && $this->except === [];
    }

    /**
     * Determine if a detection of this entity may be acted on.
     */
    public function allows(string $entity): bool
    {
        $entity = strtolower($entity);

        if (isset($this->except[$entity])) {
            return false;
        }

        return $this->only === null || isset($this->only[$entity]);
    }

    /**
     * @param  array<int, string>  $entities
     * @return array<string, true>
     */
    private function index(array $entities): array
    {
        $index = [];

        foreach ($entities as $entity) {
            $index[strtolower(trim($entity))] = true;
        }

        return $index;
    }
}
