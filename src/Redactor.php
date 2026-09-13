<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor;

use Illuminate\Container\Container;
use Illuminate\Support\Traits\Conditionable;
use Illuminate\Support\Traits\Macroable;
use Kirschbaum\Redactor\Detection\Confidence;
use Kirschbaum\Redactor\Detection\Detection;
use Kirschbaum\Redactor\Events\RedactionPerformed;
use Kirschbaum\Redactor\Operators\Operator;
use Kirschbaum\Redactor\Operators\OperatorRegistry;
use Kirschbaum\Redactor\Path\PathCursor;
use Kirschbaum\Redactor\Path\PathMatch;
use Kirschbaum\Redactor\Recognition\Recognizer;
use Kirschbaum\Redactor\Recognition\RecognizerRegistry;
use Kirschbaum\Redactor\Strategies\Contracts\ChainableStrategy;
use Kirschbaum\Redactor\Strategies\Contracts\ConditionalStrategy;
use Kirschbaum\Redactor\Strategies\Contracts\DetectingStrategy;
use Kirschbaum\Redactor\Strategies\Contracts\PreservingStrategy;
use Kirschbaum\Redactor\Strategies\Contracts\Strategy;
use Kirschbaum\Redactor\Strategies\RegexPatternsStrategy;
use Kirschbaum\Redactor\Strategies\StrategyOutcome;
use Kirschbaum\Redactor\Support\Configuration;
use Kirschbaum\Redactor\Support\InternalLog;
use Kirschbaum\Redactor\Support\SecretRegistry;
use Kirschbaum\Redactor\Tokenization\Detokenizer;

class Redactor
{
    use Conditionable;
    use Macroable;

    /** @var array<string, array<Strategy>> */
    private array $profileStrategies = [];

    /** @var array<string, Strategy> */
    private array $customStrategies = [];

    private bool $customStrategiesLoaded = false;

    private OperatorRegistry $operators;

    private SecretRegistry $secrets;

    private RecognizerRegistry $recognizers;

    public function __construct()
    {
        $this->operators = new OperatorRegistry;
        $this->secrets = new SecretRegistry;
        $this->recognizers = new RecognizerRegistry;
    }

    /**
     * Register a named entity recognizer, selectable from config by name.
     */
    public function registerRecognizer(Recognizer $recognizer): void
    {
        $this->recognizers->register($recognizer);
    }

    /**
     * Get the recognizer registry.
     */
    public function recognizers(): RecognizerRegistry
    {
        return $this->recognizers;
    }

    /**
     * Exchange every known token in the content for its original value.
     *
     * Unknown tokens - expired, foreign, invented by a model - are left as they are.
     */
    public function detokenize(mixed $content): mixed
    {
        /** @var Detokenizer $detokenizer */
        $detokenizer = Container::getInstance()->make(Detokenizer::class);

        return $detokenizer->detokenize($content);
    }

    /**
     * Register a value that must never appear in output, for every profile.
     *
     * Meant for credentials that only exist at runtime. Values too short to
     * match safely are refused, and false is returned.
     */
    public function registerSecret(string $value, string $entity = 'known_secret'): bool
    {
        return $this->secrets->add($value, $entity);
    }

    /**
     * Register a custom operator, usable from config by name.
     */
    public function registerOperator(string $name, Operator $operator): void
    {
        $this->operators->register($name, $operator);
    }

    /**
     * Get the operator registry.
     */
    public function operators(): OperatorRegistry
    {
        return $this->operators;
    }

    /**
     * Begin a redaction with the given profile.
     */
    public function profile(?string $profile): PendingRedaction
    {
        return new PendingRedaction($this, $profile);
    }

    /**
     * Redact the content and return it.
     */
    public function redact(mixed $content, ?string $profile = null): mixed
    {
        return $this->redactWithMetadata($content, $profile)->value;
    }

    /**
     * Redact the content and return it with what was found.
     */
    public function inspect(mixed $content, ?string $profile = null, ?bool $mark = null): RedactionResult
    {
        return $this->redactWithMetadata($content, $profile, $mark);
    }

    /**
     * Redact the content and return the redaction metadata alongside it.
     *
     * The metadata is kept out of the payload rather than written into it.
     */
    public function redactWithMetadata(mixed $content, ?string $profile = null, ?bool $mark = null): RedactionResult
    {
        $config = RedactorConfig::fromConfig($profile);

        if (! $config->enabled) {
            return new RedactionResult($content, false);
        }

        $context = new RedactionContext($config, $this->operators, $this->secrets, $this->recognizers);
        $strategies = $this->getStrategiesForProfile($config);

        $redactedContent = $this->redactRecursively($content, '', $context, $strategies, false, $config->paths->cursor());

        $redactedKeys = $context->getRedactedKeys();

        // An explicit $mark overrides the profile, since a response or export did not ask for markers...
        if (is_array($redactedContent) && $context->hasRedactions() && ($mark ?? $config->markRedacted)) {
            $redactedContent = $this->markResultArray($redactedContent, $redactedKeys, $config);
        }

        $result = new RedactionResult(
            value: $redactedContent,
            wasRedacted: $context->hasRedactions(),
            redactedKeys: $redactedKeys,
            findings: $context->getFindings(),
        );

        if ($result->wasRedacted && $this->eventsEnabled()) {
            $this->announce($config->profile, $result);
        }

        return $result;
    }

    /**
     * Determine if redaction events should be dispatched.
     */
    private function eventsEnabled(): bool
    {
        return $this->events ??= (bool) Configuration::get('redactor.events', true);
    }

    private ?bool $events = null;

    /**
     * Dispatch a RedactionPerformed event carrying names and counts only.
     *
     * A listener that throws inside the logging pipeline would take the log
     * line down with it, so any failure is swallowed.
     */
    private function announce(string $profile, RedactionResult $result): void
    {
        $rules = [];
        $entities = [];

        foreach ($result->findings as $finding) {
            $rules[$finding->rule] = ($rules[$finding->rule] ?? 0) + 1;
            $entities[$finding->entity()] = ($entities[$finding->entity()] ?? 0) + 1;
        }

        try {
            event(new RedactionPerformed($profile, $result->redactedKeys, $rules, $entities, count($result->findings)));
        } catch (\Throwable $e) {
            InternalLog::warning('A RedactionPerformed listener failed', [
                'exception_type' => get_class($e),
                'exception_message' => $e->getMessage(),
            ]);
        }
    }

    /**
     * Write the legacy `_redacted` markers into the payload, where it is safe.
     *
     * @param  array<array-key, mixed>  $array
     * @param  array<int, string>  $redactedKeys
     * @return array<array-key, mixed>
     */
    private function markResultArray(array $array, array $redactedKeys, RedactorConfig $config): array
    {
        // A string key would turn a JSON list into an object once encoded...
        if (array_is_list($array) && $array !== []) {
            return $array;
        }

        // Never clobber a key the caller is already using...
        if (array_key_exists('_redacted', $array)) {
            InternalLog::warning('Payload already contains a "_redacted" key; redaction markers were not added', [
                'profile' => $config->profile,
            ]);

            return $array;
        }

        $array['_redacted'] = true;

        if ($config->trackRedactedKeys && $redactedKeys !== [] && ! array_key_exists('_redacted_keys', $array)) {
            $array['_redacted_keys'] = $redactedKeys;
        }

        return $array;
    }

    /**
     * Redact the content without ever throwing.
     *
     * Meant for the logging pipeline, where an exception would take down the
     * whole channel, including the error that explains why. On failure the
     * content is replaced wholesale rather than passed through, since data
     * whose redaction could not be verified is not safe to emit.
     */
    public function redactSafely(mixed $content, ?string $profile = null): mixed
    {
        try {
            return $this->redact($content, $profile);
        } catch (\Throwable $e) {
            InternalLog::warning('Redaction failed; content replaced as a precaution', [
                'profile' => $profile,
                'exception_type' => get_class($e),
                'exception_message' => $e->getMessage(),
            ]);

            return $this->failClosed($profile);
        }
    }

    /**
     * Get the value emitted when redaction could not be completed.
     */
    protected function failClosed(?string $profile): string
    {
        $replacement = '[REDACTED]';

        try {
            $replacement = RedactorConfig::fromConfig($profile)->replacement;
        } catch (\Throwable) {
            // The config is what failed, so fall back to the documented default...
        }

        return $replacement.' (redaction failed)';
    }

    /**
     * Resolve every configured profile, collecting the problems found.
     *
     * Run at deploy time so a bad profile fails the deploy rather than the
     * first log line that uses it.
     *
     * @return array<string, string> profile name => error message
     */
    public function validateProfiles(): array
    {
        $errors = [];

        foreach ($this->profiles() as $profile) {
            try {
                $config = RedactorConfig::fromConfig($profile);

                $this->buildStrategiesForProfile($config);

                $configured = array_values(array_filter($config->strategies, 'is_string'));

                $conflicts = array_values(array_intersect($config->safeKeys, $config->blockedKeys));

                if ($conflicts !== []) {
                    // SafeKeysStrategy runs first, so a key in both lists is silently never redacted...
                    $errors[$profile] = 'Keys listed in both safe_keys and blocked_keys (safe_keys wins, so these are never redacted): '
                        .implode(', ', $conflicts);

                    continue;
                }

                // Resolved one by one rather than by count, since a conditional strategy
                // the profile switched off still resolves but stays out of the chain...
                $unresolved = array_values(array_filter(
                    $configured,
                    fn (string $name) => $this->createStrategyInstance($name, $config) === null
                ));

                if ($unresolved !== []) {
                    $errors[$profile] = 'Unresolvable strategies: '.implode(', ', $unresolved);

                    continue;
                }

                $failedSamples = $this->checkSamples($config);

                if ($failedSamples !== []) {
                    $errors[$profile] = implode('; ', $failedSamples);
                }
            } catch (\Throwable $e) {
                $errors[$profile] = $e->getMessage();
            }
        }

        return $errors;
    }

    /**
     * Check every rule's samples through the real detection path, describing each that fails.
     *
     * @return array<int, string>
     */
    private function checkSamples(RedactorConfig $config): array
    {
        $strategy = new RegexPatternsStrategy;
        $context = new RedactionContext($config, $this->operators, $this->secrets, $this->recognizers);
        $problems = [];

        foreach ($config->patterns as $rule) {
            foreach ($rule->samples as $sample) {
                if (! $this->ruleDetectsIn($strategy, $rule->name, $sample, $context)) {
                    $problems[] = sprintf('rule "%s" does not detect its sample %s', $rule->name, json_encode($sample));
                }
            }

            foreach ($rule->counterSamples as $sample) {
                if ($this->ruleDetectsIn($strategy, $rule->name, $sample, $context)) {
                    $problems[] = sprintf('rule "%s" detects its counter-sample %s', $rule->name, json_encode($sample));
                }
            }
        }

        return $problems;
    }

    /**
     * Determine if the given rule detects anything in the subject.
     */
    private function ruleDetectsIn(RegexPatternsStrategy $strategy, string $rule, string $subject, RedactionContext $context): bool
    {
        foreach ($strategy->detect($subject, '', $context) as $detection) {
            if ($detection->rule === $rule) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get the strategy chain for the given profile.
     *
     * @return array<Strategy>
     */
    private function getStrategiesForProfile(RedactorConfig $config): array
    {
        // The redactor is a singleton, so the chain is keyed on the profile's build
        // id: a rebuilt profile can never be served a stale chain, including one
        // that left out a conditional strategy the old profile had switched off...
        $cacheKey = $config->profile.'|'.$config->buildId;

        if (! isset($this->profileStrategies[$cacheKey])) {
            // Drop chains built for earlier builds of the same profile...
            foreach (array_keys($this->profileStrategies) as $key) {
                if (str_starts_with($key, $config->profile.'|')) {
                    unset($this->profileStrategies[$key]);
                }
            }

            $this->profileStrategies[$cacheKey] = $this->buildStrategiesForProfile($config);
        }

        return $this->profileStrategies[$cacheKey];
    }

    /**
     * Build the strategy chain for the given profile.
     *
     * @return array<Strategy>
     */
    private function buildStrategiesForProfile(RedactorConfig $config): array
    {
        $strategies = [];
        $strategyClasses = $config->strategies;

        // Config order is priority order...
        foreach ($strategyClasses as $strategyClass) {
            if (! is_string($strategyClass)) {
                continue;
            }
            $strategy = $this->createStrategyInstance($strategyClass, $config);

            if ($strategy === null) {
                continue;
            }

            // A strategy with nothing to do for this profile stays out of the chain...
            if ($strategy instanceof ConditionalStrategy && ! $strategy->appliesTo($config)) {
                continue;
            }

            $strategies[] = $strategy;
        }

        return $strategies;
    }

    /**
     * Create a strategy instance by custom name or class string.
     */
    private function createStrategyInstance(string $strategyClass, RedactorConfig $config): ?Strategy
    {
        $this->loadCustomStrategies();

        // Custom strategies registered by name take precedence...
        if (isset($this->customStrategies[$strategyClass])) {
            return clone $this->customStrategies[$strategyClass];
        }

        if (class_exists($strategyClass) && is_subclass_of($strategyClass, Strategy::class)) {
            return new $strategyClass;
        }

        return null;
    }

    /**
     * Load the custom strategies from configuration.
     */
    private function loadCustomStrategies(): void
    {
        // Loaded lazily, since the singleton is often built before the config is final...
        if ($this->customStrategiesLoaded) {
            return;
        }

        $this->customStrategiesLoaded = true;

        $customStrategyClasses = Configuration::get('redactor.custom_strategies', []);

        if (! is_array($customStrategyClasses)) {
            return;
        }

        foreach ($customStrategyClasses as $name => $className) {
            if (is_string($className) && is_string($name) && class_exists($className) && is_subclass_of($className, Strategy::class)) {
                $this->customStrategies[$name] = new $className;
            }
        }
    }

    /**
     * Recursively redact the given data using the strategy chain.
     *
     * @param  array<Strategy>  $strategies
     */
    protected function redactRecursively(
        mixed $data,
        string $key,
        RedactionContext $context,
        array $strategies,
        bool $alreadyDispatched = false,
        ?PathCursor $cursor = null
    ): mixed {
        if (! is_array($data) && ! is_object($data)) {
            return $this->applyStrategiesToValue($data, $key, $context, $strategies);
        }

        // Nothing below may recurse without a depth budget, or a self-referencing
        // toArray() or a pathologically nested payload would exhaust memory...
        if (! $context->enterDepth()) {
            return $this->markDepthExceeded($context);
        }

        try {
            if (is_array($data)) {
                /** @var array<string, mixed> $arrayData */
                $arrayData = $data;

                return $this->redactArray($arrayData, $context, $strategies, $alreadyDispatched, $cursor);
            }

            return $this->redactObject($data, $key, $context, $strategies, $cursor);
        } finally {
            $context->leaveDepth();
        }
    }

    /**
     * The marker meaning "drop this key entirely".
     */
    protected const REMOVE_MARKER = '__REDACTOR_REMOVE_OBJECT__';

    /**
     * Apply a path rule to whatever it landed on.
     *
     * Scalars get the full operator range. Containers only support preserve,
     * remove and replace, since masking or pseudonymising an array has no
     * defensible meaning; anything else collapses the subtree to the
     * replacement string.
     */
    protected function applyPathRule(mixed $value, string $key, PathMatch $match, RedactionContext $context): mixed
    {
        $spec = $match->spec;

        if ($spec->name === OperatorRegistry::PRESERVE) {
            return $value;
        }

        if ($spec->name === OperatorRegistry::REMOVE) {
            $context->recordRedaction($key, 'path:'.$match->pattern);

            return self::REMOVE_MARKER;
        }

        if ($spec->name === OperatorRegistry::NULLIFY) {
            $context->recordRedaction($key, 'path:'.$match->pattern);

            return null;
        }

        if (! is_scalar($value)) {
            $context->recordRedaction($key, 'path:'.$match->pattern);

            return $context->config->replacement;
        }

        $stringValue = (string) $value;

        if ($context->isAllowed($stringValue)) {
            return $value;
        }

        $detection = new Detection(
            entity: $key,
            rule: 'path:'.$match->pattern,
            offset: 0,
            value: $stringValue,
            // A path names the location outright, so there is nothing to be uncertain about...
            confidence: Confidence::of(Confidence::CERTAIN, sprintf('path "%s" matched', $match->pattern)),
            key: $key,
        );

        $context->recordDetection($detection);

        return $context->operate($detection, $spec);
    }

    /**
     * Replace a subtree that sits deeper than the configured max depth.
     */
    protected function markDepthExceeded(RedactionContext $context): string
    {
        $context->markRedacted();

        return sprintf(
            '%s (Max depth of %d exceeded)',
            $context->config->replacement,
            $context->config->maxDepth
        );
    }

    /**
     * Redact the given array.
     *
     * @param  array<string, mixed>  $array
     * @param  array<Strategy>  $strategies
     * @return array<string, mixed>
     */
    protected function redactArray(
        array $array,
        RedactionContext $context,
        array $strategies,
        bool $alreadyDispatched = false,
        ?PathCursor $cursor = null
    ): array {
        // Evaluate the array as a whole unless the caller already ran the chain
        // over this value with its real key, which would dispatch every nested
        // node twice...
        $outcome = $alreadyDispatched
            ? null
            : $this->applyStrategies($array, '', $context, $strategies);

        if ($outcome !== null && $outcome->value !== $array) {
            // A strategy replaced the array wholesale...
            if (is_array($outcome->value)) {
                /** @var array<string, mixed> $typedArray */
                $typedArray = $outcome->value;

                return $typedArray;
            }

            return ['_redacted_array' => $outcome->value];
        }

        // Start from the input rather than an empty array: copy-on-write means a
        // subtree that redacts to nothing costs a walk and no copy, and returning
        // the original lets the caller's identity check short-circuit...
        /** @var array<string, mixed> $result */
        $result = $array;
        $changed = false;

        foreach ($array as $key => $value) {
            $keyString = (string) $key;

            // Paths first: a rule naming this exact location outranks anything
            // inferred from the key or contents, and settling it here skips the
            // strategy chain and the walk below it entirely...
            $childCursor = $cursor?->descend($keyString);
            $pathMatch = $childCursor?->match();

            if ($pathMatch !== null) {
                $decided = $this->applyPathRule($value, $keyString, $pathMatch, $context);

                if ($decided === self::REMOVE_MARKER) {
                    unset($result[$key]);
                    $changed = true;

                    continue;
                }

                if ($decided !== $value) {
                    $result[$key] = $decided;
                    $changed = true;
                }

                continue;
            }

            $outcome = $this->applyStrategies($value, $keyString, $context, $strategies);
            $processedValue = $outcome !== null ? $outcome->value : $value;

            if ($processedValue === self::REMOVE_MARKER) {
                unset($result[$key]);
                $changed = true;

                continue;
            }

            // No strategy claimed this container, so walk into it without running
            // the chain over it again...
            if ($outcome === null && (is_array($value) || is_object($value))) {
                $processedValue = $this->redactRecursively(
                    $value,
                    $keyString,
                    $context,
                    $strategies,
                    alreadyDispatched: true,
                    cursor: $childCursor,
                );

                if ($processedValue === self::REMOVE_MARKER) {
                    unset($result[$key]);
                    $changed = true;

                    continue;
                }
            }

            if ($processedValue !== $value) {
                $result[$key] = $processedValue;
                $changed = true;
            }
        }

        return $changed ? $result : $array;
    }

    /**
     * Redact the given object.
     *
     * @param  array<Strategy>  $strategies
     */
    protected function redactObject(object $object, string $key, RedactionContext $context, array $strategies, ?PathCursor $cursor = null): mixed
    {
        $outcome = $this->applyStrategies($object, $key, $context, $strategies);
        if ($outcome !== null && $outcome->value !== $object) {
            return $outcome->value;
        }

        // Some objects are values in their own right and taking them apart
        // destroys them: a Throwable has no public properties, so its stack
        // trace would become an empty array...
        if ($this->isOpaque($object)) {
            return $object;
        }

        // An object already on the stack would loop; json_encode() catches this
        // itself, but the toArray() path below has no such protection...
        if (! $context->enterObject($object)) {
            $context->markRedacted();

            return sprintf(
                '%s (Circular reference to %s)',
                $context->config->replacement,
                get_class($object)
            );
        }

        try {
            return $this->redactObjectContents($object, $context, $strategies, $cursor);
        } finally {
            $context->leaveObject($object);
        }
    }

    /**
     * Determine if an object should pass through the walk whole.
     *
     * Throwables, dates, enums and closures carry no user-supplied fields, and
     * every logging formatter already knows how to render them. Key-based
     * rules still apply to them, since the strategy chain runs before this check.
     */
    protected function isOpaque(object $object): bool
    {
        return $object instanceof \Throwable
            || $object instanceof \DateTimeInterface
            || $object instanceof \DateTimeZone
            || $object instanceof \UnitEnum
            || $object instanceof \Closure;
    }

    /**
     * Convert the given object to an array and redact it.
     *
     * @param  array<Strategy>  $strategies
     */
    protected function redactObjectContents(object $object, RedactionContext $context, array $strategies, ?PathCursor $cursor = null): mixed
    {
        if (method_exists($object, 'toArray')) {
            try {
                /** @var array<string, mixed> $array */
                $array = $object->toArray();

                return $this->redactArray($array, $context, $strategies, alreadyDispatched: true, cursor: $cursor);
            } catch (\Throwable) {
                // Fall through to JSON encoding...
            }
        }

        // JSON encoding also surfaces circular references and unencodable objects...
        try {
            $jsonString = json_encode($object, JSON_THROW_ON_ERROR);
            $array = json_decode($jsonString, true, 512, JSON_THROW_ON_ERROR);

            if (! is_array($array)) {
                InternalLog::warning('Unable to redact object - JSON decode did not return array', [
                    'object_class' => get_class($object),
                    'reason' => 'json_decode_not_array',
                    'decoded_type' => gettype($array),
                    'behavior' => $context->config->nonRedactableObjectBehavior,
                ]);

                return $this->handleNonRedactableObject($object, $context);
            }

            /** @var array<string, mixed> $arrayData */
            $arrayData = $array;

            return $this->redactArray($arrayData, $context, $strategies, alreadyDispatched: true, cursor: $cursor);

        } catch (\Throwable $e) {
            InternalLog::warning('Exception while trying to redact object', [
                'object_class' => get_class($object),
                'reason' => 'exception_during_processing',
                'exception_type' => get_class($e),
                'exception_message' => $e->getMessage(),
                'behavior' => $context->config->nonRedactableObjectBehavior,
            ]);

            return $this->handleNonRedactableObject($object, $context);
        }
    }

    /**
     * Apply the strategies to the given value in priority order.
     *
     * @param  array<Strategy>  $strategies
     */
    protected function applyStrategies(mixed $value, string $key, RedactionContext $context, array $strategies): ?StrategyOutcome
    {
        $handled = false;

        foreach ($strategies as $strategy) {
            if (! $strategy->shouldHandle($value, $key, $context)) {
                continue;
            }

            // Detecting strategies only report; their reports are acted on together,
            // once, before anything that would change the string they were made
            // against gets to run...
            if (! $strategy instanceof DetectingStrategy && is_string($value) && $context->hasPendingDetections()) {
                $value = $context->resolvePendingDetections($value, $key);
            }

            $value = $strategy->handle($value, $key, $context);
            $handled = true;

            // A preserving strategy declares the value safe: nothing after it runs
            // and the walk does not descend, so "this key is safe" means the same
            // thing for a scalar and for the array under it...
            if ($strategy instanceof PreservingStrategy) {
                $context->discardPendingDetections();

                return new StrategyOutcome($value, preserved: true);
            }

            // A strategy that replaces the value wholesale ends the chain, while a
            // chainable one only rewrote part of a string, so the remaining
            // strategies still need to inspect what is left...
            if (! $strategy instanceof ChainableStrategy) {
                $context->discardPendingDetections();

                return new StrategyOutcome($value);
            }
        }

        if (is_string($value) && $context->hasPendingDetections()) {
            $value = $context->resolvePendingDetections($value, $key);
        }

        return $handled ? new StrategyOutcome($value) : null;
    }

    /**
     * Apply the strategies to the given value, returning it unchanged if none applied.
     *
     * @param  array<Strategy>  $strategies
     */
    protected function applyStrategiesToValue(mixed $value, string $key, RedactionContext $context, array $strategies): mixed
    {
        $outcome = $this->applyStrategies($value, $key, $context, $strategies);

        return $outcome !== null ? $outcome->value : $value;
    }

    /**
     * Handle an object that cannot be redacted according to the configured behavior.
     */
    protected function handleNonRedactableObject(object $object, RedactionContext $context): mixed
    {
        return match ($context->config->nonRedactableObjectBehavior) {
            'remove' => $this->removeObject($context),
            'empty_array' => $this->replaceWithEmptyArray($context),
            'redact' => $this->replaceWithRedactionText($object, $context),
            default => $object, // "preserve" or an unknown value...
        };
    }

    /**
     * Get the marker that removes the object from its parent entirely.
     */
    protected function removeObject(RedactionContext $context): string
    {
        $context->markRedacted();

        return self::REMOVE_MARKER;
    }

    /**
     * Replace the object with an empty array.
     *
     * @return array<string, mixed>
     */
    protected function replaceWithEmptyArray(RedactionContext $context): array
    {
        $context->markRedacted();

        return [];
    }

    /**
     * Replace the object with the redaction text.
     */
    protected function replaceWithRedactionText(object $object, RedactionContext $context): string
    {
        $context->markRedacted();

        return sprintf('%s (Non-redactable object %s)', $context->config->replacement, get_class($object));
    }

    /**
     * Register a custom strategy for use in profiles.
     */
    public function registerCustomStrategy(string $name, Strategy $strategy): void
    {
        $this->loadCustomStrategies();

        $this->customStrategies[$name] = $strategy;

        // Drop the cached chains so the new strategy is picked up...
        $this->profileStrategies = [];
    }

    /**
     * Get the names of the configured profiles.
     *
     * @return array<int, string>
     */
    public function profiles(): array
    {
        return array_values(array_map('strval', RedactorConfig::getAvailableProfiles()));
    }

    /**
     * Determine if a profile is configured.
     */
    public function hasProfile(string $profile): bool
    {
        return RedactorConfig::profileExists($profile);
    }

    /**
     * Get the strategy chain a profile resolves to.
     *
     * @return array<int, Strategy>
     */
    public function strategies(?string $profile = null): array
    {
        return array_values($this->getStrategiesForProfile(RedactorConfig::fromConfig($profile)));
    }

    /**
     * @deprecated Use profiles().
     *
     * @return array<int, string>
     */
    public function getAvailableProfiles(): array
    {
        return $this->profiles();
    }

    /**
     * @deprecated Use hasProfile().
     */
    public function profileExists(string $profile): bool
    {
        return $this->hasProfile($profile);
    }

    /**
     * @deprecated Use strategies().
     *
     * @return array<int, Strategy>
     */
    public function getStrategies(?string $profile = null): array
    {
        return $this->strategies($profile);
    }
}
