<?php

declare(strict_types=1);

use Illuminate\Support\Facades\Artisan;
use Kirschbaum\Redactor\Scanner\Git\GitRepository;

/**
 * A throwaway repository the tests can commit to.
 */
function gitRepo(): string
{
    $dir = sys_get_temp_dir().'/redactor_git_'.uniqid();
    mkdir($dir);
    git($dir, 'init', '-q');

    return $dir;
}

function git(string $dir, string ...$arguments): string
{
    $command = 'git -C '.escapeshellarg($dir).' -c user.email=t@example.test -c user.name=t -c commit.gpgsign=false '
        .implode(' ', array_map(escapeshellarg(...), $arguments)).' 2>&1';

    exec($command, $output, $code);

    if ($code !== 0) {
        throw new RuntimeException('git '.implode(' ', $arguments).' failed: '.implode("\n", $output));
    }

    return implode("\n", $output);
}

function scanGit(string $dir, array $arguments): array
{
    app()->setBasePath($dir);

    $exit = Artisan::call('redactor:scan', $arguments);

    return [$exit, Artisan::output()];
}

describe('Git-aware scanning', function (): void {
    beforeEach(function (): void {
        config(['redactor.scan.profile' => 'file_scan', 'redactor.scan.baseline' => null]);
        $this->dir = gitRepo();
        $this->basePath = app()->basePath();

        file_put_contents($this->dir.'/README.md', "# demo\n");
        git($this->dir, 'add', '.');
        git($this->dir, 'commit', '-q', '-m', 'initial');
    });

    afterEach(function (): void {
        app()->setBasePath($this->basePath);
        cleanupDirectory($this->dir);
    });

    it('scans only the lines staged for commit and reports their real line numbers', function (): void {
        file_put_contents($this->dir.'/README.md', "# demo\n\nsafe line\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n");
        file_put_contents($this->dir.'/unstaged.env', "STRIPE=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n");
        git($this->dir, 'add', 'README.md');

        [$exit, $output] = scanGit($this->dir, ['--staged' => true, '--output' => 'json']);
        $results = json_decode($output, true);

        expect($exit)->toBe(0)
            ->and($results)->toHaveCount(1)
            ->and($results[0]['path'])->toBe('README.md')
            ->and($results[0]['findings'])->toHaveCount(1)
            ->and($results[0]['findings'][0]['rule'])->toBe('aws_access_key')
            ->and($results[0]['findings'][0]['line'])->toBe(4);
    });

    it('fails with --bail on a staged secret, which is what the pre-commit hook relies on', function (): void {
        file_put_contents($this->dir.'/.env', "KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n");
        git($this->dir, 'add', '.env');

        [$exit] = scanGit($this->dir, ['--staged' => true, '--bail' => true, '--output' => 'json']);

        expect($exit)->toBe(1);
    });

    it('ignores a pre-existing secret that the staged change does not touch', function (): void {
        file_put_contents($this->dir.'/old.env', "KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n");
        git($this->dir, 'add', 'old.env');
        git($this->dir, 'commit', '-q', '-m', 'oops');

        file_put_contents($this->dir.'/old.env', "KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\nCOMMENT=harmless\n");
        git($this->dir, 'add', 'old.env');

        [$exit, $output] = scanGit($this->dir, ['--staged' => true, '--bail' => true, '--output' => 'json']);

        expect($exit)->toBe(0)
            ->and(json_decode($output, true)[0]['findings'])->toBe([]);
    });

    it('scans what a branch adds over a ref with --diff', function (): void {
        git($this->dir, 'checkout', '-q', '-b', 'feature');
        file_put_contents($this->dir.'/config.php', "<?php return ['token' => 'ghp_16C7e42F292c6912E7710c838347Ae178B4a'];\n");
        git($this->dir, 'add', 'config.php');
        git($this->dir, 'commit', '-q', '-m', 'add token');

        [$exit, $output] = scanGit($this->dir, ['--diff' => 'HEAD~1', '--output' => 'json']);
        $results = json_decode($output, true);

        expect($exit)->toBe(0)
            ->and($results[0]['path'])->toBe('config.php')
            ->and($results[0]['findings'][0]['rule'])->toBe('github_token');
    });

    it('finds a secret in history even after a later commit removed it', function (): void {
        file_put_contents($this->dir.'/.env', "KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n");
        git($this->dir, 'add', '.env');
        git($this->dir, 'commit', '-q', '-m', 'leak');
        $leak = trim(git($this->dir, 'rev-parse', 'HEAD'));

        file_put_contents($this->dir.'/.env', "KEY=rotated\n");
        git($this->dir, 'add', '.env');
        git($this->dir, 'commit', '-q', '-m', 'fix');

        [, $output] = scanGit($this->dir, ['--history' => '', '--output' => 'json']);
        $findings = array_merge(...array_map(fn (array $r) => $r['findings'], json_decode($output, true)));

        expect($findings)->toHaveCount(1)
            ->and($findings[0]['rule'])->toBe('stripe_key')
            ->and($findings[0]['commit'])->toBe($leak)
            ->and($findings[0]['line'])->toBe(1);
    });

    it('accepts a range for --history and a pathspec', function (): void {
        file_put_contents($this->dir.'/a.env', "A=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n");
        file_put_contents($this->dir.'/b.env', "B=AKIAIOSFODNN7EXAMPLE\n");
        git($this->dir, 'add', '.');
        git($this->dir, 'commit', '-q', '-m', 'two');

        [, $output] = scanGit($this->dir, ['--history' => 'HEAD~1..HEAD', 'paths' => ['b.env'], '--output' => 'json']);
        $results = json_decode($output, true);

        expect($results)->toHaveCount(1)
            ->and($results[0]['path'])->toBe('b.env');
    });

    it('applies the exclude patterns to git paths too', function (): void {
        config(['redactor.scan.exclude_patterns' => ['vendor/*']]);
        mkdir($this->dir.'/vendor');
        file_put_contents($this->dir.'/vendor/lib.php', "\$k = 'sk_live_4eC39HqLyjWDarjtT1zdp7dc';\n");
        git($this->dir, 'add', '-f', 'vendor/lib.php');

        [, $output] = scanGit($this->dir, ['--staged' => true, '--output' => 'json']);

        expect(json_decode($output, true))->toBe([]);
    });

    it('shows the commit in the table location for history scans', function (): void {
        file_put_contents($this->dir.'/.env', "KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\n");
        git($this->dir, 'add', '.env');
        git($this->dir, 'commit', '-q', '-m', 'leak');
        $short = substr(trim(git($this->dir, 'rev-parse', 'HEAD')), 0, 8);

        [, $output] = scanGit($this->dir, ['--history' => '']);

        expect($output)->toContain("{$short}:.env:1:");
    });

    it('reports a directory that is not a repository', function (): void {
        $plain = sys_get_temp_dir().'/redactor_plain_'.uniqid();
        mkdir($plain);

        try {
            [$exit, $output] = scanGit($plain, ['--staged' => true]);
        } finally {
            cleanupDirectory($plain);
        }

        expect($exit)->toBe(1)
            ->and($output)->toContain('not inside a git repository');
    });

    it('emits JUnit XML with a failure per finding', function (): void {
        file_put_contents($this->dir.'/.env', "KEY=sk_live_4eC39HqLyjWDarjtT1zdp7dc\nMAIL=bob@example.com\n");
        git($this->dir, 'add', '.env');

        [, $output] = scanGit($this->dir, ['--staged' => true, '--output' => 'junit']);

        $xml = simplexml_load_string($output);

        expect($xml)->not->toBeFalse()
            ->and((string) $xml['failures'])->toBe('2')
            ->and((string) $xml->testsuite->testcase['name'])->toBe('.env')
            ->and($xml->testsuite->testcase->failure)->toHaveCount(2)
            ->and($output)->not->toContain('sk_live_4eC39HqLyjWDarjtT1zdp7dc');
    });

    it('answers isRepository honestly', function (): void {
        expect((new GitRepository($this->dir))->isRepository())->toBeTrue()
            ->and((new GitRepository(sys_get_temp_dir()))->isRepository())->toBeFalse();
    });
});
