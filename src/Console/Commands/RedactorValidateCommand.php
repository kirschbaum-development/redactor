<?php

declare(strict_types=1);

namespace Kirschbaum\Redactor\Console\Commands;

use Illuminate\Console\Command;
use Kirschbaum\Redactor\Redactor;
use Symfony\Component\Console\Attribute\AsCommand;

#[AsCommand(
    name: 'redactor:validate',
    description: 'Resolve every configured redaction profile and report any that are broken'
)]
class RedactorValidateCommand extends Command
{
    protected $signature = 'redactor:validate';

    public function handle(Redactor $redactor): int
    {
        $profiles = $redactor->getAvailableProfiles();

        if ($profiles === []) {
            $this->components->error('No redaction profiles are configured.');

            return Command::FAILURE;
        }

        $errors = $redactor->validateProfiles();

        foreach ($profiles as $profile) {
            if (isset($errors[$profile])) {
                $this->components->twoColumnDetail(
                    "<fg=red>{$profile}</>",
                    "<fg=red>{$errors[$profile]}</>"
                );
            } else {
                $this->components->twoColumnDetail($profile, '<fg=green>OK</>');
            }
        }

        $this->newLine();

        if ($errors !== []) {
            $this->components->error(sprintf(
                '%d of %d profiles are invalid. Fix them before deploying; a broken profile throws at log time.',
                count($errors),
                count($profiles)
            ));

            return Command::FAILURE;
        }

        $this->components->info(sprintf('All %d redaction profiles resolve cleanly.', count($profiles)));

        return Command::SUCCESS;
    }
}
