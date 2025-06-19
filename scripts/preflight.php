<?php

$cmd = 'bash '.__DIR__.'/preflight.sh';

passthru($cmd, $exitCode);

exit($exitCode);
