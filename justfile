lint:
    #!/usr/bin/env bash
    set -euo pipefail
    for module in modules/*/; do
        echo "Validating ${module}..."
        terraform -chdir="${module}" init -backend=false
        terraform -chdir="${module}" validate
    done
