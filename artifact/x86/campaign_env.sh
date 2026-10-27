REPO_DIR=${REPO_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)}
CAMPAIGN_OUT=${CAMPAIGN_OUT:-$HOME/campaign-out}
MEASURE_LOCK=${MEASURE_LOCK:-$HOME/measure.lock}
STAGES_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/stages" && pwd)
export COMPOSE_PROJECT=${COMPOSE_PROJECT:-hqclethe-campaign}
export EVAL_IMAGE=${EVAL_IMAGE:-hqclethe-eval}
mkdir -p "$CAMPAIGN_OUT"
cd "$REPO_DIR"
