# Sentiment Finance <> EZKL Financial Simulation

## Overview
Financial simulations for Sentiment Finance and EZKL models

## Quickstart

- Dependency management is handled by pdm, install pdm
```shell
curl -sSL https://pdm-project.org/install-pdm.py | python3 -
```

- To pull git LFS files like the `*.key` files run
```shell
git lfs pull
```

- Install dependencies. Note that this will create a virtual environment for you
```shell
pdm install
```

- Activate python environment
```shell
# use pdm venve activate to get the command to activate virtual env
source .venv/bin/activate
```

- Open up jupyter, and navigate to the url provided if it doesn't already open up the browser session
```shell
jupyter-lab

# then go to the link provided via the CLI
```

## Notebooks

- `1_GARCH_modeling` : deals with garch modeling experiments

- `2_EZKL_conversion` : optimize the GARCH model and converts it into a ZK circuit with EZKL

- `3_Monte_Carlo_Sim` : monte carlo simulation for the Sentiment Vault to check for soundness of the dynamic LTV
