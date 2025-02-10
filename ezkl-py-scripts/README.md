# Python scripts for using Lilith cluster to execute callback jobs that manage sentiment LTV updates

## Quickstart

- Dependency management is handled by pdm, install pdm
```shell
curl -sSL https://pdm-project.org/install-pdm.py | python3 -
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

### .env
A `.env` at the root of the project needs the following to run the scripts:
```bash
ARCHON_API_KEY='<api-key>.json'
PRIVKEY='<private-key>'
```

## Scripts

- `enable-hl-big-blocks` : toggles big blocks for a given account (used to for large deployment transaction that don't fit in the default small blocks for Hyper EVMs dual block architecture)

- `LTV-update` : Calls into lilith to generate proof and subsequent callback job to update the LTV for a sentiment given debt pool and asset pair.
