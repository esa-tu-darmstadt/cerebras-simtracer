# Cerebras Simtracer

Converts Cerebras simulator CTF traces into [speedscope](https://www.speedscope.app/) profiles for flamegraph visualization.

Parses barectf-generated CTF streams and ELF symbol tables to reconstruct per-tile function call stacks and task timelines. Supports WSE-2 and WSE-3.

## Install

```
pip install .
```

## Usage

```
simtracer <out_dir> -o trace.speedscope.json [--tiles 16,17,18]
```

- `out_dir` — simulator `out/` directory (expects `simfab_traces/stream0`, `bin/*.elf`, and `simfab_traces/global_simdata.json`)
- `--tiles` — comma-separated tile indices to include (default: all)

Open the output in https://www.speedscope.app/.
