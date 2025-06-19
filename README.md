# Proxmox Firewall Monitor

## What is it? Why?

It's a simple application which hooks into one or more Proxmox nodes, reads their firewall log, and automatically sends it to a `known_responses` file and to a specified Discord-format webhook. I made it because I was tired of having to monitor database nodes from 3 different PVE instances.

## Installation

Just install the packages and you're good to go:
```sh
uv venv
source .venv/bin/activate
uv pip install httpx pathlib
```

Next, you need to copy the `data/nodes.json.templ` file to `data/nodes.json` and edit it with your editor of choice. The template should be self-explanitory given you have a proper PVE API key for your instance.

## Issues or contributions

If it improves the project chances are I'll accept it. I don't mind issues but am probably not willing to work through edge cases with your specific setup.

<small>
pyxfluff 2025
</small>
