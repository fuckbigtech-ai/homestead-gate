# homestead-gate

A 2-of-2 approval gate for AI agents: nothing an agent sends (email, posts, payments, wallet
transactions) leaves your machine until a local model has reviewed it **and** you have said yes.
Part of [fuckbigtech.ai](https://fuckbigtech.ai), alongside
[homestead-memory](https://github.com/fuckbigtech-ai/homestead-memory).

This repo starts with the evidence, not the product: **[GateBench](bench/)**, an open benchmark
that asks whether a small local model can catch a hijacked agent before it acts.

**v0.1 headline:** Qwen 3.5 9B (6.6GB, running on an 18GB laptop) blocked 30 of 30 attacks and
0 of 30 legitimate actions across three repeats. Full numbers in
[bench/RESULTS.md](bench/RESULTS.md), and read the limits in [bench/README.md](bench/README.md)
before quoting them.

Found an attack that gets through? Open a pull request with a new case. That's the point.

MIT licensed.
