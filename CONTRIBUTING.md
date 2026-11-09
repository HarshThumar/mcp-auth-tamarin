# Contributing

The most useful help right now:

1. **Review the assumptions** in [docs/threat-model.md](docs/threat-model.md) and [docs/flow.md](docs/flow.md). Is a step wrong, missing or over-simplified compared with the MCP spec or the RFCs?
2. **Review the models.** Is a lemma stating the right property? Is a rule too permissive or too strict?
3. **Suggest properties** worth proving, especially for Client ID Metadata Documents and Enterprise-Managed Authorization.

Please open an issue using the "Spec gap / modelling question" template. Pull requests are welcome. Keep one question per model file, and add the expected lemma results to `scripts/prove.sh`.
