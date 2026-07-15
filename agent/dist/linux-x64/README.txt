netflowAgent v0.3.0 — Linux endpoint (ubuntu-pc01)

Features: NetFlow v9 (template 258) or IPFIX, TCP flags in flows.

Build on the target host (Ubuntu 18.04+):

  git clone https://github.com/kolixxx/nflowCapAgent.git
  cd nflowCapAgent/agent
  ./scripts/build-linux.sh

Then:

  cd dist/linux-x64
  sudo ./install-linux.sh

Docs: docs/netflowAgent-install-linux.adoc
