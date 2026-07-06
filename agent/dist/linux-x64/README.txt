netflowAgent — Linux endpoint (ubuntu-pc01)

Binary is NOT included — build on the target host (Ubuntu 18.04+):

  git clone https://github.com/kolixxx/nflowCapAgent.git
  cd nflowCapAgent/agent
  ./scripts/build-linux.sh

Then:

  cd dist/linux-x64
  sudo ./install-linux.sh

Docs: docs/netflowAgent-install-linux.adoc
