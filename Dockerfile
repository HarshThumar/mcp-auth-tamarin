# Reproducible artifact: Tamarin 1.12.0 + Maude 3.5.1 (same release binaries as CI)
FROM ubuntu:22.04

ARG TAMARIN_VERSION=1.12.0
ARG MAUDE_VERSION=3.5.1
ARG MAUDE_SHA256=72ed1ca87e3b3d0dfc6ee1436baf154bf04c45ff97d521bec040c5e8dfc8f92c
ARG TAMARIN_SHA256=201be06f469e47cff554df6ca93db8366fc2c69d70c61fcbd1370a1074b469c6

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip bash coreutils findutils grep sed gawk python3 libgmp10 libtinfo6 libncurses6 \
 && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    mkdir -p /opt/tools/bin /opt/tools/maude; cd /opt/tools; \
    curl -fsSL -o maude.zip "https://github.com/maude-lang/Maude/releases/download/Maude${MAUDE_VERSION}/Maude-${MAUDE_VERSION}-linux-x86_64.zip"; \
    echo "${MAUDE_SHA256}  maude.zip" | sha256sum -c -; \
    unzip -q maude.zip -d maude-unzipped; \
    find maude-unzipped -type f \( -name 'maude' -o -name '*.maude' \) -exec cp {} maude/ \; ; \
    chmod +x maude/maude; ln -sf /opt/tools/maude/maude bin/maude; \
    curl -fsSL -o tamarin.tar.gz "https://github.com/tamarin-prover/tamarin-prover/releases/download/${TAMARIN_VERSION}/tamarin-prover-${TAMARIN_VERSION}-linux64-ubuntu.tar.gz"; \
    echo "${TAMARIN_SHA256}  tamarin.tar.gz" | sha256sum -c -; \
    tar xzf tamarin.tar.gz -C bin; chmod +x bin/tamarin-prover; \
    rm -rf maude.zip maude-unzipped tamarin.tar.gz; \
    PATH=/opt/tools/bin:$PATH MAUDE_LIB=/opt/tools/maude sh -c 'maude --version; tamarin-prover --version | head -3'

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PATH=/opt/tools/bin:$PATH \
    MAUDE_LIB=/opt/tools/maude

WORKDIR /work
COPY models/ models/
COPY scripts/ scripts/
COPY docs/ docs/

# Linters first, then every variant. ONLY / TIMEOUT / JOBS are read from the environment.
CMD ["bash", "-c", "set -e; bash scripts/check-model-header.sh; bash scripts/check-mapping.sh; bash scripts/prove.sh"]
