FROM python:slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 \
        iptables \
        libseccomp2 \
        iputils-ping \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
        pytest

COPY . /opt/dojjail
WORKDIR /opt/dojjail

RUN pip install -e .

CMD ["pytest", "tests"]