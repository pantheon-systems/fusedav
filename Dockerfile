ARG VERSION

FROM quay.io/getpantheon/fedora:${VERSION}

COPY pkg/fusedav /opt/fusedav
RUN dnf install -y /opt/fusedav/*.rpm && rm -r /opt/fusedav
