ARG VERSION

FROM quay.io/getpantheon/fedora:${VERSION}

COPY pkg/fusedav /opt/fusedav
RUN dnf install -y /opt/fusedav/*.rpm make perf valgrind gdb \
  && rm -r /opt/fusedav \
  && dnf clean all
