FROM archlinux:latest AS temp

ARG NVME0=/tmp
ARG CI_JOB_ID=test
USER root
RUN yes | pacman -Sy archlinux-keyring openssl openssl-1.1 --noconfirm
RUN yes | pacman -S reflector --noconfirm
RUN reflector --sort rate --country Greece,Italy,Uk,Fr -l 8 -f 8 > /etc/pacman.d/mirrorlist
RUN pacman-key --init
RUN pacman-key --populate archlinux
RUN yes | pacman -Su --noconfirm
RUN yes | pacman -S gcc cmake make git numactl boost --noconfirm
RUN yes | pacman -Scc
RUN rm -Rf /root/.* /makepkg/.* /var/lib/pacman/* /usr/share/cmake/Help/* /usr/share/graphviz/doc/* || true

COPY ./ /parallax
WORKDIR /parallax/
RUN cmake --workflow --preset debug
RUN cmake --workflow --preset release

FROM scratch
COPY --from=temp / /
