FROM archlinux:latest AS temp

ARG NVME0=/tmp
ARG CI_JOB_ID=test
USER root
RUN rm /etc/pacman.d/mirrorlist
RUN echo 'Server = https://mirror.osbeck.com/archlinux/$repo/os/$arch' >> /etc/pacman.d/mirrorlist
RUN echo 'Server = http://mirror.sunred.org/archlinux/$repo/os/$arch' >> /etc/pacman.d/mirrorlist
RUN echo 'Server = http://md.mirrors.hacktegic.com/archlinux/$repo/os/$arch' >> /etc/pacman.d/mirrorlist
RUN yes | pacman -Syyu archlinux-keyring openssl openssl-1.1 --noconfirm
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
