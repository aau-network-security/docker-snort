FROM ubuntu:14.04
LABEL maintainer="egk@es.aau.dk"

# Installs Snort, a Network Intrusion Detection System
#
# Purpose is offline parsing of pcap files. Access to nic has not been
# considered (Hint: setup-snort.sh).
#
# Building:
#     docker build .
#
# Tagging:
#     docker tag <container id> kidmose/snort:<YYYYMMDD>.<DD - two digit daily version number>
#
# Usage
#     docker run -it -v /path/to/pcaps:/data/in:ro -v /path/for/output/:/data/out
#
# Tested with Docker version 18.03.1-ce, build 9ee9f40.
#
# Based on
# https://s3.amazonaws.com/snort-org-site/production/document_files/files/000/000/065/original/Snort_2.9.7.x_on_Ubuntu_12_and_14.pdf

ENV IF=eth1
ENV USR=snort

VOLUME /data/in # PCAPs in
VOLUME /data/out # Log files out

# Dependencies from official repositories
RUN \
    echo 'debconf debconf/frontend select Noninteractive' | debconf-set-selections && \
    apt-get update && \
    apt-get upgrade -y && \
    apt-get install -yq build-essential wget && \
    apt-get install -yq libpcap-dev libpcre3-dev libdumbnet-dev zlib1g-dev liblzma-dev `# snort` && \
    apt-get install -yq bison flex `# DAQ` && \
    apt-get install -yq ethtool && \
    rm -rf /var/lib/apt/lists/*

# dependency from source (DAQ)
RUN \
    mkdir -p ~/snort_src && \
    cd ~/snort_src && \
    wget -q http://kom.aau.dk/~egk/snort/daq-2.0.6.tar.gz && \
    echo "d41da5f7793e66044e6927dd868c0525e7ee4ec1a3515bf74ef9a30cd9273af0  daq-2.0.6.tar.gz" | sha256sum -c - && \
    tar -xvzf daq-2.0.6.tar.gz && \
    cd daq-2.0.6 && \
    ./configure && \
    make && \
    make install

# install Snort
COPY snort.conf.patch /root/snort_src/
RUN \
    mkdir -p ~/snort_src && \
    cd ~/snort_src && \
    wget -q http://kom.aau.dk/~egk/snort/snort-2.9.7.6.tar.gz && \
    echo "842e8575e26d919a9e74b9ad0c10d1098f7b5ff2189a8422eb51a9a5b6ebbf63  snort-2.9.7.6.tar.gz" | sha256sum -c - && \
    tar -xvzf snort-2.9.7.6.tar.gz && \
    cd snort-2.9.7.6 && \
    ./configure && \
    make && \
    make install && \
    ldconfig

RUN \
    # Configure to run as $USR
    groupadd $USR && \
    useradd $USR -r -s /usr/sbin/nologin -c SNORT_IDS -g $USR && \
    # Default configuration
    mkdir -p /etc/snort && \
    mkdir -p /etc/snort/rules && \
    mkdir -p /etc/snort/preproc_rules && \
    touch /etc/snort/rules/white_list.rules /etc/snort/rules/black_list.rules /etc/snort/rules/local.rules && \
    mkdir -p /usr/local/lib/snort_dynamicrules && \
    cp ~/snort_src/snort-2.9.7.6/etc/*.conf* /etc/snort && \
    cp ~/snort_src/snort-2.9.7.6/etc/*.map /etc/snort && \
    # Download fixed rule set
    mkdir -p ~/snort_src && \
    cd ~/snort_src && \
    wget -q http://kom.aau.dk/~egk/snort/snortrules-snapshot-2976.tar.gz && \
    echo "319caaf9cac4d2dfe486cf565c59cc70b25c29a76dcaed36db5459e56994ac15  snortrules-snapshot-2976.tar.gz" | sha256sum -c - && \
    tar -xvzf snortrules-snapshot-2976.tar.gz -C /etc/snort && \
    cd /etc/snort/etc && \
    cp ./*.conf* ../ && \
    cp ./*.map ../ && \
    cd .. && \
    rm -Rf /etc/snort/etc && \
    # Fix access 
    chmod -R 5775 /etc/snort && \
    chmod -R 5775 /usr/local/lib/snort_dynamicrules && \
    chown $USR:$USR /etc/snort && \
    chown $USR:$USR /usr/local/lib/snort_dynamicrules && \
    patch /etc/snort/snort.conf  ~/snort_src/snort.conf.patch && \
    # logs and alerts
    mkdir -p /var/log/snort && \
    chmod -R 5775 /var/log/snort && \
    chown $USR:$USR /var/log/snort && \
    # enable preprocessor rules
    sed -i 's/^# include \$PREPROC\_RULE\_PATH/include \$PREPROC\_RULE\_PATH/' /etc/snort/snort.conf && \
    # Strip some legacy includes
    perl -0777 -i -pe 's/# legacy dynamic library rule files\n(.*\n)*\n//' /etc/snort/snort.conf && \
    # enable dynamic library rules
    sed -i 's/^# include \$SO\_RULE\_PATH/include \$SO\_RULE\_PATH/' /etc/snort/snort.conf && \
    rm -rf ~/snort_src

# Test config
RUN \
    snort -T -c /etc/snort/snort.conf

COPY run-snort.sh /usr/bin

CMD ["run-snort.sh"]
