#!/bin/bash
# Installs Snort, a Network Intrusion Detection System
# Reference: on https://s3.amazonaws.com/snort-org-site/production/document_files/files/000/000/065/original/Snort_2.9.7.x_on_Ubuntu_12_and_14.pdf

IF=eth1
USR=snort
OINKCODE=50b8de2546a19ed031795a059df4a0bbdbb340af

apt-get update && apt-get upgrade -y || exit 1

# Dependencies from official repositories
apt-get install -y build-essential
apt-get install -y libpcap-dev libpcre3-dev libdumbnet-dev zlib1g-dev # snort
apt-get install -y bison flex # DAQ 

# dependency from source (DAQ)
mkdir ~/snort_src
cd ~/snort_src
wget https://www.snort.org/downloads/snort/daq-2.0.6.tar.gz
tar -xvzf daq-2.0.6.tar.gz
cd daq-2.0.6
./configure
make
make install || exit 2

# install Snort
cd ~/snort_src
# wget https://www.snort.org/downloads/snort/snort-2.9.7.6.tar.gz # Cisco took it down :(
tar -xvzf snort-2.9.7.6.tar.gz
cd snort-2.9.7.6
./configure
make
make install || exit 3
ldconfig

# Configure to run as $USR
groupadd $USR
useradd $USR -r -s /usr/sbin/nologin -c SNORT_IDS -g $USR

# Default configuration
mkdir /etc/snort
mkdir /etc/snort/rules
mkdir /etc/snort/preproc_rules
touch /etc/snort/rules/white_list.rules /etc/snort/rules/black_list.rules /etc/snort/rules/local.rules
mkdir /usr/local/lib/snort_dynamicrules

cp ~/snort_src/snort-2.9.7.6/etc/*.conf* /etc/snort
cp ~/snort_src/snort-2.9.7.6/etc/*.map /etc/snort

# Download fixed rule set
cd ~/snort_src
wget https://snort.org/rules/snortrules-snapshot-2976.tar.gz?oinkcode=$OINKCODE -O snortrules-snapshot-2976.tar.gz
tar -xvzf snortrules-snapshot-2976.tar.gz -C /etc/snort
cd /etc/snort/etc
cp ./*.conf* ../
cp ./*.map ../
cd ..
rm -Rf /etc/snort/etc

# Fix access 
chmod -R 5775 /etc/snort
chmod -R 5775 /usr/local/lib/snort_dynamicrules
chown $USR:$USR /etc/snort
chown $USR:$USR /usr/local/lib/snort_dynamicrules

echo "104,106c104,106
< var RULE_PATH ../rules
< var SO_RULE_PATH ../so_rules
< var PREPROC_RULE_PATH ../preproc_rules
---
> var RULE_PATH /etc/snort/rules
> var SO_RULE_PATH /etc/snort/so_rules
> var PREPROC_RULE_PATH /etc/snort/preproc_rules
113,114c113,114
< var WHITE_LIST_PATH ../rules
< var BLACK_LIST_PATH ../rules
---
> var WHITE_LIST_PATH /etc/snort/rules
> var BLACK_LIST_PATH /etc/snort/rules" | patch /etc/snort/snort.conf 

# logs and alerts
mkdir /var/log/snort
chmod -R 5775 /var/log/snort
chown $USR:$USR /var/log/snort

# enable preprocessor rules
sed -i 's/^# include \$PREPROC\_RULE\_PATH/include \$PREPROC\_RULE\_PATH/' /etc/snort/snort.conf
# Strip some legacy includes
perl -0777 -i -pe 's/# legacy dynamic library rule files\n(.*\n)*\n//' /etc/snort/snort.conf
# enable dynamic library rules
sed -i 's/^# include \$SO\_RULE\_PATH/include \$SO\_RULE\_PATH/' /etc/snort/snort.conf

snort -T -c /etc/snort/snort.conf || exit 4

# Append config for interface in promiscous mode
if grep -q $IF /etc/network/interfaces ; then echo "Error: $IF already configured"; exit 5; fi
echo "
# For sniffing traffic
auto $IF
iface $IF inet manual
        up ifconfig $IF promisc up
        down ifconfig $IF promisc down" >> /etc/network/interfaces

ifup $IF || exit 5

# Large Receive Offload and Generic Receive Offload (NIC features)
# doesn't play nice with snort. Disable.
apt-get install -y ethtool
ethtool -K $IF gro off
ethtool -K $IF lro off



exit 0
# PulledPork - NOTE THE EXIT ABOVE :)
apt-get install -y libcrypt-ssleay-perl liblwp-useragent-determined-perl
cd ~/snort_src
wget https://pulledpork.googlecode.com/files/pulledpork-0.7.0.tar.gz
tar xvfvz pulledpork-0.7.0.tar.gz
cd pulledpork-0.7.0/
cp pulledpork.pl /usr/local/bin
chmod +x /usr/local/bin/pulledpork.pl
cp etc/*.conf /etc/snort
mkdir /etc/snort/rules/iplists
touch /etc/snort/rules/iplists/default.blacklist
sed -i "s/<oinkcode>/$OINKCODE/" /etc/snort/pulledpork.conf
sed -i 's!/usr/local/etc/snort!/etc/snort!' /etc/snort/pulledpork.conf
echo "131c131
< distro=FreeBSD-8.1
---
> distro=Ubuntu-14-4
194,197c194,197
< # enablesid=/etc/snort/enablesid.conf
< # dropsid=/etc/snort/dropsid.conf
< # disablesid=/etc/snort/disablesid.conf
< # modifysid=/etc/snort/modifysid.conf
---
> enablesid=/etc/snort/enablesid.conf
> dropsid=/etc/snort/dropsid.conf
> disablesid=/etc/snort/disablesid.conf
> modifysid=/etc/snort/modifysid.conf" | patch /etc/snort/pulledpork.conf

echo 'include $RULE_PATH/snort.rules' >> /etc/snort/snort.conf


