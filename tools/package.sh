#!/usr/bin/env bash
# Simple helper script to create packages

name=snifstat
version=1.1.2
contact='Stefan Midjich <swehack at gmail dot com>'
descr='Capture packets from network and calculate traffic from packet size.'
files='/usr/bin/snifstat /usr/share/man/man1/snifstat.1'

test -z $1 && exit 1

# RPM
if [ $1 = 'RPM' ]; then
    fpm -s dir -t rpm -n $name -v $version -d libpcap -m "$contact" --description "$descr" $files
fi

# Deb
if [ $1 = 'Debian' ]; then
    fpm -s dir -t deb -n $name -v $version -d libpcap0.8 -m "$contact" --description "$descr" $files
fi

# FreeBSD ports
if [ $1 = 'FreeBSD' ]; then
    fbsd_plist_file=FreeBSD/pkg-plist
    fbsd_makefile=FreeBSD/Makefile
    fbsd_header='$FreeBSD$'
    fbsd_sites="https://github.com/stemid/snifstat/archive/"
    fbsd_categories=net
    filename="${name}-${version}.tar.gz"
    fbsd_remote_file="${fbsd_sites}/${filename}"
    fbsd_distinfo=FreeBSD/distinfo
    fbsd_pkg_descr=FreeBSD/pkg-descr
    fbsd_files='/usr/local/bin/snifstat /usr/local/share/man/man1/snifstat.1'
    fbsd_symlink="${name}-${version}"
    fbsd_wrksrc='${WRKDIR}/${PORTNAME}-${PORTNAME}-${PORTVERSION}'

    export name version contact descr fbsd_sites fbsd_categories fbsd_header fbsd_wrksrc

    :> $fbsd_plist_file
    for file in $fbsd_files; do
        echo ${file/\/} >> $fbsd_plist_file
    done

    :> $fbsd_makefile
    envsubst < "${fbsd_makefile}.in" > $fbsd_makefile

    # Create simple pkg-descr
    echo $descr > $fbsd_pkg_descr

    # Generate distinfo file
    # Kind of wasteful to fetch the file twice but whatever
    read -ra sum < <(curl -sLo - "$fbsd_remote_file" | sha256sum -)
    read -ra size < <(curl -sLo - "$fbsd_remote_file" | wc -c)
    fbsd_checksum="${sum[0]}"
    fbsd_size="${size[0]}"

    echo "SHA256 (${filename}) = $fbsd_checksum" > $fbsd_distinfo
    echo "SIZE (${filename}) = $fbsd_size" >> $fbsd_distinfo

    # Now make tarball
    ln -s FreeBSD "$fbsd_symlink"
    tar -cvzf "${name}-${version}.tar.gz" --exclude='Makefile.in' "${fbsd_symlink}"/*

    # Cleanup files
    rm -f $fbsd_plist_file $fbsd_makefile $fbsd_pkg_descr $fbsd_distinfo $fbsd_symlink
fi
