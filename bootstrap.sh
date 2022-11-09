#!/bin/bash

[ -d optee ] || mkdir optee
(cd optee && repo init -u git@github.com:L0czek/optee_manifest.git -m qemu_v8.xml && repo sync -j $(nproc))
