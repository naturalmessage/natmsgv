#!/bin/bash

DATESTAMP=$(date +"%Y-%m-%d")
clear

echo "This is an example shell script that could be run on a Raspberry Pi"
echo "computer that is permanently offline (keeping it permanently offline"
echo "is a way to minimize the chance that somebody will hack a computer"
echo "and gain access to the offline master private key.  Tested on"
echo "Debian 7 for Raspberry Pi (Raspian)."
echo ""
echo "This procedure would be run once per month to create a short-term"
echo "online public signing key that is signed by the (permanently)"
echo "offline private key.  The offline private key corresponds to the"
echo "public key of that offline private key.... the offline public key"
echo "has the SHA384 equal to the fingerprint of the directory serer." 
echo ""

echo "Your computer thinks that the date is: ${DATESTAMP} (YYYY-MM-DD)"
echo "IF THIS IS NOT CORRECT, QUIT NOW AND FIX THE DATE"
echo "The date command is in this format:"
echo "  date MMDDhhmmYYYY"
echo ""
read -p "...." junk

key_dir="keys/${DATESTAMP}"


if [ ! -d "${key_dir}" ]; then
	echo "dir does not exist: ${key_dir}"
	mkdir -p "${key_dir}"
fi

########################################################################
# Tokyo server
#
key_prefix="${key_dir}/TokyoDir01"


./nm_create_online_key 'Natural Message Tokyo DirSvr01' 'none' \
  PUB002016013113CC95900BF7D64498E8A23D6D00E3862CF3B29E2B597DB492BC65CCADF11AF529AF8914B7B2B4290E6F86D54DC1E6C438D11B759D178705F7F1B64F724930E4 \
  106.187.53.102 'NA' 'NA' '' "${key_prefix}"

rc=$?
echo "rc was ${rc}"

./nm_sign --in "${key_prefix}OnlinePUBSignKey.key" --signature "${key_prefix}OnlinePUBSignKey.sig" --key keys/20150131/offline/TokyoDirSvr2015aOfflinePRVSignKey.key

rc=$?

echo "Return code from the verify step was ${rc}"
echo "The files are in ${key_dir}"
########################################################################
########################################################################
# Switzerland shard server
#
key_prefix="${key_dir}/SwitzerlandShard01"


./nm_create_online_key 'Natural Message Swizterland Shard01' 'none' \
  PUB002016013113CC95900BF7D64498E8A23D6D00E3862CF3B29E2B597DB492BC65CCADF11AF529AF8914B7B2B4290E6F86D54DC1E6C438D11B759D178705F7F1B64F724930E4 \
  178.209.40.102 'NA' 'NA' '' "${key_prefix}"

rc=$?
echo "rc was ${rc}"

./nm_sign --in "${key_prefix}OnlinePUBSignKey.key" --signature "${key_prefix}OnlinePUBSignKey.sig" --key keys/20150131/offline/SwitzerlandShardSvr012015aOfflinePRVSignKey.key

rc=$?

echo "Return code from the verify step for Switzerland Shard01 was ${rc}"
echo "The files are in ${key_dir}"

########################################################################
# My Raspberry Pi is set to use a British keyboard,
# but I use a US English keyboard.  There is probably a better 
# way to fix this, but I type a few keys using this translation
# table:
#
#   I Enter            I see
# ----------------------------
# Right-alt -          \
# right-alt-' e        ê
# right-alt-.          ·
# right-alt-~          |
# pipe                 ~
# backslash            #
# "                    @
# @                    "
# right-alt-:          ^
