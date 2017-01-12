#!/usr/bin/env bash
# Script to remove LDC Router RFC2136 support
VERSION="v3.1"
ME="${0##*/} ${VERSION}: "

# Uncomment these lines to enable debugging
# source /config/user-data/KH_Source/bash_debug_function.sh
# s_dbg on verb
# DEBUG=Yes

# Make sure script runs as root
if [[ ${EUID} == 0 ]]
then
  echo "This script must be run as the admin user!"
  #exit 1
fi

# Set up the Vyatta environment
source /opt/vyatta/etc/functions/script-template
OPRUN=/opt/vyatta/bin/vyatta-op-cmd-wrapper
CFGRUN=/opt/vyatta/sbin/vyatta-cfg-cmd-wrapper
API=/bin/cli-shell-api
shopt -s expand_aliases

alias begin='${CFGRUN} begin'
alias cleanup='${CFGRUN} cleanup'
alias comment='${CFGRUN} comment'
alias commit='${CFGRUN} commit'
alias copy='${CFGRUN} copy'
alias delete='${CFGRUN} delete'
alias discard='${CFGRUN} discard'
alias end='${CFGRUN} end'
alias load='${CFGRUN} load'
alias rename='${CFGRUN} rename'
alias save='${CFGRUN} save'
alias set='${CFGRUN} set'
alias show='${API} showConfig'
alias version='${OPRUN} show version'

alias bold='tput bold'
alias normal='tput sgr0'
alias reverse='tput smso'
alias underline='tput smul'

alias black='tput setaf 0'
alias blink='tput blink'
alias blue='tput setaf 4'
alias cyan='tput setaf 6'
alias green='tput setaf 2'
alias lime='tput setaf 190'
alias magenta='tput setaf 5'
alias powder='tput setaf 153'
alias purple='tput setaf 171'
alias red='tput setaf 1'
alias tan='tput setaf 3'
alias white='tput setaf 7'
alias yellow='tput setaf 3'
alias ansi='sed -r "s/\[(.[^]]*)\]/\[$(cyan)\1$(normal)\]/g"'

# Setup the echo_logger function
echo_logger ()
{
local MSG=
SHOWVER=$(version | sed 's/$/;/g')
BUILD=$(echo ${SHOWVER} | awk 'BEGIN {RS=";"} /Build ID:/ {print $3}')

  shopt -s checkwinsize
  COLUMNS=$(tput cols)

  case "${1}" in
    E)
      shift
      MSG="[$(red)$(bold)ERROR$(normal)]: ${@}"
      LOG="[ERROR]: ${@}";;
    F)
      shift
      MSG="[$(red)$(bold)FAILED$(normal)]: ${@}"
      LOG="[FAILED]: ${@}";;
    FE)
      shift
      MSG="[$(red)$(bold)FATAL ERROR$(normal)]: ${@}"
      LOG="[FAILED]: ${@}";;
    I)
      shift
      MSG="[$(blue)$(bold)INFO$(normal)]: ${@}"
      LOG="[INFO]: ${@}";;
    S)
      shift
      MSG="[$(green)$(bold)SUCCESS$(normal)]: ${@}"
      LOG="[SUCCESS]: ${@}";;
    T)
      shift
      MSG="[$(tan)$(bold)TRYING$(normal)]: ${@}"
      LOG="[TRYING]: ${@}";;
    W)
      shift
      MSG="[$(yellow)$(bold)WARNING$(normal)]: ${@}"
      LOG="[WARNING]: ${@}";;
    *)
      echo "ERROR: usage: echo_logger MSG TYPE(E, F, FE, I, S, T, W) MSG."
      exit 1;;
  esac

  echo "$(echo ${MSG} | ansi)" | fold -s -w ${COLUMNS}
  logger -t ${ME} "${LOG}"
}

# Function to output command status of success or failure to screen and log
try ()
{
  [[ ${DEBUG} ]] && echo_logger T "[${@}]..."
  if eval ${@}
  then
    echo_logger                 S "[${@}]."
    return 0
  else
    echo_logger                 E "[${@}] unsuccessful!"
    return 1
  fi
}

# Usage: yesno prompt...
yesno(){
  default=

  if [[ "${1}" = "-y" ]]
  then
    default='y'
    shift
  elif [[ "${1}" = "-n" ]]
  then
    default='n'
    shift
  fi

  if [[ ${#} = 0 ]]
  then
    prompt="[Y/n]: "
  else
    prompt="${@}"
  fi

  while true
  do
    read -p "${prompt}" || exit 1
    if [[ -z "${REPLY}" && ! -z "${default}" ]]
    then
      REPLY=$default
    fi
    case "${REPLY}" in
      y*|Y*)  return 0;;
      n*|N*)  return 1;;
          *)  echo "Answer (y)es or (n)o please";;
    esac
  done
}

Delete_RFC2136(){
local FILES2REMOVE=(/config/user-data/KH_Source /config/auth/keys /config/scripts/post-config.d/KH_Install_Packages.sh /var/lib/my_packages/)

  echo_logger I "Opening EdgeOS configuration session..."
  try begin
  echo_logger I "Deleting router rfc2136 dynamic DNS support..."
  try delete service dns dynamic
  try delete port-forward
  try delete system package
  try set system host-name ubnt
  echo_logger I "Closing EdgeOS configuration session"
  try commit  # End the CLI session
  try save    # Save the configuration
  echo_logger I "Closing EdgeOS configuration session..."
  try end

  for i in ${FILES2REMOVE[@]}; do
    try rm -rf "${i}"
  done
}

main(){
  echo_logger I "This script will completely remove and erase all RFC 2136 DDNS support and reset the system hostname to 'ubnt'!"
  if yesno -y "Is that OK? [Y/n]: "
  then
    echo_logger I "Starting LDC EdgeOS Router RFC 2136 DDNS configuration removal..."
    cd ~  # Make sure we're not in KH_Source when we remove it!
    Delete_RFC2136
    echo_logger I "LDC EdgeOS Router RFC 2136 DDNS configuration removal completed."
  else
    echo_logger I "LDC EdgeOS Router RFC 2136 DDNS configuration removal canceled!"
  fi
}

# Now let's get to business!
main
