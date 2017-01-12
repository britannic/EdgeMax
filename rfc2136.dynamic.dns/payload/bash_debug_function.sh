function s_dbg {

     export COLOR="\e[1;31m" CLEAR="\e[0m"
     help="$(  echo "Turn a detailed debugging prompt on or off.  Usage:"
               echo -e "${COLOR}\t$FUNCNAME on [verb] | $FUNCNAME off${CLEAR}"
               echo "Prints line# and last exit code value, as well as function name"
               echo "and relative subshell level if it goes above that of the script."
               echo "'verb' is an optional argument that turns on the shell's verbose behavior."
               echo "This function is designed to be loaded from bashrc and exported for use"
               echo "in scripts.  It doesn't do so well when called directly in an interactive shell."
               )"

     export bss=$((BASH_SUBSHELL+1)) #increment by one to counteract embedded test subshell below

     if [[ ! $* ]]; then
          echo "$help" && return
     elif [[ "$*" =~ verb ]]; then
          verb="-v"
     fi

     if [[ "$*" =~ on ]]; then
          export PS4="${COLOR}"'${LINENO}|ex:$?|${FUNCNAME[0]+Fn:${FUNCNAME[0]}|}$((($BASH_SUBSHELL > bss)) && echo "sbshl:$((BASH_SUBSHELL-1))|") '"$CLEAR"
          set -x $verb
          echo "${FUNCNAME} $@"
          echo "shell level:$SHLVL,subshell level:$BASH_SUBSHELL"
     else
          unset PS4
          set +xv
     fi
} 2>/dev/null   #error redirect keeps function from outputting itself

export -f s_dbg #export above function for use in scripts