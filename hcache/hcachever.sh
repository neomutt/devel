#!/bin/sh

BASEVERSION=2

cleanstruct () {
  echo "$1" | sed -e 's/.* //'
}

cleanbody () {
  echo "$1" | sed -e 's/{ *//'
}

getstruct () {
  STRUCT=""
  BODY=''
  inbody=0
  case "$1" in
    *'{') inbody=1 ;;
    *';') return ;;
  esac

  STRUCT=`cleanstruct "$1"`

  while read line
  do
    if test $inbody -eq 0
    then
      case "$line" in
        '{'*) inbody=1 ;;
        *';') return ;;
      esac
    fi

    case "$line" in
      '};'*)
        break
      ;;
      '#'*) continue ;;
      *)
        if test $inbody -ne 0
        then
          BODY="$BODY $line"
        fi
      ;;
    esac
  done

  case $STRUCT in
    Address|ListNode|Buffer|Parameter|Body|Envelope|Header)
      BODY=`cleanbody "$BODY"`
      echo "$STRUCT: $BODY"
    ;;
  esac
  return
}

DEST="$1"
TMPD="$DEST.tmp"

TEXT="$BASEVERSION"

echo "/* base version: $BASEVERSION" > $TMPD
while read line
do
  case "$line" in
    'struct'*)
       STRUCT=`getstruct "$line"`
       if test -n "$STRUCT"
       then
	 NAME=`echo $STRUCT | cut -d: -f1`
	 BODY=`echo $STRUCT | cut -d' ' -f2-`
         echo " * $NAME:" $BODY >> $TMPD
         TEXT="$TEXT $NAME {$BODY}"
       fi
    ;;
  esac
done
echo " */" >> $TMPD

MD5CMD=`which md5sum || which md5` # Try both md5sum (Linux) and md5 (BSD)
if [ $? != 0 ]; then
    echo "Could not find md5 program"
    exit 1
fi
MD5TEXT=`echo "$TEXT" | $MD5CMD | cut -c-8`
echo "#define HCACHEVER 0x$MD5TEXT" >> $TMPD

# TODO: validate we have all structs

mv $TMPD $DEST
