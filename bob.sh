#!/bin/bash

[ -d mdir1 ] || exit 1
[ -d mdir2 ] || exit 1
[ -d mdir3 ] || exit 1
[ -d mdir4 ] || exit 1

DATE=$(date "+%a, %d %b %Y")

for i in {21..30}; do
	for j in {1..4}; do
		cat > mdir$j/new/test$i <<EOF
Date: $DATE 09:$i:00 +0000
From: foo@example.com
To: bar@example.com
Subject: test$i

test$i
EOF
		for k in {0..99}; do
			echo LINE $k
		done >> mdir$j/new/test$i
	done
done
