#!/bin/bash

DATE=$(date "+%a, %d %b %Y")

rm -fr mdir[1234]
mkdir -p mdir{1,2,3,4}/{cur,new,tmp}

for i in {11..20}; do
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
