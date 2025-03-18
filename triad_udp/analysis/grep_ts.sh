
LOG_PATH=out/log
OUT_PATH=out/ts
egrep "\[Node [0-9]*\]> (Node Time|Ref\. Time)" $LOG_PATH/$1 > $OUT_PATH/$1
