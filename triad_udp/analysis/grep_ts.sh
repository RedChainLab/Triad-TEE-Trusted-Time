
LOG_PATH=out/log
OUT_PATH=out/ts
mkdir -p $LOG_PATH $OUT_PATH
egrep "\[Node [0-9]*\]> (Node Time|Ref\. Time)" $LOG_PATH/$1.log > $OUT_PATH/$1-ts-node.log
egrep "\[utrst-Handler [0-9]*\]> TS Time" $LOG_PATH/$1.log > $OUT_PATH/$1-aex.log
egrep "\[utrst-ENode [0-9]*\]> TS Time" $LOG_PATH/$1.log > $OUT_PATH/$1-ut-node.log
egrep "\[utrst-TA [0-9]*\]> TS Time" $LOG_PATH/$1.log > $OUT_PATH/$1-ut-ta.log