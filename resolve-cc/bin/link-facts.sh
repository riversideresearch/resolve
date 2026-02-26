# link-facts.sh
#
# Copyright (c) 2025 Riverside Research.
# LGPL-3; See LICENSE.txt in the repo root for details.
#
# Link facts from multiple object files, storing them in <build-dir>
# See HELP for usage.

SCRIPT_DIR="${0%/*}"
EXTRACT_FACTS="${SCRIPT_DIR}/extract_facts.py"
FACT_FILES="facts.facts"

HELP="Usage: ./link-facts.sh <build-dir> <object-file1> [<object-file2> ... <object-fileN>]"

if [ $# -lt 2 ]; then
    echo "$HELP";
    exit -1;
fi

BUILD_DIR=$1
TARGETS="${@:2}"

for f in $TARGETS; do
    BASENAME=$(basename "$f");
    echo "Target $BASENAME, full path $f: link facts";
    if [ -f $f ]; then
    #for path in `find / -wholename "*/$f" -type f`; do
        echo "Target $BASENAME: artifact directory $BUILD_DIR/$BASENAME";
        rm -rf $BUILD_DIR/$BASENAME &&
        mkdir -p $BUILD_DIR/$BASENAME &&
        $EXTRACT_FACTS --in_bin $f --out_dir $BUILD_DIR/$BASENAME &&
        for fact_file in $FACT_FILES; do
            echo "Target $BASENAME: Source fact file $BUILD_DIR/$BASENAME/$fact_file";
            echo "Target $BASENAME: Destination fact file $BUILD_DIR/$fact_file";
            cat $BUILD_DIR/$BASENAME/$fact_file >> $BUILD_DIR/$fact_file
        done
    fi
done
