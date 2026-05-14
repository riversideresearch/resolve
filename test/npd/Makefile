INTERP_PATH="/lib/shiva""
SHIVA-LD_PATH="shiva-ld"

test: test.c
	gcc test.c -o test

patch: test.patch.c
	gcc -mcmodel=large -fno-pic -I ../ -fno-stack-protector -c test.patch.c
	$(SHIVA-LD_PATH) -e test -p test.patch.o -i /lib/shiva -s /home/rzmuda/repos/gh-resolve/test/npd -o test.patched